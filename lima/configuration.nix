{
  lib,
  pkgs,
  terrarium,
  ...
}:
{
  environment.systemPackages = [ terrarium pkgs.envoy-bin pkgs.nginx pkgs.socat pkgs.openssl pkgs.curl ];

  # Boot-time deny-all firewall. This table loads before terrarium
  # starts and blocks all non-loopback traffic. Terrarium replaces it
  # with policy-based rules on startup. If terrarium never starts,
  # crashes, or is stopped, the deny-all rules remain in the kernel.
  networking.nftables = {
    enable = true;
    tables.terrarium = {
      family = "inet";
      content = ''
        chain input {
          type filter hook input priority filter; policy drop;
          iifname "lo" accept
          ct state established,related accept
          # Allow SSH from Lima host for guest agent communication.
          tcp dport 22 accept
        }
        chain output {
          type filter hook output priority filter; policy drop;
          oifname "lo" accept
          ct state established,related accept
        }
      '';
    };
  };

  # Prevent nixos-rebuild switch from restarting lima-init or its
  # dependent lima-guestagent. This allows the provisioning script
  # (which runs inside lima-init) to call switch without killing itself.
  systemd.services.lima-init.restartIfChanged = lib.mkForce false;
  systemd.services.lima-guestagent.restartIfChanged = lib.mkForce false;

  # Envoy user (UID 1001) matching Terrarium's default.
  users.users.envoy = {
    isSystemUser = true;
    uid = 1001;
    group = "envoy";
  };
  users.groups.envoy = { };

  # Terrarium VM-wide network filter daemon.
  systemd.services.terrarium = {
    description = "Terrarium VM-wide network filter daemon";
    after = [ "network-online.target" "nftables.service" "dnsmasq.service" ];
    wants = [ "network-online.target" "dnsmasq.service" ];
    wantedBy = [ "multi-user.target" ];
    environment = {
      # Terrarium resolves default paths from XDG and HOME. Point
      # these at writable directories so the daemon does not attempt
      # writes under /home.
      HOME = "/var/lib/terrarium";
      XDG_DATA_HOME = "/var/lib/terrarium";
      XDG_STATE_HOME = "/var/lib/terrarium";
    };

    path = [ pkgs.envoy-bin ];

    serviceConfig = {
      Type = "notify";
      # Seed the mutable config from the NixOS-managed default if it
      # does not already exist. Tests overwrite this file at runtime.
      ExecStartPre = pkgs.writeShellScript "terrarium-seed-config" ''
        if [ ! -f /var/lib/terrarium/config.yaml ]; then
          cp /etc/terrarium/config.yaml /var/lib/terrarium/config.yaml
        fi
      '';
      ExecStart = "${terrarium}/bin/terrarium daemon --config=\${TERRARIUM_CONFIG}";
      EnvironmentFile = "/etc/environment";
      StateDirectory = "terrarium";
      WatchdogSec = "30s";
      Restart = "always";
      RestartSec = "5s";
      StartLimitBurst = 0;
    };
  };

  # Terrarium egress policy, applied on every boot.
  # Edit and run `task lima:rebuild` to apply changes.
  environment.etc."terrarium/config.yaml".text = builtins.toJSON {
    logging = true;
    egress = [
      {
        toFQDNs = [
          { matchName = "jacobcolvin.com"; }
          { matchPattern = "*.jacobcolvin.com"; }
          { matchName = "cache.nixos.org"; }
        ];
        toPorts = [
          {
            ports = [
              { port = "443"; protocol = "TCP"; }
              { port = "80"; protocol = "TCP"; }
            ];
          }
        ];
      }
    ];
  };

  # Harden SSH: disable root login and password auth. Lima's guest
  # agent connects as the default user, not root.
  services.openssh.settings = {
    PermitRootLogin = "no";
    PasswordAuthentication = false;
    KbdInteractiveAuthentication = false;
  };

  # Guard table: a separate nftables table the terrarium daemon never
  # touches (it only manages the "terrarium" table via netlink). This
  # provides deny-all egress when the daemon's table is absent --
  # during the brief startup window when the daemon deletes the
  # boot-time table before applying its own, or if someone manually
  # deletes the terrarium table.
  #
  # Priority 10 fires after the daemon's filter output chain
  # (priority 0). In nftables, accept in one chain does not skip
  # subsequent chains; only drop is terminal. So this guard must
  # explicitly accept the same non-loopback egress the daemon allows:
  # Envoy (proxied connections) and root (DNS forwarding). All other
  # user traffic is NAT-redirected to Envoy on loopback by the daemon.
  networking.nftables.tables.terrarium-guard = {
    family = "inet";
    content = ''
      chain output {
        type filter hook output priority 10; policy accept;
        oifname "lo" accept
        meta skuid 1001 accept
        meta skuid 0 accept
        ct state established,related accept
        drop
      }
    '';
  };

  # Ensure the CA certificate directory exists for terrarium's
  # installCA, which copies the MITM CA cert here at runtime.
  systemd.tmpfiles.rules = [
    "d /usr/local/share/ca-certificates 0755 root root -"
    "f /etc/dnsmasq-hosts 0644 root root -"
  ];

  # Local DNS forwarder for e2e tests. Listens on a separate loopback
  # address (127.0.0.53) to avoid conflicting with terrarium's DNS
  # proxy on 127.0.0.1:53. The test driver writes hostname entries to
  # /etc/dnsmasq-hosts and reloads dnsmasq before restarting terrarium.
  # The Lima DHCP gateway IP (192.168.5.3) varies by network mode.
  services.dnsmasq = {
    enable = true;
    settings = {
      listen-address = "127.0.0.53";
      bind-interfaces = true;
      server = [ "192.168.5.3" ];
      addn-hosts = "/etc/dnsmasq-hosts";
    };
  };

  # Point resolv.conf at dnsmasq. When the terrarium daemon starts, it
  # reads /etc/resolv.conf and captures 127.0.0.53 as its upstream DNS,
  # then starts its own proxy on 127.0.0.1:53. No port conflict.
  networking.nameservers = lib.mkForce [ "127.0.0.53" ];

  # Install the e2e test CA into the system trust store so Envoy's MITM
  # DFP cluster validates upstream TLS connections signed by this CA.
  security.pki.certificateFiles = [ ./test-ca.pem ];
}
