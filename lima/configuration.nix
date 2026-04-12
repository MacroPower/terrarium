{
  lib,
  pkgs,
  terrarium,
  ...
}:
let
  testImage = pkgs.dockerTools.buildLayeredImage {
    name = "terrarium-test";
    tag = "latest";
    contents = pkgs.buildEnv {
      name = "test-image-env";
      paths = [ pkgs.curl pkgs.cacert pkgs.nginx pkgs.openssl pkgs.coreutils ];
      pathsToLink = [ "/bin" "/etc" "/lib" "/share" ];
    };
    # Minimal passwd/group so nginx can resolve user "nobody".
    fakeRootCommands = ''
      mkdir -p ./etc ./tmp ./var/log/nginx
      echo 'root:x:0:0:root:/root:/bin/false' > ./etc/passwd
      echo 'nobody:x:65534:65534:nobody:/nonexistent:/bin/false' >> ./etc/passwd
      echo 'root:x:0:' > ./etc/group
      echo 'nobody:x:65534:' >> ./etc/group
      echo 'nogroup:x:65533:' >> ./etc/group
    '';
    config.Env = [ "PATH=/bin" ];
  };
in
{
  environment.systemPackages = [ terrarium pkgs.envoy-bin pkgs.nginx pkgs.socat pkgs.openssl pkgs.curl pkgs.nerdctl pkgs.cni-plugins pkgs.conntrack-tools ];

  # Containerd for running bridge-networked test containers.
  virtualisation.containerd.enable = true;

  # br_netfilter forces bridged L2 frames through netfilter inet hooks
  # so terrarium's nftables rules see container-to-container traffic.
  boot.kernelModules = [ "br_netfilter" ];
  boot.kernel.sysctl = {
    "net.bridge.bridge-nf-call-iptables" = 1;
    "net.bridge.bridge-nf-call-ip6tables" = 1;
    "net.ipv4.ip_forward" = 1;
    # route_localnet on default ensures dynamically-created interfaces
    # (cni0, veth*) inherit the setting. Required for DNAT to 127.0.0.1
    # on bridge interfaces.
    "net.ipv4.conf.default.route_localnet" = 1;
  };

  # Disable the NixOS firewall. Its nftables INPUT chain (policy DROP)
  # fires before terrarium's and blocks DNATted bridge-container traffic
  # (DNS, HTTP) that terrarium explicitly accepts. Terrarium manages its
  # own table; the NixOS firewall is redundant and actively conflicts.
  # This does not affect networking.nftables.tables.* (boot-time table
  # and guard table remain).
  networking.firewall.enable = false;

  # CNI bridge network for test containers. ipMasq is disabled to
  # avoid MASQUERADE rules that could interact with terrarium's
  # nftables table.
  environment.etc."cni/net.d/10-bridge.conflist".text = builtins.toJSON {
    cniVersion = "1.0.0";
    name = "bridge";
    plugins = [
      {
        type = "bridge";
        bridge = "cni0";
        isGateway = true;
        ipMasq = false;
        ipam = {
          type = "host-local";
          ranges = [ [ { subnet = "172.20.0.0/16"; gateway = "172.20.0.1"; } ] ];
          routes = [ { dst = "0.0.0.0/0"; } ];
        };
      }
      { type = "portmap"; capabilities = { portMappings = true; }; }
      { type = "loopback"; }
    ];
  };

  # Pre-load the test container image into containerd.
  systemd.services.load-test-image = {
    after = [ "containerd.service" ];
    requires = [ "containerd.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      TimeoutStartSec = "60s";
      ExecStartPre = "${pkgs.writeShellScript "wait-containerd" ''
        for i in $(seq 1 30); do
          ${pkgs.nerdctl}/bin/nerdctl version >/dev/null 2>&1 && exit 0
          sleep 1
        done
        exit 1
      ''}";
      ExecStart = "${pkgs.nerdctl}/bin/nerdctl load -i ${testImage}";
    };
  };

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

  # Test user (UID 1000) for container assertion commands.
  users.users.testuser = {
    isNormalUser = true;
    uid = 1000;
  };

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
    logging = {
      firewall.enabled = true;
    };
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
        # Allow dnsmasq to forward DNS queries to the upstream resolver.
        # dnsmasq runs as a dedicated user (not root) and must reach the
        # Lima gateway when the terrarium daemon is not running.
        udp dport 53 accept
        tcp dport 53 accept
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
      server = [ "192.168.5.2" ];
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
