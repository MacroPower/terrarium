{
  description = "NixOS configuration for the Terrarium Lima VM";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    nixos-lima = {
      url = "github:nixos-lima/nixos-lima";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    source = {
      url = "path:..";
      flake = false;
    };
  };

  outputs =
    {
      nixpkgs,
      nixos-lima,
      source,
      ...
    }@inputs:
    let
      lib = nixpkgs.lib;

      mkTerrarium = pkgs:
        pkgs.buildGoModule {
          pname = "terrarium";
          version = "dev";
          src = lib.cleanSource source;
          vendorHash = "sha256-MJNyu4NtDsDKbcUfi6PbRe4qHRHlxtnBMUNP/NBAf3M=";
          env.CGO_ENABLED = 0;
          subPackages = [ "cmd/terrarium" ];
          ldflags = [
            "-s"
            "-w"
            "-X go.jacobcolvin.com/x/version.Version=dev"
          ];
          flags = [ "-trimpath" ];
        };

      modules = [
        "${nixos-lima}/lima.nix"
        ./configuration.nix
      ];

      mkArgs = system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          terrarium = mkTerrarium pkgs;
        };

      mkSystem =
        system:
        nixpkgs.lib.nixosSystem {
          inherit system modules;
          specialArgs = mkArgs system;
        };

    in
    rec {
      nixosConfigurations = {
        terrarium-aarch64 = mkSystem "aarch64-linux";
        terrarium-x86_64 = mkSystem "x86_64-linux";
      };

      packages = {
        aarch64-linux.image = nixosConfigurations.terrarium-aarch64.config.system.build.images.qemu-efi;
        x86_64-linux.image = nixosConfigurations.terrarium-x86_64.config.system.build.images.qemu-efi;
      };
    };
}
