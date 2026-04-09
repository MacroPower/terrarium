{
  description = "NixOS configuration for the Terrarium Lima VM";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    nixos-lima = {
      url = "github:nixos-lima/nixos-lima";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nur-packages = {
      url = "git+https://nur.jacobcolvin.com";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      nixos-lima,
      nur-packages,
      ...
    }@inputs:
    let
      modules = [
        "${nixos-lima}/lima.nix"
        ./configuration.nix
      ];

      mkArgs = system: {
        terrarium = nur-packages.packages.${system}.terrarium;
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
