{
  description = "Flake of the test repository";

  outputs =
    { nixpkgs, ... }:
    {
      packages.aarch64-linux.default = nixpkgs.legacyPackages.aarch64-linux.buildGoModule {
        pname = "repo";
        version = "dev";
        src = ./..;
        vendorHash = "sha256-Saiub9Fa4ougHAdfKhM1jfyK3/P+bkoVL0fD2KXYVIc=";
        env.GOWORK = "off";
      };
    };
}
