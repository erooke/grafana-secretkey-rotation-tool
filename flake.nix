{
  description = "grafana_secretkey_rotation_tool";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs allSystems (
          system:
          f {
            pkgs = import nixpkgs { inherit system; };
          }
        );
    in
    {
      packages = forAllSystems (
        { pkgs }:
        {
          default = pkgs.buildGoModule {
            pname = "rotate";
            version = "1.0.0";
            src = ./.;
            vendorHash = "sha256-J6CbBjJ/5etSOI5uaw0UlcK+zfIvL5veHnS4rY0KeRY=";
          };
        }
      );
    };
}
