{
  description = "A flake for building the package";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      naersk,
    }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;
      pkgsBySystem = forAllSystems (
        system:
        import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        }
      );
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsBySystem.${system};
          target = "wasm32-wasip1";
          rust = pkgs.rust-bin.stable.latest.default.override { targets = [ target ]; };
        in
        {
          default =
            (pkgs.callPackage naersk {
              cargo = rust;
              rustc = rust;
            }).buildPackage
              {
                src = ./.;
                doCheck = false;
                cargoBuildOptions = prev: [ "--target=${target}" ] ++ prev;
                copyBins = false;
                copyLibs = false;
                postInstall = ''
                  mkdir -p $out/lib
                  for bin in $(find ./target/${target}/release -type f -executable); do
                    install -Dm 755 $bin $out/lib/$(basename $bin)
                  done
                '';
                passthru = { inherit rust target; };
              };
        }
      );
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsBySystem.${system};
          inherit (pkgs) mkShell;
          inherit (self.packages.${system}.default) rust;
        in
        mkShell {
          buildInputs = [ rust ];
        }
      );
    };
}
