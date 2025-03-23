{
  description = "Obsrvr Flow Plugin: Kale Metrics Processor";

  nixConfig = {
    allow-dirty = true;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages = {
          default = pkgs.buildGoModule {
            pname = "flow-processor-kale-metrics";
            version = "1.0.0";
            src = ./.;
            vendorHash = null;
            hardeningDisable = [ "all" ];
            preBuild = ''
              export CGO_ENABLED=1
            '';
            buildPhase = ''
              runHook preBuild
              go build -mod=vendor -buildmode=plugin -o flow-processor-kale-metrics.so .
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib
              cp flow-processor-kale-metrics.so $out/lib/
              mkdir -p $out/share
              cp go.mod $out/share/
              if [ -f go.sum ]; then
                cp go.sum $out/share/
              fi
              if [ -f README.md ]; then
                cp README.md $out/share/
              fi
              runHook postInstall
            '';
            nativeBuildInputs = [ pkgs.pkg-config ];
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_23
            pkg-config
            git
            gopls
            delve
          ];
          shellHook = ''
            export CGO_ENABLED=1
            if [ ! -d vendor ]; then
              echo "Vendoring dependencies..."
              go mod tidy
              go mod vendor
            fi
            echo "Development environment ready! To build, run: go build -buildmode=plugin -o flow-processor-kale-metrics.so ."
          '';
        };
      }
    );
} 