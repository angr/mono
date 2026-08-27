{
  description = "angr/mono (EXPERIMENT): the angr components built and tested from a single tree";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/6b5e5b7a6631f065bf6908986990b37d845f847f";

    # VEX stays external on purpose: it is a vendored fork of valgrind's IR
    # library with its own release cadence, and pyvex only ever consumes it as
    # a source drop. Pinning it here keeps `pyvex/vex` out of this tree while
    # still giving every build the same bytes.
    vex = {
      url = "github:angr/vex/875f7c9a5f6be621b4f000c29c016e15ddf32207";
      flake = false;
    };

    # angr's function and type definitions: ~200 MB of generated JSON.
    angr-data = {
      url = "github:angr/angr-data";
      flake = false;
    };

    # Test fixtures. The component suites resolve them as `../../binaries`
    # relative to their own tests directory, which is exactly where
    # `ci/link-external.sh` puts this input.
    binaries = {
      url = "github:angr/binaries";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      vex,
      angr-data,
      binaries,
    }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = lib.genAttrs systems;

      pythonOverlay =
        pkgs:
        import ./nix/python-overlay.nix {
          inherit (pkgs) lib;
          src = self;
          vexSrc = vex;
          angrDataSrc = angr-data;
        };

      overlay = final: prev: {
        pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [ (pythonOverlay final) ];
      };

      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ overlay ];
        };

      # Python 3.12 matches the angr development shell; upstream supports 3.12-3.14.
      pythonFor = pkgs: pkgs.python312;

      # `nix run` needs to know which of the environment's several dozen
      # executables is the point of it.
      named =
        program: env:
        env.overrideAttrs (old: {
          meta = (old.meta or { }) // {
            mainProgram = program;
          };
        });

      # What `nix run github:angr/mono` gives you: angr and its optional
      # engines, nothing test-related.
      runtimeEnvFor =
        pkgs:
        named "angr" (
          (pythonFor pkgs).withPackages (p: [
            p.angr
            p.unicorn
          ])
        );

      # What CI runs the component suites in. Kept apart from the runtime
      # environment so the default closure stays lean.
      testPackages = p: [
        p.angr
        p.unicorn
        # angr's `llm` extra: tests/llm and tests/mcp are part of the suite,
        # so the packages they import are part of the environment.
        p.pydantic-ai
        p.mcp
        p.fastmcp
        p.pytest
        p.pytest-xdist
        p.pytest-timeout
        p.pytest-forked
        p.pytest-split
        p.keystone-engine
        p.sqlalchemy
        p.pydantic
      ];

      # angr-management and its suite. Apart again: pulling Qt into the core
      # test environment would grow the closure the other six suites carry for
      # a dependency none of them import.
      guiPackages = p: [
        p.angr-management
        p.unicorn
        p.pytest
        p.pytest-xdist
        p.pytest-timeout
        p.pytest-split
      ];

      # The build backends, so `ci/dev-setup.sh` can rebuild a component from
      # the source tree in place instead of through a Nix rebuild.
      buildPackages = p: [
        p.pip
        p.setuptools
        p.setuptools-rust
        p.scikit-build-core
        p.cffi
        p.nanobind
        p.grpcio-tools
        p.protobuf
        p.wheel
        p.editables
        p.pathspec
      ];

      # nixpkgs' qtawesome is Linux-only at this pin, so angr-management and
      # everything that carries it exist only where it can be built. The other
      # six components are fine everywhere the flake claims.
      hasGui = pkgs: pkgs.stdenv.hostPlatform.isLinux;

      testEnvFor = pkgs: (pythonFor pkgs).withPackages testPackages;
      guiEnvFor = pkgs: named "angr-management" ((pythonFor pkgs).withPackages guiPackages);
      devEnvFor =
        pkgs:
        (pythonFor pkgs).withPackages (
          p: testPackages p ++ lib.optionals (hasGui pkgs) (guiPackages p) ++ buildPackages p
        );
    in
    {
      overlays.default = overlay;

      # nix fmt
      formatter = forAllSystems (system: (pkgsFor system).nixfmt-rfc-style);

      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          ps = (pythonFor pkgs).pkgs;
        in
        {
          default = runtimeEnvFor pkgs;
          angr = runtimeEnvFor pkgs;
          test-env = testEnvFor pkgs;

          angr-lib = ps.angr;
          cle-lib = ps.cle;
          claripy-lib = ps.claripy;
          pyvex-lib = ps.pyvex;
          archinfo-lib = ps.archinfo;
          pypcode-lib = ps.pypcode;
          angr-data-lib = ps.angr-data;

          # Test fixtures and VEX sources as store paths, so CI warms and
          # transfers them through the same binary cache as everything else.
          binaries = pkgs.runCommandLocal "angr-binaries" { } "ln -s ${binaries} $out";
          vex-src = pkgs.runCommandLocal "angr-vex" { } "ln -s ${vex} $out";

        }
        // lib.optionalAttrs (hasGui pkgs) {
          gui-env = guiEnvFor pkgs;
          angr-management = guiEnvFor pkgs;
          angr-management-lib = ps.angr-management;
        }
      );

      legacyPackages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          pythonPackages = (pythonFor pkgs).pkgs;
          python = pythonFor pkgs;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          # nix develop .#test --command pytest ...
          test = pkgs.mkShell {
            packages = [
              (testEnvFor pkgs)
              pkgs.binutils
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.gcc ];
          };

          # Everything needed to hack on the tree itself.
          default = pkgs.mkShell {
            packages = [
              (devEnvFor pkgs)
              pkgs.binutils
              pkgs.cargo
              pkgs.rustc
              pkgs.cmake
              pkgs.ninja
              pkgs.git
              pkgs.jq
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.gcc ];
            shellHook = ''
              echo "angr/mono dev shell."
              echo "  ci/link-external.sh   fixtures and VEX sources into place"
              echo "  ci/dev-setup.sh       editable installs of every component in .venv"
              echo "  ci/run-suite.sh cle   one component's suite"
            '';
          };
        }
        // lib.optionalAttrs (hasGui pkgs) {
          # nix develop .#gui --command pytest ... -- what the angr-management
          # suite runs in.
          gui = pkgs.mkShell {
            packages = [
              (guiEnvFor pkgs)
              pkgs.binutils
            ];
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          env = self.packages.${system}.angr;
          runPython =
            name: script: args:
            pkgs.runCommand name { nativeBuildInputs = [ env ]; } ''
              export HOME=$TMPDIR XDG_CONFIG_HOME=$TMPDIR XDG_CACHE_HOME=$TMPDIR XDG_DATA_HOME=$TMPDIR
              python3 ${script} ${args}
              touch $out
            '';
        in
        {
          import-smoke =
            runPython "angr-import-smoke" ./nix/checks/import_smoke.py
              (pythonFor pkgs).pkgs.monoPinned.z3-solver.version;
          fauxware-cfg =
            runPython "angr-fauxware-cfg" ./nix/checks/fauxware_cfg.py
              "${binaries}/tests/x86_64/fauxware";
        }
      );
    };
}
