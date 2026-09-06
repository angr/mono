{
  description = "angr/mono (EXPERIMENT): the angr components built and tested from a single tree";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/6b5e5b7a6631f065bf6908986990b37d845f847f";

    # angr's function and type definitions: ~200 MB of generated JSON.
    angr-data = {
      url = "github:angr/angr-data";
      flake = false;
    };

  };

  outputs =
    {
      self,
      nixpkgs,
      angr-data,
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
          angrDataSrc = angr-data;
        };

      # We do not run third-party packages' own test suites.
      #
      # Upstream tests its own code. What this repository needs from those
      # packages is that they build and import; whether they work for our use
      # is what our own component suites are for. Leaving their suites on
      # means a clock-dependent test in somebody else's package can fail
      # `warm`, and `warm` gates every one of the 97 jobs in the matrix. It
      # keeps happening: backrefs, portalocker, python-ulid, cyclopts,
      # syrupy, fastmcp, inline-snapshot, libbs and binsync have all had to
      # be patched or skipped, and most recently python3.12-httpx2-2.9.1's
      # websocket keepalive test took the whole matrix down -- attempt 1 of
      # run 34038401917 lost 15 jobs that never started. Not one of those
      # failures said anything about angr's code.
      #
      # The boundary is ours versus not-ours, and it needs no list of names.
      # Our twelve components -- angr, angr-data, angr-management,
      # angr-platforms, angrop, archinfo, claripy, cle, pypcode, pysoot,
      # pyvex and tracer -- already set `doCheck = false`, because the
      # monorepo ships no test fixtures and the suites run from the source
      # tree instead. So "turn checks off for every package in the set"
      # leaves our twelve exactly where they are and turns off everybody
      # else's. A hand-maintained list of third-party names is the thing this
      # avoids: it goes stale on the next nixpkgs bump, and which packages
      # run their suites at all depends on what Hydra happens to have built.
      #
      # What still gates is untouched. `mk-python-derivation` adds the
      # import, runtime-dependency, conflict and metadata check hooks
      # unconditionally rather than as check inputs, so a package that no
      # longer runs pytest must still import cleanly, resolve its runtime
      # dependencies, not collide with anything else in the environment, and
      # carry consistent metadata. Only the pytest phase and its check inputs
      # go.
      #
      # This replaces six per-package overrides in nix/python-overlay.nix,
      # whose comment predicted that the answer to a fifth failure would be
      # to stop running the *llm stack's* suites. The fifth was httpx2, and
      # that narrower rule would not have caught it: httpx2 is not an llm
      # package at all. It is in the build closure of pyvex, cle and angr
      # through pyvex -> bitstring -> pytest-benchmark -> elasticsearch ->
      # elastic-transport -> respx -> starlette -> httpx2, where bitstring is
      # a pyvex runtime dependency and pytest-benchmark is bitstring's check
      # input. Scoping the rule to one stack leaves the failure in place.
      #
      # Gated on 3.12 because that is the interpreter this flake builds for.
      # Mapping the 3.14 set as well breaks evaluation outright: nixpkgs'
      # fetch-cargo-vendor calls `charset-normalizer.override`, and
      # `overridePythonAttrs` returns a derivation that has no `override`.
      noThirdPartyTests =
        _pythonFinal: pythonPrev:
        if pythonPrev.python.pythonVersion != "3.12" then
          { }
        else
          lib.mapAttrs (
            _name: value:
            # Mapping the whole set reaches attributes that throw when
            # forced -- packages nixpkgs marks unsupported on this platform,
            # aliases it has removed. Those pass through untouched and throw
            # when something asks for them, exactly as they did before.
            let
              overridable = builtins.tryEval (lib.isDerivation value && value ? overridePythonAttrs);
              checksOff =
                drv:
                drv.overridePythonAttrs (_: {
                  doCheck = false;
                });
            in
            if overridable.success && overridable.value then
              # `overridePythonAttrs` returns a derivation with no `override`,
              # and nixpkgs defines packages in terms of one another that way
              # -- `beets-minimal = beets.override { ... }` in
              # python-packages.nix, `charset-normalizer.override` in
              # fetch-cargo-vendor. Dropping `override` turns those into
              # evaluation errors, so it is put back, applying the rule to
              # whatever it returns.
              checksOff value
              // lib.optionalAttrs (value ? override) {
                override = args: checksOff (value.override args);
              }
            else
              value
          ) pythonPrev;

      overlay = final: prev: {
        # The order matters: noThirdPartyTests has to come after the
        # monorepo's own extension so that it also covers the third-party
        # packages that extension defines.
        pythonPackagesExtensions = prev.pythonPackagesExtensions ++ [
          (pythonOverlay final)
          noThirdPartyTests
        ];
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
      # `pkgs` as well as the package set: tracer's shellphish-qemu is a
      # prebuilt wheel published only for x86_64 Linux, so the eighteen angr
      # tests it gates run on the system the Nix lane uses and report as
      # skips elsewhere -- which is what upstream does too.
      testPackagesFor = pkgs: p: [
        p.angr
        p.unicorn
        # angr's `llm` extra: tests/llm and tests/mcp are part of the suite,
        # so the packages they import are part of the environment.
        p.pydantic-ai
        p.mcp
        p.fastmcp
        # Twenty-one of angr's tests are behind `skipUnless(pysoot)` and
        # they skipped here while pysoot sat in the tree unpackaged, which
        # is the failure mode importing it was meant to remove.
        p.pysoot
        # claripy's suite runs in this environment (ci/suites.json), and
        # since angr/angr#6550 angr vendors claripy at angr/angr/claripy and
        # no longer depends on the package -- so nothing pulls it in any
        # more. Without this line ci/run-suite.sh aborts with "cannot import
        # claripy in the 'test' environment".
        p.claripy
        # The dependents whose own suites run here. Upstream tests every
        # transitive dependent of a changed component; without these, a
        # claripy change is tried against angr and angr-management only.
        p.angr-platforms
        p.angrop
        p.pytest
        p.pytest-xdist
        p.pytest-timeout
        p.pytest-forked
        p.pytest-split
        p.keystone-engine
        p.sqlalchemy
        p.pydantic
      ]
      ++ lib.optionals (pkgs.stdenv.hostPlatform.system == "x86_64-linux") [ p.tracer ];

      # angr-management and its suite. Apart again: pulling Qt into the core
      # test environment would grow the closure the other six suites carry for
      # a dependency none of them import.
      guiPackages = p: [
        p.angr-management
        p.unicorn
        # angr-management's MCP suite skips itself unless fastmcp and uvicorn
        # are importable -- the 29 in tests/test_mcp_server.py plus one in
        # test_main_window.py, which looked like they ran and did not.
        p.pydantic-ai
        p.mcp
        p.fastmcp
        p.uvicorn
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

      testEnvFor = pkgs: (pythonFor pkgs).withPackages (testPackagesFor pkgs);
      guiEnvFor = pkgs: named "angr-management" ((pythonFor pkgs).withPackages guiPackages);
      devEnvFor =
        pkgs:
        (pythonFor pkgs).withPackages (
          p: testPackagesFor pkgs p ++ lib.optionals (hasGui pkgs) (guiPackages p) ++ buildPackages p
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
              # pysoot starts a JVM through jpype. Both halves are needed and
              # neither belongs in the package: pysoot runs `java` off PATH,
              # and jpype ignores that lookup entirely -- it has its own
              # finder that reads JAVA_HOME and otherwise cannot find
              # libjvm.so. Patching the two lookups into the derivation was
              # the first attempt and it broke pysoot's own
              # test_no_java_on_path, which clears the environment and
              # expects the lookup to fail. Upstream supplies both the same
              # way, with actions/setup-java.
              pkgs.jdk
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.gcc ];
            env = {
              JAVA_HOME = pkgs.jdk.home;
            }
            // lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
              # tracer runs 32-bit ELFs under shellphish-qemu, and they are
              # dynamically linked: without a 32-bit loader qemu stops at
              # `Could not open '/lib/ld-linux.so.2'`, the trace comes back
              # empty, and test_runner fails its `len(r.trace) > 100`. On a
              # distribution that is `libc6:i386`; upstream's CI image has it
              # already. Here it is a store path, named the way qemu-user
              # expects to be told.
              QEMU_LD_PREFIX = "${pkgs.pkgsi686Linux.glibc}";
            };
          };

          # Everything needed to hack on the tree itself.
          default = pkgs.mkShell {
            packages = [
              (devEnvFor pkgs)
              pkgs.binutils
              pkgs.cargo
              pkgs.rustc
              # CI runs cargo fmt and clippy over angr's extension; a dev
              # shell that cannot is a dev shell that finds out on the PR.
              pkgs.rustfmt
              pkgs.clippy
              pkgs.cmake
              pkgs.ninja
              pkgs.git
              pkgs.jq
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.gcc ];
            shellHook = ''
              echo "angr/mono dev shell."
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
          # The fixtures live in this repository now and deliberately do
          # not go into the flake -- half a gigabyte of them would land in
          # every closure and every cache upload. This check needs exactly
          # one 8.7 KB file, so that one file is content-addressed into the
          # store on its own. Nothing else in `binaries/` reaches Nix, and a
          # fixture change elsewhere cannot invalidate a build.
          fauxware-cfg =
            runPython "angr-fauxware-cfg" ./nix/checks/fauxware_cfg.py
              "${builtins.path {
                path = ./binaries/tests/x86_64/fauxware;
                name = "fauxware";
              }}";
        }
      );
    };
}
