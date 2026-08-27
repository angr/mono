# Python package-set overlay that builds the monorepo components.
#
# Every derivation reads its dependency list and build backend from the
# component's own pyproject.toml, so the flake follows upstream as the trees
# move. The hand-maintained pieces are: the version-file locations, the
# packages nixpkgs does not carry (`skipped`), the exact-version table
# (`pinned`) for the few third-party packages whose version matters, and the
# native build wiring (Rust for angr, CMake for pyvex and pypcode).
{
  lib,
  src, # the monorepo root
  vexSrc, # checkout of github:angr/vex (kept external, pinned in flake.lock)
  angrDataSrc, # checkout of github:angr/angr-data (flake input)
}:
python-final: python-prev:
let
  inherit (python-final) buildPythonPackage;
  pkgs = python-final.pkgs;
  system = pkgs.stdenv.hostPlatform.system;

  # PEP 503 normalisation; nixpkgs attribute names follow it.
  normalize = n: lib.toLower (builtins.replaceStrings [ "_" "." ] [ "-" "-" ] n);
  specName =
    spec:
    normalize (builtins.head (builtins.match "^[[:space:]]*([A-Za-z0-9][A-Za-z0-9._-]*).*$" spec));
  # Requirements whose environment marker excludes the platform we build for.
  isDarwin = pkgs.stdenv.hostPlatform.isDarwin;
  notForUs =
    spec:
    builtins.match ".*platform_system[[:space:]]*==[[:space:]]*['\"]Windows['\"].*" spec != null
    ||
      builtins.match ".*sys_platform[[:space:]]*==[[:space:]]*['\"](win32|emscripten)['\"].*" spec != null
    || (
      !isDarwin
      && builtins.match ".*platform_system[[:space:]]*==[[:space:]]*['\"]Darwin['\"].*" spec != null
    );

  # Distribution names nixpkgs spells differently. PySide6 is one package
  # there, not the Essentials/Addons split PyPI publishes.
  aliases = {
    "pyside6-essentials" = "pyside6";
    "pyside6-addons" = "pyside6";
    # The pyobjc family is the one place nixpkgs does not follow PEP 503
    # normalisation, and angr-management asks for it on Darwin.
    "pyobjc-framework-cocoa" = "pyobjc-framework-Cocoa";
  };

  # Runtime requirements nixpkgs does not package and this overlay does not
  # add. cle guards the import (cle/backends/uefi_firmware.py), so only the
  # UEFI-firmware path loses functionality.
  #
  # pyxdia used to be on this list. It is not any more: dropping it makes five
  # of cle's PE tests fail, because a PDB is unreadable without it and
  # `find_symbol` quietly returns None. A test suite that fails for want of an
  # optional dependency is not a suite that tells you anything, so the wheel is
  # packaged below instead.
  skipped = [
    "uefi-firmware"
  ];

  # ---------------------------------------------------------------------------
  # Exact-version table.
  #
  # Most third-party pins are relaxed (pythonRelaxDeps) and the nixpkgs version
  # is used. The packages below are the exception: their version changes
  # behaviour in ways the test suites catch (z3 4.16's Python binding types
  # Z3_fpa_get_numeral_sign's out-parameter as c_bool and blows up FP solves;
  # pyelftools 0.32 rejects SHT_NULL sh_link before cle's soname guard runs), so
  # the overlay provides the version upstream develops against and checks every
  # component requirement against it at evaluation time. When upstream bumps a
  # `==` pin or raises a floor above the provided version, evaluation fails
  # with a message naming the package; extend the table rather than relaxing.
  #
  # These packages are resolved only by the component derivations and exposed
  # as `monoPinned.<name>`; they deliberately do NOT replace the canonical
  # attributes of the shared package set. Overriding `pyelftools` globally
  # would rebuild auto-patchelf (a python3 env with pyelftools) and with it
  # rustc's bootstrap, i.e. hours of rebuilding for every user.
  pinned = {
    "z3-solver" =
      let
        version = "4.13.0.0";
        # PyPI wheels: fastest reliable route (a source build of z3 takes
        # tens of minutes and nixpkgs' z3 recipe carries patches for 4.16).
        wheels = {
          x86_64-linux = {
            platform = "manylinux2014_x86_64";
            hash = "sha256-jELegrbj/37mEofQPHr4qZ+fZVTN0SBMa5vKlv8ct/s=";
          };
          aarch64-linux = {
            platform = "manylinux2014_aarch64";
            hash = "sha256-nWIgIqNRHAWZFcVrLCMchLXBvhuC9FfXVg3aPZFkdP4=";
          };
          aarch64-darwin = {
            platform = "macosx_11_0_arm64";
            hash = "sha256-vKfVmmmaRAJHU3whgMUZ1oLJ3zUgoWziiPztYacNJT0=";
          };
        };
        wheel =
          wheels.${system}
            or (throw "z3-solver ${version}: no wheel hash recorded for ${system} in nix/python-overlay.nix");
      in
      buildPythonPackage {
        pname = "z3-solver";
        inherit version;
        format = "wheel";
        src = python-final.fetchPypi {
          pname = "z3_solver";
          inherit version;
          format = "wheel";
          python = "py2.py3";
          abi = "none";
          inherit (wheel) platform hash;
        };
        # libz3.so in the wheel links libstdc++ from the manylinux toolchain.
        nativeBuildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.autoPatchelfHook ];
        buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.stdenv.cc.cc.lib ];
        doCheck = false;
        pythonImportsCheck = [ "z3" ];
        meta = {
          description = "Z3 theorem prover Python bindings (pinned by claripy)";
          homepage = "https://github.com/Z3Prover/z3";
          license = lib.licenses.mit;
        };
      };
    "pyelftools" = python-prev.pyelftools.overridePythonAttrs (old: rec {
      version = "0.33";
      src = python-final.fetchPypi {
        pname = "pyelftools";
        inherit version;
        hash = "sha256-Zg2C3L646D0XAr2X8iP3YWJdoGERwMyYjqxrirDBth8=";
      };
      # The sdist ships no test tree.
      doCheck = false;
    });
  };

  # Enforce the table against a requirement string from `component`.
  matchVersion = op: spec: builtins.match (".*" + op + "[[:space:]]*([0-9][0-9A-Za-z.!+-]*).*") spec;
  # Every version constraint a component writes against a pinned package has
  # to be one this function actually models. An operator it does not
  # understand is a `throw`, not a pass: silently installing 4.13 for a
  # `~= 4.16` is the exact failure the table exists to prevent.
  checkPinned =
    component: spec:
    let
      name = specName spec;
      provided = pinned.${name}.version;
      constraints = builtins.filter (c: c != "") (
        lib.splitString "," (lib.removePrefix (specName spec) (lib.toLower spec))
      );
      check =
        constraint:
        let
          exact = matchVersion "==" constraint;
          floor = matchVersion ">=" constraint;
          bare = builtins.match "^[[:space:]]*$" constraint != null;
          modelled = exact != null || floor != null || bare;
        in
        if !modelled then
          throw "${component} constrains ${name} with `${constraint}`, which nix/python-overlay.nix does not model; extend checkPinned"
        else if exact != null && builtins.head exact != provided then
          throw "${component} requires ${name}==${builtins.head exact} but nix/python-overlay.nix provides ${provided}; update the `pinned` table"
        else if floor != null && !(lib.versionAtLeast provided (builtins.head floor)) then
          throw "${component} requires ${name}>=${builtins.head floor} but nix/python-overlay.nix provides ${provided}; update the `pinned` table"
        else
          true;
    in
    if !(pinned ? ${name}) then spec else lib.deepSeq (map check constraints) spec;

  resolve =
    name:
    let
      n = aliases.${name} or name;
    in
    pinned.${n} or python-final.${n};
  depsOf =
    component: specs:
    map resolve (
      lib.filter (n: !(lib.elem n skipped)) (
        map specName (map (checkPinned component) (lib.filter (s: !(notForUs s)) specs))
      )
    );

  readPyproject = dir: builtins.fromTOML (builtins.readFile (dir + "/pyproject.toml"));

  versionFrom =
    file:
    let
      re = "__version__ = \"([^\"]+)\".*";
      line = lib.findFirst (l: builtins.match re l != null) (throw "no __version__ in ${toString file}") (
        lib.splitString "\n" (builtins.readFile file)
      );
    in
    builtins.head (builtins.match re line);

  mkComponent =
    {
      pname,
      versionFile,
      extraDependencies ? [ ],
      extraRemoveDeps ? [ ],
      nativeBuildInputs ? [ ],
      postPatch ? "",
      ...
    }@args:
    let
      # builtins.path copies the component directory into its own
      # content-addressed store path. Referencing `src + "/${pname}"`
      # directly would make every derivation depend on the whole tree, so an
      # edit to flake.nix or a check script would rebuild the Rust extension.
      dir = builtins.path {
        path = src + "/${pname}";
        name = "${pname}-source";
      };
      pyproject = readPyproject dir;
    in
    buildPythonPackage (
      (removeAttrs args [
        "versionFile"
        "extraDependencies"
        "extraRemoveDeps"
      ])
      // {
        inherit pname;
        version = versionFrom (dir + "/${versionFile}");
        pyproject = true;
        src = dir;

        build-system = depsOf pname pyproject.build-system.requires;
        dependencies = depsOf pname (pyproject.project.dependencies or [ ]) ++ extraDependencies;

        # Sibling pins (cle==9.3.4.dev0 ...) and third-party exact pins
        # (lmdb==2.1.1 ...) are relaxed in the wheel metadata; the monorepo
        # snapshots are what we ship. Packages in `pinned` are provided at the
        # required version instead, checked above.
        pythonRelaxDeps = true;
        pythonRemoveDeps = skipped ++ extraRemoveDeps;

        nativeBuildInputs = nativeBuildInputs;
        postPatch = ''
          python ${./relax-build-requires.py} pyproject.toml
        ''
        + postPatch;

        # The monorepo ships no test fixtures (angr/binaries).
        doCheck = false;

        meta = {
          license = lib.licenses.bsd2;
          homepage = "https://angr.io/";
        }
        // (args.meta or { });
      }
    );
in
{
  monoPinned = pinned;

  # binsync (an angr-management dependency) and its libbs core fail their own
  # nixpkgs test suites on this pin: both parse C declarations through
  # pycparser, and pycparser 3 dropped the bundled `ply` attribute they reach
  # for. Neither failure is about angr-management, and neither package is under
  # test here, so the two affected files are skipped rather than patched.
  libbs = python-prev.libbs.overridePythonAttrs (old: {
    disabledTestPaths = (old.disabledTestPaths or [ ]) ++ [ "tests/test_client_server.py" ];
  });

  binsync = python-prev.binsync.overridePythonAttrs (old: {
    disabledTestPaths = (old.disabledTestPaths or [ ]) ++ [ "tests/test_auxiliary_server.py" ];
  });

  # backrefs reaches this tree through pydantic-ai's documentation stack
  # (pydantic-ai-slim -> griffelib -> mkdocstrings -> mkdocs-material). Its
  # test_timeout asserts that a regex search exceeds a wall-clock budget and
  # raises; on a busy CI runner the search finishes first and the test fails
  # for having been too fast. Nothing here depends on that behaviour, and a
  # timing assertion is not something to make fourteen jobs depend on.
  backrefs = python-prev.backrefs.overridePythonAttrs (old: {
    disabledTests = (old.disabledTests or [ ]) ++ [ "test_timeout" ];
  });

  # py-key-value-aio is a transitive dependency of fastmcp -- a key-value
  # abstraction with a backend per store. fastmcp asks for it with no extras
  # and only ever uses the in-memory backend, but the package's own test suite
  # exercises every backend, so its check inputs name duckdb and pyarrow (both
  # from-source C++ builds, tens of minutes each) alongside mongodb,
  # elasticsearch, redis and memcached. None of that is on any runtime path
  # here. `doCheck = false` rather than skipping test files, because the cost
  # is in the check *inputs*, not in running the tests.
  py-key-value-aio = python-prev.py-key-value-aio.overridePythonAttrs (_: {
    doCheck = false;
  });

  # inline-snapshot is a test dependency of mcp, which angr's `llm` extra
  # needs. Its tests/test_docs.py runs the code blocks in the project's own
  # documentation and compares them against the formatted output recorded in
  # the Markdown; three of them disagree because the docs were written against
  # a different version of the code formatter than the one nixpkgs supplies,
  # so the expected text differs in line wrapping and highlighted line numbers.
  # The library itself is unaffected, so only that file is skipped.
  inline-snapshot = python-prev.inline-snapshot.overridePythonAttrs (old: {
    disabledTestPaths = (old.disabledTestPaths or [ ]) ++ [ "tests/test_docs.py" ];
  });

  # cle's PDB reader. Ships as a per-platform wheel wrapping a native library;
  # the sdist builds by downloading that library from GitHub releases, which a
  # sandboxed build cannot do, so the wheel is the only route.
  pyxdia =
    let
      version = "0.1.1";
      # Direct file URLs: fetchPypi's path scheme does not resolve a wheel
      # whose platform tag is a compatibility list.
      wheels = {
        x86_64-linux = {
          url = "https://files.pythonhosted.org/packages/82/44/a88fa7a26d8e0ae2e09ce9e19e25f5114f391cc82c820ef7c5e9aa85e2ab/pyxdia-0.1.1-py3-none-manylinux1_x86_64.manylinux_2_28_x86_64.manylinux_2_5_x86_64.whl";
          hash = "sha256-890kZ4wY1uoTdyyKFY7epVAasXz3R+QFFjCle/BIhP4=";
        };
        aarch64-linux = {
          url = "https://files.pythonhosted.org/packages/73/73/10158c938d99cefc4a111d95851e6c180dbf76083c6cfd8891c29eb985c4/pyxdia-0.1.1-py3-none-manylinux_2_28_aarch64.whl";
          hash = "sha256-xTqJNj/w6hJWgdGxp3xxgjWZkuOtvtzCRLo7PBBVJCY=";
        };
        aarch64-darwin = {
          url = "https://files.pythonhosted.org/packages/2b/a8/4060873178731c8c1e68077ef509cbc10e6e781ae9a0b2a87408ec813784/pyxdia-0.1.1-py3-none-macosx_14_0_arm64.whl";
          hash = "sha256-kIo7xfqeRMOpl+mk+KmxUR7AmVeYspLzB3aNXoBcbHQ=";
        };
      };
      wheel =
        wheels.${system}
          or (throw "pyxdia ${version}: no wheel hash recorded for ${system} in nix/python-overlay.nix");
    in
    buildPythonPackage {
      pname = "pyxdia";
      inherit version;
      format = "wheel";
      src = pkgs.fetchurl { inherit (wheel) url hash; };
      nativeBuildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.autoPatchelfHook ];
      buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.stdenv.cc.cc.lib ];
      doCheck = false;
      pythonImportsCheck = [ "pyxdia" ];
      meta = {
        description = "PDB debug information reader used by cle";
        homepage = "https://pypi.org/project/pyxdia/";
        license = lib.licenses.mit;
      };
    };

  # Two packages nixpkgs does not carry that the tree needs.
  #
  # pyqodeng is angr-management's code editor widget; pytest-split is what
  # upstream angr CI shards its 326 test files with (`--splits N --group K`),
  # and this repository's matrix uses the same flags so a shard here means the
  # same thing as a shard there.
  pyqodeng = buildPythonPackage rec {
    pname = "pyqodeng";
    version = "0.0.14";
    pyproject = true;
    src = python-final.fetchPypi {
      inherit pname version;
      hash = "sha256-Stdymiqijvtn3T254K4ILKsp6NVdEnl7cSdRP8Ya4eQ=";
    };
    build-system = [ python-final.setuptools ];
    dependencies = [
      python-final.pygments
      python-final.qtpy
      python-final.pyside6
    ];
    # nixpkgs ships Qt for Python as one `pyside6`, distribution name
    # "PySide6". The PyPI split-out "PySide6-Essentials" is a subset of it and
    # exists under no name here, so the requirement can never be satisfied and
    # is dropped instead.
    pythonRemoveDeps = [ "PySide6-Essentials" ];
    doCheck = false;
    meta = {
      description = "Code editor widget library for PySide6";
      homepage = "https://github.com/angr/pyqodeng";
      license = lib.licenses.mit;
    };
  };

  pytest-split = buildPythonPackage rec {
    pname = "pytest-split";
    version = "0.11.0";
    pyproject = true;
    src = python-final.fetchPypi {
      pname = "pytest_split";
      inherit version;
      hash = "sha256-jr2ynMcsyWLo6x7AfbHuuYqyXiFe2OMhb2ufx84OwrU=";
    };
    build-system = [ python-final.poetry-core ];
    dependencies = [ python-final.pytest ];
    doCheck = false;
    pythonImportsCheck = [ "pytest_split" ];
    meta = {
      description = "Split a test suite into equally-timed groups";
      homepage = "https://github.com/jerry-git/pytest-split";
      license = lib.licenses.mit;
    };
  };

  # angr's `llm` extra asks for pydantic-ai, which nixpkgs does not carry; it
  # has pydantic-ai-slim, the same release cut without the model-provider
  # extras. Upstream publishes `pydantic-ai` as a metadata-only distribution
  # whose sole content is a dependency on `pydantic-ai-slim[...]` at the
  # matching version -- the sdist holds a pyproject.toml and nothing else, and
  # the module `pydantic_ai` comes from slim either way. So the requirement is
  # satisfied by installing that upstream wheel over the slim package nixpkgs
  # already builds, at the version nixpkgs pins so the `==` inside it holds.
  #
  # The wheel is installed rather than built from the sdist because the sdist's
  # version comes from uv-dynamic-versioning reading git history, which an
  # unpacked tarball does not have.
  #
  # The provider extras the metadata names (openai, anthropic, google, cli,
  # mcp, evals, web, retries, logfire) are not pulled in: angr imports the core
  # API only (angr/llm_client.py), and picking up nine SDKs to satisfy a name
  # would cost far more than it buys. Any provider a caller actually wants is
  # an ordinary package added alongside.
  pydantic-ai =
    let
      version = "2.27.0";
    in
    buildPythonPackage {
      pname = "pydantic-ai";
      inherit version;
      format = "wheel";
      src = python-final.fetchPypi {
        pname = "pydantic_ai";
        inherit version;
        format = "wheel";
        dist = "py3";
        python = "py3";
        abi = "none";
        platform = "any";
        hash = "sha256-AAuXWOk2AMcUcbMCFncfjoWwrkezoFk1HMA9UaZqmWc=";
      };
      dependencies = [ python-final.pydantic-ai-slim ];
      # Both wheels ship the same `pai` console script, and an environment
      # holding both is a buildEnv collision. The metadata package's copy is
      # the redundant one: slim is where the code lives.
      postInstall = "rm -rf $out/bin";
      doCheck = false;
      pythonImportsCheck = [ "pydantic_ai" ];
      meta = {
        description = "Metadata package pairing the pydantic-ai name with nixpkgs' pydantic-ai-slim";
        homepage = "https://github.com/pydantic/pydantic-ai";
        license = lib.licenses.mit;
      };
    };

  angr-data = buildPythonPackage {
    pname = "angr-data";
    version = versionFrom (angrDataSrc + "/angr_data/__init__.py");
    pyproject = true;
    src = angrDataSrc;
    build-system = [ python-final.setuptools ];
    doCheck = false;
    pythonImportsCheck = [ "angr_data" ];
    meta.license = lib.licenses.bsd2;
  };

  archinfo = mkComponent {
    pname = "archinfo";
    versionFile = "archinfo/__init__.py";
    pythonImportsCheck = [ "archinfo" ];
  };

  pyvex = mkComponent {
    pname = "pyvex";
    versionFile = "pyvex/__init__.py";
    # scikit-build-core drives CMake itself; keep the nixpkgs cmake/ninja hooks
    # from configuring or building on their own.
    nativeBuildInputs = [
      pkgs.cmake
      pkgs.ninja
    ];
    dontUseCmakeConfigure = true;
    dontUseNinjaBuild = true;
    dontUseNinjaInstall = true;
    dontUseNinjaCheck = true;
    # VEX is not in this tree; CMakeLists.txt and license-files both want it
    # at ./vex, so the pinned flake input is copied in before the build.
    postPatch = ''
      cp -r --no-preserve=mode,ownership ${vexSrc} vex
    '';
    pythonImportsCheck = [ "pyvex" ];
    # angr's unicornlib compiles against these at build time.
    postInstall = ''
      test -d "$out/${python-final.python.sitePackages}/pyvex/include"
      test -d "$out/${python-final.python.sitePackages}/pyvex/lib"
    '';
    meta.license = with lib.licenses; [
      bsd2
      gpl2Only
    ];
  };

  pypcode = mkComponent {
    pname = "pypcode";
    versionFile = "pypcode/__version__.py";
    # setup.py invokes cmake itself (build tree under build/native).
    dontUseCmakeConfigure = true;
    pythonImportsCheck = [ "pypcode" ];
    meta.license = with lib.licenses; [
      bsd2
      asl20
      zlib
    ];
  };

  claripy = mkComponent {
    pname = "claripy";
    versionFile = "claripy/__init__.py";
    pythonImportsCheck = [ "claripy" ];
  };

  cle = mkComponent {
    pname = "cle";
    versionFile = "cle/__init__.py";
    pythonImportsCheck = [ "cle" ];
  };

  angr = mkComponent {
    pname = "angr";
    versionFile = "angr/__init__.py";

    # native/angr is a pyo3 cdylib built through setuptools-rust. The lock
    # file lists git dependencies (angr/icicle-emu); allowBuiltinFetchGit
    # fetches them by revision at evaluation time so no hashes are kept here.
    cargoDeps = pkgs.rustPlatform.importCargoLock {
      lockFile = builtins.path {
        path = src + "/angr/Cargo.lock";
        name = "angr-Cargo.lock";
      };
      allowBuiltinFetchGit = true;
    };
    nativeBuildInputs = [
      pkgs.rustPlatform.cargoSetupHook
      pkgs.cargo
      pkgs.rustc
    ];

    optional-dependencies = {
      angrdb = [ python-final.sqlalchemy ];
      keystone = [ python-final.keystone-engine ];
      unicorn = [ python-final.unicorn ];
      llm = [
        python-final.pydantic-ai
        python-final.mcp
        python-final.fastmcp
      ];
    };

    pythonImportsCheck = [
      "angr"
      "angr.rustylib"
      "angr.ailment"
    ];
  };

  angr-management = mkComponent {
    pname = "angr-management";
    versionFile = "angrmanagement/__init__.py";

    # `angr[angrDB]` in the dependency list resolves to plain `angr` here (the
    # extra is dropped with the name), so angrDB's SQLAlchemy is added back.
    extraDependencies = [ python-final.sqlalchemy ];
    # See pyqodeng above: "PySide6-Essentials" is a distribution nixpkgs does
    # not have, satisfied in substance by `pyside6`, which the alias table maps
    # the requirement onto.
    extraRemoveDeps = [ "PySide6-Essentials" ];

    # As nixpkgs' own angr-management does: PySide6 carries its own Qt
    # wiring, so no wrapQtAppsHook, and the one library Qt's xcb platform
    # plugin needs that PySide6 does not bring is added here.
    buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.libxcb-cursor ];

    # Importing angrmanagement instantiates Qt, and a builder has no display.
    pythonImportsCheck = [ "angrmanagement" ];
    env.QT_QPA_PLATFORM = "offscreen";

    meta.mainProgram = "angr-management";
  };
}
