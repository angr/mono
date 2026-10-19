# Shared Python recipes; native outputs come from native.nix.
{
  pkgs,
  sources,
  python,
  natives,
  z3-solver,
  resources,
  angrDataSrc ? null,
  withPyxdia ? true,
}:

let
  inherit (pkgs) lib;
  inherit (import ./subtree.nix lib) subtreeExcept;
  versionOf = import ./version.nix;
  checkPins = (import ./check-pins.nix lib).source;

  # A source collection fixes each sibling already; relax only those pins.
  unselectable = {
    angr = [
      "angr-data"
      "archinfo"
      "claripy"
      "cle"
      "pyvex"
      "z3-solver"
    ];
    angr-management = [
      "angr"
      "cle"
    ];
    cle = [
      "archinfo"
      "pyvex"
    ];
  };

  # Before angr/angr#6550 the solver was a separate distribution.
  claripySource =
    sources.claripy or (pkgs.fetchFromGitHub {
      owner = "angr";
      repo = "claripy";
      rev = "0a2d0c6f3b619f358c9ee2f10e97b26a6290c416";
      hash = "sha256-jjSD4NRmibU5adalfq9u9o7TfGy0Eib/r/hat7M7JO8=";
    });

  angrDeclaresClaripy =
    let
      pyproject = builtins.fromTOML (builtins.readFile (sources.angr + "/pyproject.toml"));
    in
    builtins.any (dep: builtins.match "claripy([^A-Za-z0-9_.-].*)?" dep != null) (
      pyproject.project.dependencies or [ ]
    );
in
self: super: {

  inherit z3-solver;

  monoPinned.z3-solver = z3-solver;

  # ------------------------------------------------------------ archinfo --
  #
  # Pure Python, no native part, nothing to split.
  archinfo = self.buildPythonPackage {
    pname = "archinfo";
    version = versionOf sources.archinfo "archinfo/__init__.py" "__version__";
    pyproject = true;

    src = subtreeExcept sources.archinfo "archinfo-src" [
      "tests"
      ".github"
    ];

    build-system = [ self.setuptools ];

    doCheck = false;
    pythonImportsCheck = [ "archinfo" ];

    meta = {
      description = "Classes with architecture-specific information useful to binary analysis";
      homepage = "https://github.com/angr/archinfo";
      license = lib.licenses.bsd2;
    };
  };

  # --------------------------------------------------------------- pyvex --
  #
  # scikit-build-core normally compiles libVEX and libpyvex through CMake.
  # Use setuptools to package the artifacts supplied by pyvex-native.
  pyvex = self.buildPythonPackage {
    pname = "pyvex";
    version = versionOf sources.pyvex "pyvex/__init__.py" "__version__";
    pyproject = true;

    src = subtreeExcept sources.pyvex "pyvex-python-src" [
      "vex"
      "pyvex_c"
      "CMakeLists.txt"
      "make_ffi.py"
      "fuzzing"
      "tests"
      ".github"
    ];

    build-system = [
      self.setuptools
      self.cffi
    ];
    nativeBuildInputs = [
      self.packaging
      self.tomlkit
    ];

    postPatch = ''
      python3 -P ${./pyvex_build_system.py}

      # pyvex/native.py dlopens importlib.resources.files("pyvex") / "lib", so
      # the library has to sit inside the package. vex_ffi.py is generated from
      # the C headers by make_ffi.py, which makes it an output of the native
      # build rather than a source file.
      mkdir -p pyvex/lib pyvex/include
      cp ${natives.pyvex-native}/lib/${natives.pyvex-native.libraryFile} pyvex/lib/
      cp -r ${natives.pyvex-native}/include/. pyvex/include/
      cp ${natives.pyvex-native}/vex_ffi.py pyvex/
      chmod -R u+w pyvex/lib pyvex/include pyvex/vex_ffi.py
    '';

    dependencies = [
      self.bitstring
      self.cffi
    ];

    doCheck = false;
    pythonImportsCheck = [ "pyvex" ];

    meta = {
      description = "Python interface to libVEX and VEX IR";
      homepage = "https://github.com/angr/pyvex";
      license = with lib.licenses; [
        bsd2
        gpl2Only
      ];
    };
  };

  # ------------------------------------------------------------- pypcode --
  #
  # setup.py's build_ext runs CMake and sleigh. Package the outputs from
  # pypcode-native and pypcode-sla with build_ext disabled.
  pypcode = self.buildPythonPackage {
    pname = "pypcode";
    version = versionOf sources.pypcode "pypcode/__version__.py" "__version__";
    pyproject = true;

    src = subtreeExcept sources.pypcode "pypcode-python-src" [
      "CMakeLists.txt"
      "pypcode/pypcode_native.cpp"
      "pypcode/sleigh"
      "pypcode/zlib"
      "pypcode/thirdparty"
      "pypcode/processors"
      "tests"
      "build"
      ".github"
    ];

    build-system = [
      self.setuptools
      self.nanobind
    ];

    postPatch = ''
      python3 - <<'PATCH'
      import pathlib
      p = pathlib.Path("setup.py")
      s = p.read_text()
      old = '    def run(self):\n        try:\n            subprocess.check_output(["cmake", "--version"])\n'
      assert old in s, "pypcode's BuildExtension.run is not where this patch expects it"
      new = '    def run(self):\n        return\n\n    def _upstream_run(self):\n        try:\n            subprocess.check_output(["cmake", "--version"])\n'
      p.write_text(s.replace(old, new, 1))

      # cmake is a declared build dependency only because build_ext drove it,
      # and the no-isolation build refuses to start without it on the path.
      t = pathlib.Path("pyproject.toml")
      s = t.read_text()
      req = 'requires = [ "setuptools", "nanobind", "cmake" ]'
      assert req in s, "pypcode's build-system requires moved"
      t.write_text(s.replace(req, 'requires = [ "setuptools", "nanobind" ]'))

      # With build_ext a no-op, setuptools no longer produces the extension and
      # so does not put it in the wheel either. Ship it as package data.
      s = p.read_text()
      data = '["py.typed", "pypcode_native.pyi"]'
      assert data in s, "pypcode's package_data list moved"
      p.write_text(s.replace(data, '["py.typed", "pypcode_native.pyi", "pypcode_native*.so"]'))
      PATCH

      cp ${natives.pypcode-native}/lib/pypcode_native*.so pypcode/
      mkdir -p pypcode/bin
      cp ${natives.pypcode-native}/bin/sleigh pypcode/bin/
      cp -r ${natives.pypcode-sla}/processors pypcode/processors
      chmod -R u+w pypcode/bin pypcode/processors pypcode/pypcode_native*.so
    '';

    doCheck = false;
    pythonImportsCheck = [ "pypcode" ];

    meta = {
      description = "Machine code disassembly and IR translation library";
      homepage = "https://github.com/angr/pypcode";
      license = lib.licenses.bsd2;
    };
  };

  # ----------------------------------------------------------------- cle --
  cle = self.buildPythonPackage {
    pname = "cle";
    version = versionOf sources.cle "cle/__init__.py" "__version__";
    pyproject = true;

    src = subtreeExcept sources.cle "cle-src" [
      "tests"
      ".github"
    ];

    build-system = [ self.setuptools ];

    # Mono includes PDB support by default. Consumers can select pyxdia only
    # for their test or analysis environments through withPyxdia = false.
    pythonRemoveDeps = lib.optional (!withPyxdia) "pyxdia";
    # Upstream pins arpy==1.1.1; nixpkgs carries 2.3.0. archinfo and pyvex are
    # `unselectable` above.
    pythonRelaxDeps = [ "arpy" ] ++ unselectable.cle;

    dependencies =
      assert checkPins "cle" sources.cle { pyelftools = self.monoPinned.pyelftools.version; };
      [
        self.archinfo
        self.arpy
        self.cart
        self.minidump
        self.pefile
        self.monoPinned.pyelftools
        self.pyvex
        self.pyxbe
        self.sortedcontainers
        self.uefi-firmware
      ]
      ++ lib.optional withPyxdia self.pyxdia;

    doCheck = false;
    pythonImportsCheck = [ "cle" ];

    meta = {
      description = "Python loader for many binary formats";
      homepage = "https://github.com/angr/cle";
      license = lib.licenses.bsd2;
    };
  };

  # ------------------------------------------------------------- claripy --
  #
  # Older angr snapshots declare the standalone solver. Use sources.claripy
  # when supplied; otherwise use the fallback at 0a2d0c6f (9.3.5.dev0).
  # That fallback includes b6f45428's cloned-solver constraint fix, which angr
  # snapshots from before 2026-08-30 were not tested against upstream.
  #
  # The fallback pins z3-solver==4.13.0.0. Relax that pin to the single Z3
  # package also used by angr's Rust extension.
  claripy = self.buildPythonPackage {
    pname = "claripy";
    version = versionOf claripySource "claripy/__init__.py" "__version__";
    pyproject = true;
    src = claripySource;

    build-system = [ self.setuptools ];

    pythonRelaxDeps = [ "z3-solver" ];

    dependencies =
      assert checkPins "claripy" claripySource { z3-solver = z3-solver.version; };
      [
        self.cachetools
        self.z3-solver
      ];

    doCheck = false;
    pythonImportsCheck = [ "claripy" ];

    meta = {
      description = "An abstraction layer for constraint solvers";
      homepage = "https://github.com/angr/claripy";
      license = lib.licenses.bsd2;
    };
  };

  # ---------------------------------------------------------------- angr --
  angr = self.buildPythonPackage {
    pname = "angr";
    version = versionOf sources.angr "angr/__init__.py" "__version__";
    pyproject = true;

    # Keep native sources and Cargo manifests out of the Python source tree.
    src = subtreeExcept sources.angr "angr-python-src" [
      "native"
      "Cargo.toml"
      "Cargo.lock"
      "tests"
      ".github"
    ];

    build-system = [
      self.setuptools
      self.grpcio-tools
      self.protobuf
    ];

    postPatch = ''
      python3 - <<'PATCH'
      import pathlib

      import re

      toml = pathlib.Path("pyproject.toml")
      s = toml.read_text()

      # setuptools-rust, pyvex and z3-solver are build requirements only because
      # setup.py built the Rust extension and the unicorn glue here. It does not
      # any more, and pypa/build --no-isolation refuses to start on a build
      # requirement it cannot find. Scoped to the first requires list, which is
      # the [build-system] one -- pyvex and z3-solver are runtime dependencies
      # too and those must stay.
      head = s.index('requires = [')
      tail = s.index(']', head)
      block = s[head:tail]
      block = re.sub(r'\n\s*"setuptools-rust[^"]*",', "", block)
      block = re.sub(r'\n\s*"pyvex[^"]*",', "", block)
      block = re.sub(r'\n\s*"z3-solver[^"]*",', "", block)
      assert 'setuptools-rust' not in block, "angr's build-system requires moved"
      s = s[:head] + block + s[tail:]

      # setuptools-rust builds angr.rustylib out of the cargo workspace, and the
      # workspace is not in this source tree. Adding nixpkgs' setuptools-rust is
      # not an option either: its setup hook aborts unless cargoSetupHook is
      # present too, which would drag the whole cargo build back in -- the
      # opposite of the point.
      ext = '[[tool.setuptools-rust.ext-modules]]\ntarget = "angr.rustylib"\npath = "native/angr/Cargo.toml"\ndebug = false\n'
      assert ext in s, "angr's setuptools-rust ext-modules table moved"
      s = s.replace(ext, "")

      # Upstream pins grpcio-tools ~=1.80 and protobuf <7 so the gencode stamp
      # protoc writes into angr/protos/*_pb2.py stays on the 6.x major and the
      # runtime protobuf can always load it. nixpkgs is a major ahead on both
      # halves in step -- its grpcio-tools depends on the protobuf angr will
      # import at run time -- so the invariant still holds one major up. The
      # angr.protos.cfg_pb2 import check below is what verifies that.
      s = s.replace('"grpcio-tools~=1.80.0",', '"grpcio-tools",')
      s = s.replace('"protobuf>=6.31.1,<7",', '"protobuf",')
      toml.write_text(s)

      setup = pathlib.Path("setup.py")
      s = setup.read_text()

      # Before angr/angr#6550 setup.py only checked that setuptools_rust could
      # be imported. From #6550 on it imports it and registers a build_rust
      # command that points the Rust build at z3. Either shape is removed; any
      # other fails here.
      guard = 'try:\n    _ = importlib.import_module("setuptools_rust")\nexcept ImportError as err:\n    raise Exception("angr requires setuptools-rust to build") from err\n'
      imp = 'import setuptools_rust\n'
      if guard in s:
          s = s.replace(guard, "")
      else:
          assert imp in s, "angr's setup.py neither imports setuptools_rust nor checks for it"
          s = s.replace(imp, "")

          cls = 'class build_rust(setuptools_rust.build_rust):\n    def run(self):\n        configure_z3()\n        super().run()\n\n\n'
          assert cls in s, "angr's build_rust command moved"
          s = s.replace(cls, "")

          reg = '    "build_rust": build_rust,\n'
          assert reg in s, "angr's cmdclass no longer registers build_rust"
          s = s.replace(reg, "")

      # The unicorn glue and the Rust extension are already built. Replace the
      # step that builds them with a copy from their store paths, and keep the
      # original body under another name so this patch fails loudly if upstream
      # rewrites it.
      fn = 'def build_unicornlib():\n'
      assert fn in s, "angr's build_unicornlib moved"
      new = 'def build_unicornlib():\n    shutil.copy(os.environ["ANGR_UNICORNLIB"], "angr/" + library_file)\n    shutil.copy(os.environ["ANGR_RUSTYLIB"], "angr/rustylib.abi3.so")\n\n\ndef _upstream_build_unicornlib():\n'
      s = s.replace(fn, new, 1)
      setup.write_text(s)
      PATCH
    '';

    ANGR_UNICORNLIB = "${natives.unicornlib}/lib/${natives.unicornlib.libraryFile}";
    ANGR_RUSTYLIB = "${natives.rustylib}/lib/rustylib.abi3.so";

    # lmdb is pinned ==2.1.1 against nixpkgs' 2.3.0, and pypcode ~=4.0 against
    # a dev version of 4.0.1. Neither is an API floor angr needs.
    pythonRelaxDeps = [
      "lmdb"
      "pypcode"
    ]
    ++ unselectable.angr;

    dependencies =
      assert checkPins "angr" sources.angr { z3-solver = z3-solver.version; };
      [
        self.angr-data
        self.archinfo
        self.cachetools
        self.capstone
        self.cffi
        self.cle
        self.cxxheaderparser
        self.gitpython
        self.lmdb
        self.msgspec
        self.mulpyplexer
        self.networkx
        self.platformdirs
        self.protobuf
        self.psutil
        self.pycparser
        self.pydemumble
        self.pypcode
        self.pyvex
        self.rich
        self.sortedcontainers
        self.sympy
        self.typing-extensions
        self.z3-solver
      ]
      ++ lib.optional angrDeclaresClaripy self.claripy;

    # pyproject.toml's extras, in nixpkgs names. `llm` names pydantic-ai;
    # pydantic-ai-slim is the same package without its optional providers,
    # which is all tests/llm and tests/mcp use.
    optional-dependencies = {
      angrdb = [ self.sqlalchemy ];
      keystone = [ self.keystone-engine ];
      telemetry = [ self.opentelemetry-api ];
      llm = [
        self.pydantic-ai-slim
        self.mcp
        self.fastmcp
      ];
      unicorn = [ self.unicorn ];
    };

    doCheck = false;
    # angr.protos.cfg_pb2 is generated during the build, so importing it proves
    # the generated code and the runtime protobuf agree -- a stamp/runtime
    # mismatch raises at import. angr.claripy is the solver that used to be its
    # own distribution; importing it proves rustylib loaded and found libz3.
    # An angr from before angr/angr#6550 imports the `claripy` distribution
    # instead.
    pythonImportsCheck = [
      "angr"
      "angr.protos.cfg_pb2"
      (if angrDeclaresClaripy then "claripy" else "angr.claripy")
    ];

    meta = {
      description = "A multi-architecture binary analysis toolkit";
      homepage = "https://angr.io/";
      license = lib.licenses.bsd2;
    };
  };

  # ----------------------------------- dependencies pinned past nixpkgs --

  # angr uses MemberPointer, introduced in cxxheaderparser 2.0.0. The pinned
  # nixpkgs still carries 1.9.2, which makes importing current angr fail.
  cxxheaderparser = self.buildPythonPackage rec {
    pname = "cxxheaderparser";
    version = "2.0.0";
    pyproject = true;

    src = self.fetchPypi {
      pname = "cxxheaderparser";
      version = "2.0.0";
      hash = "sha256-Ypj0D87fijp9vsZ5xOiGhvJPNO21vcH9ymXBgCpCBas=";
    };

    postInstall = ''
      cp cxxheaderparser/version.py "$out/${python.sitePackages}/cxxheaderparser/version.py"
    '';

    build-system = [
      self.hatchling
      self.hatch-vcs
    ];

    doCheck = false;
    pythonImportsCheck = [ "cxxheaderparser.types" ];

    meta = {
      description = "Modern pure Python C++ header parser";
      homepage = "https://github.com/robotpy/cxxheaderparser";
      license = lib.licenses.bsd3;
    };
  };

  # Keep this pin local to family packages. Overriding the shared pyelftools
  # attribute also changes auto-patchelf and its toolchain dependencies.
  monoPinned.pyelftools = self.buildPythonPackage {
    pname = "pyelftools";
    version = "0.33";
    pyproject = true;

    src = self.fetchPypi {
      pname = "pyelftools";
      version = "0.33";
      hash = "sha256-Zg2C3L646D0XAr2X8iP3YWJdoGERwMyYjqxrirDBth8=";
    };

    build-system = [ self.setuptools ];

    doCheck = false;
    pythonImportsCheck = [
      "elftools"
      "elftools.elf.elffile"
      "elftools.elf.dynamic"
    ];

    meta = {
      description = "Library for analyzing ELF files and DWARF debugging information";
      homepage = "https://github.com/eliben/pyelftools";
      license = lib.licenses.publicDomain;
    };
  };

  # ------------------------------------------- dependencies nixpkgs lacks --

  # angr's function and type prototype definitions, split out of the angr
  # release so they do not bloat it. Data plus a PyInstaller hook.
  #
  # angrDataSrc selects an explicit snapshot; otherwise use the PyPI release
  # below. Older angr snapshots require ~=0.1.1, so the requirement is relaxed
  # to the selected data package.
  angr-data = self.buildPythonPackage {
    pname = "angr_data";
    version =
      if angrDataSrc == null then
        "0.2.0"
      else
        versionOf angrDataSrc "angr_data/__init__.py" "__version__";
    pyproject = true;

    src =
      if angrDataSrc != null then
        angrDataSrc
      else
        self.fetchPypi {
          pname = "angr_data";
          version = "0.2.0";
          hash = "sha256-kKl4y0UlRLS4ssgsZbepSWnuxOELWiR0XMnjH4pLtxo=";
        };

    build-system = [ self.setuptools ];
    pythonImportsCheck = [ "angr_data" ];

    meta = {
      description = "Function and type prototype definitions for angr";
      homepage = "https://github.com/angr/angr-data";
      license = lib.licenses.bsd2;
    };
  };

  # cle's UEFI firmware backend.
  uefi-firmware = self.buildPythonPackage {
    pname = "uefi_firmware";
    version = "1.16";
    pyproject = true;

    src = self.fetchPypi {
      pname = "uefi_firmware";
      version = "1.16";
      hash = "sha256-Fia5kwsQBvnsELde+In/wXxjLgtDpKugehCQ2QIxM+o=";
    };

    build-system = [
      self.setuptools
      self.setuptools-scm
    ];

    dependencies = [ self.future ];
    pythonImportsCheck = [ "uefi_firmware" ];

    meta = {
      description = "Parser for UEFI firmware volumes, capsules and PE32+ images";
      homepage = "https://github.com/theopolis/uefi-firmware-parser";
      license = lib.licenses.bsd3;
    };
  };

  # ----------------------------------------------------- angr-management --
  #
  # The GUI uses shared FLIRT signatures and library documentation selected
  # by resources.nix. Its Python source excludes those resource trees.

  # PyPI sdist, pure Python; the only angr-management dependency nixpkgs
  # lacks. Requires-Dist names PySide6-Essentials, which nixpkgs calls pyside6.
  pyqodeng = self.buildPythonPackage {
    pname = "pyqodeng";
    version = "0.0.14";
    pyproject = true;

    src = self.fetchPypi {
      pname = "pyqodeng";
      version = "0.0.14";
      hash = "sha256-Stdymiqijvtn3T254K4ILKsp6NVdEnl7cSdRP8Ya4eQ=";
    };

    build-system = [ self.setuptools ];
    pythonRemoveDeps = [ "PySide6-Essentials" ];
    dependencies = [
      self.pygments
      self.qtpy
      self.pyside6
    ];

    doCheck = false;
    pythonImportsCheck = [ "pyqodeng.core" ];

    meta = {
      description = "Source code editor widget for PySide (angr's fork of pyqode)";
      homepage = "https://github.com/angr/pyqodeng";
      license = lib.licenses.mit;
    };
  };

  # libbs 3.3.0's tests read pycparser.ply, removed in pycparser 3.00.
  libbs = super.libbs.overridePythonAttrs (_: {
    doCheck = false;
  });

  # nixpkgs' binsync 5.11.0 test collection imports flask, which the
  # derivation does not supply. The one name angr-management imports,
  # binsync.interface_overrides.angr.BinsyncPlugin, is still exported.
  binsync = super.binsync.overridePythonAttrs (_: {
    doCheck = false;
  });

  angr-management = self.buildPythonPackage {
    pname = "angr-management";
    version = versionOf sources.angr-management "angrmanagement/__init__.py" "__version__";
    pyproject = true;

    src = subtreeExcept sources.angr-management "angr-management-src" [
      "angrmanagement/resources/flirt_signatures"
      "angrmanagement/resources/library_docs"
    ];

    postPatch = ''
      substituteInPlace angrmanagement/config/config_manager.py \
        --replace-fail './angrmanagement/resources/flirt_signatures/flirt_signatures/' '${resources.flirt-signatures}/' \
        --replace-fail './angrmanagement/resources/library_docs/' '${resources.library-docs}/'
    '';

    postInstall = ''
      resourceDir="$out/${python.sitePackages}/angrmanagement/resources"
      mkdir -p "$resourceDir"
      ln -s ${resources.flirt-signatures} "$resourceDir/flirt_signatures"
      ln -s ${resources.library-docs} "$resourceDir/library_docs"
    '';

    buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.libxcb-cursor ];

    build-system = [ self.setuptools ];

    # nixpkgs names: PySide6-Essentials is pyside6, PySide6-QtAds is
    # pyside6-qtads. Upstream pins QtAwesome==1.4.0 and binsync==5.7.11;
    # nixpkgs has 1.4.1 and 5.11.0.
    pythonRemoveDeps = [
      "PySide6-Essentials"
      "PySide6-QtAds"
    ];
    pythonRelaxDeps = [
      "QtAwesome"
      "binsync"
    ]
    ++ unselectable.angr-management;

    dependencies = [
      self.pyside6
      self.pyside6-qtads
      self.qtawesome
      self.qtpy
      self.angr
      self.sqlalchemy # angr[angrDB]
      self.bidict
      self.cle
      self.ipython
      self.pyqodeng
      self.requests
      self.pysocks # requests[socks]
      self.tomlkit
      self.thefuzz
      self.rapidfuzz # thefuzz[speedup]
      self.binsync
      self.rpyc
      self.qtconsole
      self.tornado
      self.traitlets
      # The TUI work replaces QStandardPaths with platformdirs, which makes
      # it a plain dependency. It is already in the closure through
      # qtconsole -> jupyter-core; naming it keeps the runtime-deps check
      # passing once pyproject.toml lists it.
      self.platformdirs
      # The Textual frontend (`am-tui`) is a first-class entry point, so
      # textual is a plain dependency; pyproject.toml lists it too.
      self.textual
    ];

    # Image rendering for the TUI is selected by environments using the extra.
    optional-dependencies.tui = [
      self.textual-image
    ];

    doCheck = false;
    # Importing angrmanagement loads PySide6; the sandbox has no display.
    pythonImportsCheck = [ "angrmanagement" ];
    env.QT_QPA_PLATFORM = "offscreen";

    meta = {
      mainProgram = "angr-management";
      description = "The official GUI for angr";
      homepage = "https://github.com/angr/angr-management";
      license = lib.licenses.bsd2;
    };
  };

  # --------------------------------------------------------------- jpype --
  #
  # nixpkgs pins jpype1 1.6.0; pysoot master pins `jpype1==1.7.1` (angr/pysoot#59,
  # merged 2026-09-18), and pythonRuntimeDepsCheckHook fails the pysoot build on the
  # mismatch. The inputs, the dependencies and the disabled check come from nixpkgs.
  #
  # The build backend does not: nixpkgs' recipe is for 1.6.0, which built with
  # setuptools after a preBuild `ant` run. 1.7.1's pyproject.toml declares
  # `build-backend = "scikit_build_core.build"`, and its CMakeLists.txt runs ant
  # for org.jpype.jar and compiles _jpype itself, so with setuptools alone the
  # build stops at "Backend 'scikit_build_core.build' is not available". CMake is
  # driven by scikit-build-core, not by nix's cmake configure phase, and the Java
  # test harness it builds by default is only for upstream's own suite.
  #
  # It matters beyond making the build pass: angr resolves pysoot from `branch =
  # "master"` in its own pyproject, so angr CI runs master against 1.7.1. Building
  # 1.6.0 here would gate a pair nobody runs.
  jpype1 = super.jpype1.overridePythonAttrs (old: rec {
    version = "1.7.1";
    src = pkgs.fetchFromGitHub {
      owner = "originell";
      repo = "jpype";
      tag = "v${version}";
      hash = "sha256-6QKX43XyyBCwOxunQz8lFV1Svh/IXjLtpElbWEx37QQ=";
    };
    build-system = [ self.scikit-build-core ];
    nativeBuildInputs = old.nativeBuildInputs ++ [
      pkgs.cmake
      pkgs.ninja
    ];
    # scikit-build-core drives CMake itself, so nix's own configure phase must
    # not also run -- that is all `dontUseCmakeConfigure` does here.
    #
    # It does NOT make `cmakeFlags` inert, which is the easy thing to assume:
    # nixpkgs' scikit-build-core carries `setupHooks = [ ./append-cmakeFlags.sh ]`,
    # whose `scikitBuildFlagsHook` runs from `preConfigureHooks` and appends every
    # `cmakeFlags` entry to `pypaBuildFlags` as `-Ccmake.args=<flag>`. That has
    # nothing to do with `cmakeConfigurePhase`, so the flags below are live.
    dontUseCmakeConfigure = true;
    # Upstream's Java test harness (BUILD_TEST_HARNESS, CMakeLists.txt:7, ON by
    # default) is an ant and javadoc compile for jpype's own suite; only
    # org.jpype.jar is installed into the wheel, so building it is work thrown
    # away on every rebuild here.
    cmakeFlags = [ "-DBUILD_TEST_HARNESS=OFF" ];
    # 1.7.1's CMakeLists runs ant for org.jpype.jar itself (ENABLE_BUILD_JAR is
    # ON by default), so nixpkgs' 1.6.0 preBuild would run it a second time.
    # The jar is in the output: lib/python3.12/site-packages/org.jpype.jar.
    preBuild = "";
  });

  # -------------------------------------------------------------- pysoot --
  #
  # Retain tests in this source so consumers can enable its check phase.
  # Launchers supply JAVA_HOME; patching pysoot's lookup would break its
  # test that deliberately clears Java from the environment.
  pysoot = self.buildPythonPackage {
    pname = "pysoot";
    version = versionOf sources.pysoot "pyproject.toml" "version";
    pyproject = true;

    src = sources.pysoot;
    pythonRelaxDeps = [ "jpype1" ];

    build-system = [ self.setuptools ];

    dependencies = [
      self.jpype1
      self.frozendict
    ];

    doCheck = false;
    pythonImportsCheck = [
      "pysoot"
      "pysoot.soot_manager"
    ];

    meta = {
      description = "Python bindings for Soot's Shimple and Jimple IR";
      homepage = "https://github.com/angr/pysoot";
      license = lib.licenses.bsd2;
    };
  };

  # ------------------------------------------------------- terminal UI --
  #
  # Skip Textual's own suite when building consumer environments; keep its
  # import check.
  textual = super.textual.overridePythonAttrs (_: {
    doCheck = false;
  });

  # pytest-textual-snapshot 1.1.0 pins syrupy==4.8.0; nixpkgs relaxes that
  # to its syrupy 5.5.3. syrupy 5 renamed the two SingleFileSnapshotExtension
  # members the plugin's SVGImageExtension overrides: `_file_extension` is
  # `file_extension` and `_read_snapshot_data_from_location` is
  # `read_snapshot_data_from_location`. Unpatched, snapshots are written as
  # `.raw` instead of `.svg` and the normalisation on read never runs.
  # syrupy 4.x cannot be taken instead: 4.8.0 and 4.9.1 both require
  # pytest<9, and the set has pytest 9.1.1.
  pytest-textual-snapshot = super.pytest-textual-snapshot.overridePythonAttrs (old: {
    postPatch = (old.postPatch or "") + ''
      substituteInPlace pytest_textual_snapshot.py \
        --replace-fail '_file_extension = "svg"' 'file_extension = "svg"' \
        --replace-fail '_read_snapshot_data_from_location' 'read_snapshot_data_from_location'
    '';
  });

  # ----------------------------------------------------------- llm extra --
  #
  # angr's `llm` extra (tests/llm, tests/mcp) needs pydantic-ai and fastmcp.
  # nixpkgs has both, but two packages in their closures fail their own
  # tests at the pin.

  # inline-snapshot's documentation examples disagree with this nixpkgs
  # formatter version. It is a build dependency of fastmcp's dependency stack.
  inline-snapshot = super.inline-snapshot.overridePythonAttrs (_: {
    doCheck = false;
  });

  # griffelib's check phase pulls mkdocstrings and mkdocs-material, about 36
  # derivations, for a library pydantic-ai only imports.
  griffelib = super.griffelib.overridePythonAttrs (_: {
    doCheck = false;
  });

  # py-key-value-aio's test_put_ttl_get_ttl uses a wall-clock TTL assertion
  # sensitive to runner load. Skip its suite while retaining the import check.
  py-key-value-aio = super.py-key-value-aio.overridePythonAttrs (_: {
    doCheck = false;
  });

  pydantic-ai-slim = super.pydantic-ai-slim.override { inherit (self) griffelib; };

  # ----------------------------------------------------------- type stubs --
  #
  # The two stub packages angr's CI image installs for pyright, from PyPI
  # sdists: nixpkgs has neither at the pin. Pure data, nothing to import.
  sortedcontainers-stubs = self.buildPythonPackage {
    pname = "sortedcontainers-stubs";
    version = "2.4.3";
    pyproject = true;

    src = pkgs.fetchurl {
      url = "https://files.pythonhosted.org/packages/19/13/2940fafc136048ec99c932bf0077613f1ae4693a313705162982335fe5fb/sortedcontainers_stubs-2.4.3.tar.gz";
      hash = "sha256-uhctrO2kvWF9L2/9JFgiYaSU2pJwVAllGWf6pA68dd0=";
    };

    build-system = [ self.poetry-core ];
    # The wheel's metadata names both as runtime requirements.
    dependencies = [
      self.sortedcontainers
      self.typing-extensions
    ];
    doCheck = false;
    pythonImportsCheck = [ ];

    meta = {
      description = "Type stubs for sortedcontainers";
      license = lib.licenses.asl20;
    };
  };

  types-pefile = self.buildPythonPackage {
    pname = "types-pefile";
    version = "2023.2.7.post0";
    pyproject = true;

    src = pkgs.fetchurl {
      url = "https://files.pythonhosted.org/packages/d8/fa/ca3a2a979b7e718da7442e89c59fb519eff745adfb6e87757f472e629bd2/types-pefile-2023.2.7.post0.tar.gz";
      hash = "sha256-oI54fhTR/1O9FcYxig0bVqp2RwVOU042Z5nQ6UaXpjc=";
    };

    build-system = [ self.setuptools ];
    # The sdist requires pefile~=2023.2.7; nixpkgs is newer, and the stubs
    # do not care.
    dependencies = [ self.pefile ];
    pythonRelaxDeps = [ "pefile" ];
    doCheck = false;
    pythonImportsCheck = [ ];

    meta = {
      description = "Type stubs for pefile";
      license = lib.licenses.asl20;
    };
  };
}
