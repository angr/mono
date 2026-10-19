# The four compiled artifacts angr's runtime needs, each in its own derivation.
#
#   libpyvex.so           pyvex's C library and the vendored libVEX
#   unicornlib.so         angr's unicorn engine glue, linked against libpyvex
#   rustylib.abi3.so      angr's Rust extension (clarirs, icicle), linked against libz3
#   pypcode_native*.so    pypcode's nanobind extension, plus the sleigh compiler
#
# Each source filter keeps the artifact's build inputs so unrelated Python
# edits can reuse the native output. Package versions still affect derivation
# identities, and pypcode's version file is also a C++ input.
#
# `pypcode-sla` separately compiles the processor specifications with sleigh.
{
  pkgs,
  sources,
  python,
  z3-solver,
}:

let
  inherit (pkgs) lib;
  inherit (import ./subtree.nix lib) subtree;

  angrSrc = sources.angr;
  pyvexSrc = sources.pyvex;
  pypcodeSrc = sources.pypcode;

  versionOf = import ./version.nix;
  checkPins = (import ./check-pins.nix lib).source;

  angrVersion = versionOf angrSrc "angr/__init__.py" "__version__";
  pyvexVersion = versionOf pyvexSrc "pyvex/__init__.py" "__version__";
  pypcodeVersion = versionOf pypcodeSrc "pypcode/__version__.py" "__version__";

  sharedLibraryExtension = pkgs.stdenv.hostPlatform.extensions.sharedLibrary;
  pyvexLibrary = "libpyvex${sharedLibraryExtension}";
  unicornLibrary = "unicornlib${sharedLibraryExtension}";

  z3LibraryDir = "${z3-solver}/${python.sitePackages}/z3/lib";
in
rec {

  # --------------------------------------------------------------- libpyvex --
  #
  # CMake builds libVEX as a static library, links libpyvex.so against it,
  # generates vex/pub/libvex_guest_offsets.h with a host tool, copies the
  # public headers into pyvex/include, and runs make_ffi.py to emit
  # pyvex/vex_ffi.py.
  #
  # vex_ffi.py is a Python file and still belongs here: make_ffi.py derives it
  # from the C headers, so it is an output of the native build, not an input to
  # it. The Python derivation copies it in from this store path.
  pyvex-native = pkgs.stdenv.mkDerivation {
    pname = "pyvex-native";
    version = pyvexVersion;

    src = subtree pyvexSrc "pyvex-native-src" [
      "CMakeLists.txt"
      "pyvex_c"
      "vex"
      "make_ffi.py"
    ];

    nativeBuildInputs = [
      pkgs.cmake
      pkgs.ninja
      python
    ];

    # The custom commands write generated headers and vex_ffi.py back into the
    # source tree, and include_directories names pyvex/include, so those
    # directories have to exist. The unpacked source is a writable copy of the
    # store path, which is why this is safe here and would not be in a checkout.
    postPatch = ''
      mkdir -p pyvex/include pyvex/lib
    '';

    cmakeFlags = [
      "-DCMAKE_INSTALL_PREFIX=${placeholder "out"}"
      # CMakeLists references ${Python3_EXECUTABLE} with no find_package(Python3).
      # Under scikit-build-core that variable happens to be set; standalone it
      # expands to nothing, cmake execs make_ffi.py through /bin/sh, and the
      # build dies on `make_ffi.py: 10: Syntax error: "(" unexpected`.
      "-DPython3_EXECUTABLE=${python.withPackages (ps: [ ps.cffi ])}/bin/python3"
    ];

    postInstall = ''
      mkdir -p $out/lib $out/include
      mv $out/pyvex/lib/* $out/lib/
      mv $out/pyvex/vex_ffi.py $out/
      rm -rf $out/pyvex
      # cmake only *installs* libvex_guest_offsets.h. The rest of the public
      # header set is put in <source>/pyvex/include by the copy_headers custom
      # target, which has no install() rule, so take it from there -- unicornlib
      # fails on `libvex.h: No such file` otherwise. This runs in the cmake
      # build directory, one below the source root.
      cp -r ../pyvex/include/. $out/include/
    '';

    passthru.libraryFile = pyvexLibrary;
  };

  # ----------------------------------------------------------- unicornlib.so --
  #
  # angr/setup.py runs `make` in native/unicornlib with PYVEX_INCLUDE_PATH and
  # PYVEX_LIB_PATH pointing at the installed pyvex package. Here the same make
  # runs on its own against the pyvex-native store path.
  unicornlib = pkgs.stdenv.mkDerivation {
    pname = "angr-unicornlib";
    version = angrVersion;

    src = subtree angrSrc "angr-unicornlib-src" [ "native/unicornlib" ];
    sourceRoot = "angr-unicornlib-src/native/unicornlib";

    PYVEX_INCLUDE_PATH = "${pyvex-native}/include";
    PYVEX_LIB_PATH = "${pyvex-native}/lib";

    buildInputs = [ pyvex-native ];
    nativeBuildInputs = lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.patchelf ];

    # The Makefile links -lpyvex out of PYVEX_LIB_PATH and writes no RPATH, so
    # the consumer would need LD_LIBRARY_PATH from whatever shell started it.
    # That is exactly the dependency this conversion is getting rid of: bake the
    # store path in.
    postBuild = lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
      patchelf --set-rpath "${pyvex-native}/lib" unicornlib.so
    '';

    installPhase = ''
      runHook preInstall
      mkdir -p $out/lib
      cp ${unicornLibrary} $out/lib/
      runHook postInstall
    '';

    passthru.libraryFile = unicornLibrary;
  };

  # ------------------------------------------------------- rustylib.abi3.so --
  #
  # setuptools-rust builds the angr.rustylib cdylib from the cargo workspace at
  # the checkout root. Here cargo runs directly, on a source tree filtered down
  # to the workspace manifests and the crates they name.
  #
  # cargoLock.lockFile keys the vendored dependencies to the selected Cargo.lock.
  # A separately maintained fixed-output hash could reuse another lockfile's
  # vendor output when the name and declared hash agree.
  rustylib =
    let
      src =
        assert checkPins "angr" angrSrc { z3-solver = z3-solver.version; };
        subtree angrSrc "angr-rustylib-src" [
          "Cargo.toml"
          "Cargo.lock"
          "native/angr"
          "native/clarirs-core"
          "native/clarirs-num"
          "native/clarirs-vsa"
          "native/clarirs-z3"
        ];
    in
    pkgs.rustPlatform.buildRustPackage {
      pname = "angr-rustylib";
      version = angrVersion;

      inherit src;

      cargoLock = {
        lockFile = src + "/Cargo.lock";
        # native/angr depends on three crates from the icicle-emu repository by
        # git revision. Letting builtins.fetchGit take them keeps the whole
        # vendor step keyed on Cargo.lock instead of on a hash we maintain.
        allowBuiltinFetchGit = true;
      };

      nativeBuildInputs = [ python ] ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.patchelf ];

      # pyo3's abi3-py312 does not link libpython, but the build script still
      # reads the ABI configuration out of an interpreter.
      PYO3_PYTHON = "${python}/bin/python3";

      # What angr/setup.py's configure_z3() does. z3-sys probes pkg-config
      # before honouring the override, and a system-wide Z3 of another version
      # would win -- the bindings are tied to one Z3 release.
      Z3_NO_PKG_CONFIG = "1";
      Z3_LIBRARY_PATH_OVERRIDE = z3LibraryDir;

      doCheck = false;

      # The cdylib installs as librustylib.so. Python imports it as
      # angr.rustylib, so it needs an extension-module suffix; `.abi3.so` is in
      # importlib.machinery.EXTENSION_SUFFIXES and says what the build is.
      #
      # z3-sys emits a link search path but no rpath, so upstream relies on
      # angr/_z3.py having already ctypes-loaded libz3 by the time the
      # extension is imported. Set the rpath instead and the extension resolves
      # on its own.
      postInstall = ''
        mkdir -p $out/lib
        if [ -f $out/lib/librustylib${sharedLibraryExtension} ]; then
          mv $out/lib/librustylib${sharedLibraryExtension} $out/lib/rustylib.abi3.so
        fi
      ''
      + lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
        patchelf --set-rpath "${z3LibraryDir}:$(patchelf --print-rpath $out/lib/rustylib.abi3.so)" \
          $out/lib/rustylib.abi3.so
      '';

      passthru.libraryFile = "rustylib.abi3.so";
    };

  # ------------------------------------------------------- pypcode_native.so --
  #
  # pypcode's setup.py drives cmake, which builds the nanobind extension and the
  # sleigh compiler.
  pypcode-native = pkgs.stdenv.mkDerivation {
    pname = "pypcode-native";
    version = pypcodeVersion;

    src = subtree pypcodeSrc "pypcode-native-src" [
      "CMakeLists.txt"
      "pypcode/pypcode_native.cpp"
      # Not a mistake. pypcode_native.cpp does `#include "__version__.py"`
      # literally, so that Python file really is a native build input and a
      # version bump really does rebuild the extension.
      "pypcode/__version__.py"
      "pypcode/sleigh"
      "pypcode/zlib"
      "pypcode/thirdparty"
    ];

    nativeBuildInputs = [
      pkgs.cmake
      pkgs.ninja
      python
      python.pkgs.nanobind
    ];

    buildInputs = [ python ];

    cmakeFlags = [
      "-DCMAKE_INSTALL_PREFIX=${placeholder "out"}"
      "-DPython_EXECUTABLE=${python}/bin/python3"
    ];

    postInstall = ''
      mkdir -p $out/lib
      mv $out/pypcode_native*.so $out/lib/
    '';

    passthru.libraryFile = "pypcode_native.so";
  };

  # ------------------------------------------------------------- .sla files --
  #
  # `sleigh -a` compiles each processor's .slaspec into a .sla. The result is
  # 30 MB of data that the pypcode package loads at run time, and its only
  # inputs are the specifications and the compiler -- so it sits with the native
  # artifacts and not in the Python derivation, where every docstring change
  # would recompile it.
  pypcode-sla = pkgs.stdenv.mkDerivation {
    pname = "pypcode-sla";
    version = pypcodeVersion;

    src = subtree pypcodeSrc "pypcode-sla-src" [ "pypcode/processors" ];

    nativeBuildInputs = [ pypcode-native ];

    buildPhase = ''
      runHook preBuild
      mkdir -p $out
      cp -r pypcode/processors $out/processors
      chmod -R u+w $out/processors
      sleigh -a $out/processors
      runHook postBuild
    '';

    dontInstall = true;
  };
}
