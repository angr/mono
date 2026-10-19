# Additional distributions used by mono's tests and downstream tools.
{ pkgs, sources }:
python-final: python-prev:
let
  inherit (pkgs) lib;
  inherit (python-final) buildPythonPackage;
  system = pkgs.stdenv.hostPlatform.system;
  versionFrom =
    file: import ./version.nix (builtins.dirOf file) (builtins.baseNameOf file) "__version__";
in
{
  backrefs = python-prev.backrefs.overridePythonAttrs (old: {
    disabledTests = (old.disabledTests or [ ]) ++ [ "test_timeout" ];
  });

  # test_shared_processes times out waiting for worker file locks on loaded
  # runners.
  portalocker = python-prev.portalocker.overridePythonAttrs (old: {
    disabledTests = (old.disabledTests or [ ]) ++ [ "test_shared_processes" ];
  });

  # test_same_millisecond_overflow assumes the frozen clock and the ULID
  # provider agree on the current millisecond.
  python-ulid = python-prev.python-ulid.overridePythonAttrs (old: {
    disabledTests = (old.disabledTests or [ ]) ++ [ "test_same_millisecond_overflow" ];
  });

  # The completion tests run interactive shells with a five-second prompt
  # timeout. The directory shares this timing constraint, so skip it together.
  cyclopts = python-prev.cyclopts.overridePythonAttrs (old: {
    disabledTestPaths = (old.disabledTestPaths or [ ]) ++ [ "tests/completion" ];
  });

  # Prebuilt PDB reader; its sdist downloads outside the Nix sandbox.
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
          or (throw "pyxdia ${version}: no wheel hash recorded for ${system} in nix/extra-packages.nix");
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

  shellphish-qemu = buildPythonPackage {
    pname = "shellphish-qemu";
    version = "0.12.4";
    format = "wheel";
    src = pkgs.fetchurl {
      url = "https://files.pythonhosted.org/packages/53/9a/382b5114da9a2967e5be6c5689f75bb89c4957e73ff1468653c633e77000/shellphish_qemu-0.12.4-py3-none-manylinux2010_x86_64.whl";
      hash = "sha256-X9CqsQrA5CS+2Qfh7zptby4GiojpGzqKGesv96Pu4gI=";
    };
    nativeBuildInputs = [ pkgs.autoPatchelfHook ];
    buildInputs = [
      pkgs.stdenv.cc.cc.lib
      pkgs.glib
    ];
    # The wheel declares ninja, which is its *build* tool -- it ships the
    # QEMU binaries already compiled and nothing at run time invokes it.
    # Providing it is worse than dropping it: the nixpkgs python ninja
    # carries a setup hook that then tries to build this wheel with ninja.
    pythonRemoveDeps = [ "ninja" ];
    doCheck = false;
    pythonImportsCheck = [ "shellphish_qemu" ];
    meta = {
      description = "Prebuilt QEMU tracers used by tracer";
      homepage = "https://pypi.org/project/shellphish-qemu/";
      license = lib.licenses.gpl2Plus;
    };
  };

  tracer = buildPythonPackage {
    pname = "tracer";
    version = "0.1";
    format = "setuptools";
    src = builtins.path {
      path = sources.tracer;
      name = "tracer-source";
    };
    dependencies = [
      python-final.shellphish-qemu
      python-final.angr
    ];
    doCheck = false;
    pythonImportsCheck = [ "tracer" ];
    meta = {
      description = "Symbolically trace concrete inputs";
      homepage = "https://angr.io/";
      license = lib.licenses.bsd2;
    };
  };

  # The dependent tools are included in mono's test environment.
  angr-platforms = buildPythonPackage {
    pname = "angr-platforms";
    version = "0.1";
    format = "setuptools";
    src = builtins.path {
      path = sources.angr-platforms;
      name = "angr-platforms-source";
    };
    dependencies = [
      python-final.angr
      python-final.cle
      python-final.archinfo
      python-final.pyvex
    ];
    doCheck = false;
    pythonImportsCheck = [ "angr_platforms" ];
    meta = {
      description = "Extra architectures and loaders for angr";
      homepage = "https://angr.io/";
      license = lib.licenses.bsd2;
    };
  };

  angrop = buildPythonPackage {
    pname = "angrop";
    version = versionFrom (sources.angrop + "/angrop/__init__.py");
    format = "setuptools";
    src = builtins.path {
      path = sources.angrop;
      name = "angrop-source";
    };
    dependencies = [
      python-final.angr
      python-final.tqdm
    ];
    doCheck = false;
    pythonImportsCheck = [ "angrop" ];
    meta = {
      description = "ROP chain builder built on angr";
      homepage = "https://angr.io/";
      license = lib.licenses.bsd2;
    };
  };

}
