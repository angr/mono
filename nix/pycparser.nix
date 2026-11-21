# pycparser selected from the requirement in the angr source tree.
#
# pycparser 3.12 breaks angr's parser, while historical angr snapshots declare
# the broader ~=3.0 range. Keep their previous package while newer source
# collections select 3.11.
{
  lib,
  pythonPackages,
  previous,
  angrSource,
}:

let
  packages = {
    "3.0.0" = previous;
    "3.11.0" = pythonPackages.buildPythonPackage {
      pname = "pycparser";
      version = "3.11";
      pyproject = true;

      src = pythonPackages.fetchPypi {
        pname = "pycparser";
        version = "3.11";
        hash = "sha256-2HXwnDUH0A4aug7sxtytwTUvMP/wnca/8vHCk16Xwrw=";
      };

      build-system = [ pythonPackages.setuptools ];
      doCheck = false;
      pythonImportsCheck = [ "pycparser" ];

      meta = {
        description = "C parser in Python";
        homepage = "https://github.com/eliben/pycparser";
        license = lib.licenses.bsd3;
      };
    };
  };
  version = (import ./check-pins.nix lib).selectPython {
    component = "angr";
    project = builtins.fromTOML (builtins.readFile (angrSource + "/pyproject.toml"));
    dependency = "pycparser";
    # Preserve the oldest compatible package for historical source trees.
    versions = lib.sort lib.versionOlder (builtins.attrNames packages);
  };
in
packages.${version}
