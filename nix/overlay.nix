# The one package-set extension used by the factory and flake overlay.
{
  pkgs,
  sources,
  python,
  angrDataSrc ? null,
  withPyxdia ? true,
}:
let
  z3-solver = pkgs.callPackage ./z3-solver.nix { inherit python; };
  natives = import ./native.nix {
    inherit
      pkgs
      sources
      python
      z3-solver
      ;
  };
  resources = import ./resources.nix {
    inherit pkgs;
    managementSource = sources.angr-management;
  };
  core = import ./python.nix {
    inherit
      pkgs
      sources
      python
      natives
      resources
      z3-solver
      angrDataSrc
      withPyxdia
      ;
  };
  extras = import ./extra-packages.nix { inherit pkgs sources; };
in
self: super:
(core self super)
// (extras self super)
// {
  monoNative = natives;
  monoResources = resources;
}
