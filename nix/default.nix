# Reusable angr family packaging. Sources may be mono components or independently
# selected component snapshots; every value is a path or an attrset with outPath.
{
  pkgs ? import (builtins.fetchTree (builtins.fromJSON (builtins.readFile ../flake.lock))
  .nodes.nixpkgs.locked) { },
  sources ? import ./sources.nix { inherit pkgs; },
  python ? pkgs.python312,
  angrDataSrc ? sources.angr-data or null,
  withPyxdia ? true,
  packageOverrides ? (_: _: { }),
}:
let
  extension = import ./overlay.nix {
    inherit
      pkgs
      sources
      python
      angrDataSrc
      withPyxdia
      ;
  };
  interpreter = python.override {
    packageOverrides = pkgs.lib.composeManyExtensions [
      (python.packageOverrides or (_: _: { }))
      extension
      packageOverrides
    ];
  };
  ps = interpreter.pkgs;
  natives = ps.monoNative;
in
natives
// ps.monoResources
// {
  python = interpreter;
  inherit (ps)
    angr
    archinfo
    cle
    claripy
    pyvex
    pypcode
    angr-management
    pysoot
    angr-data
    pyqodeng
    pyxdia
    z3-solver
    sortedcontainers-stubs
    types-pefile
    ;

  rustylib-check = natives.rustylib.overrideAttrs (_: {
    doCheck = true;
  });
  natives-all = pkgs.linkFarm "angr-natives" [
    {
      name = "libpyvex";
      path = natives.pyvex-native;
    }
    {
      name = "unicornlib";
      path = natives.unicornlib;
    }
    {
      name = "rustylib";
      path = natives.rustylib;
    }
    {
      name = "pypcode_native";
      path = natives.pypcode-native;
    }
  ];
}
