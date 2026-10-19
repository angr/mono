# Adapt a mono tree to the per-component source interface. External consumers
# pass their own source attrset directly to nix/default.nix.
{
  pkgs,
  src ? ../.,
}:
let
  names = [
    "angr"
    "archinfo"
    "cle"
    "claripy"
    "pyvex"
    "pypcode"
    "angr-management"
    "pysoot"
    "tracer"
    "angr-platforms"
    "angrop"
  ];
  components = pkgs.lib.genAttrs names (name: {
    outPath = builtins.path {
      path = src + "/${name}";
      name = "${name}-source";
    };
  });
in
components
// {
  angr-management = components.angr-management // {
    resourceSources = import ./mono-resource-sources.nix {
      inherit pkgs;
      manifest = src + "/mono.json";
    };
  };
}
