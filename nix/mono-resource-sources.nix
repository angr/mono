# The monorepo omits these large submodules but records the exact selected
# revisions. External component snapshots supply their own resource trees.
{
  pkgs,
  manifest ? ../mono.json,
}:
let
  pins =
    (builtins.fromJSON (builtins.readFile manifest)).components.angr-management.excluded_submodules;
  fetch =
    repository:
    let
      key = "angrmanagement/resources/${repository}";
    in
    builtins.fetchTree {
      type = "github";
      owner = "angr";
      repo = repository;
      rev = pins.${key} or (throw "mono.json has no recorded revision for ${key}");
    };
in
{
  flirt-signatures = fetch "flirt_signatures";
  library-docs = fetch "library_docs";
}
