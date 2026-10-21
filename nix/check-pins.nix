# Check the dependencies whose versions affect native ABI or loader behavior.
lib:
let
  # Keep each compatible version explicit so an upgrade requires another check.
  compatible = {
    angr.z3-solver."5.0.0.0" = [ "5.1.0.0" ];
    claripy.z3-solver."4.13.0.0" = [
      "5.1.0.0"
      "5.3.1.0"
    ];
  };
  requirementsOf =
    project: (project.project.dependencies or [ ]) ++ (project.build-system.requires or [ ]);
  normalize = name: lib.toLower (builtins.replaceStrings [ "_" "." ] [ "-" "-" ] name);
  check =
    {
      component,
      requirements,
      provided,
    }:
    builtins.all (
      spec:
      let
        parsed = builtins.match "[[:space:]]*([A-Za-z0-9][A-Za-z0-9._-]*)(.*)" spec;
        name =
          if parsed == null then
            throw "${component}: invalid requirement ${spec}"
          else
            normalize (builtins.head parsed);
        actual = provided.${name};
        constraints = lib.splitString "," (builtins.elemAt parsed 1);
        checkConstraint =
          constraint:
          let
            bare = builtins.match "[[:space:]]*" constraint != null;
            version = builtins.match "[[:space:]]*(==|>=)[[:space:]]*([0-9][0-9.]*)[[:space:]]*" constraint;
            operator = builtins.elemAt version 0;
            required = builtins.elemAt version 1;
            legacy = compatible.${component}.${name}.${required} or [ ];
            accepted =
              if operator == "==" then
                actual == required || builtins.elem actual legacy
              else
                lib.versionAtLeast actual required;
          in
          if bare then
            true
          else if version == null then
            throw "${component}: unsupported constraint `${spec}` for pinned ${name}; extend nix/check-pins.nix"
          else if accepted then
            true
          else
            throw "${component} requires ${spec}, but mono provides ${name} ${actual}; update its pin and compatibility checks";
      in
      if builtins.hasAttr name provided then builtins.all checkConstraint constraints else true
    ) requirements;
in
{
  inherit check;
  select =
    {
      component,
      project,
      dependency,
      versions,
    }:
    let
      accepts =
        version:
        check {
          inherit component;
          requirements = requirementsOf project;
          provided.${dependency} = version;
        };
      selected = lib.findFirst (
        version: (builtins.tryEval (accepts version)).success
      ) (builtins.head versions) versions;
    in
    # Re-run the failed check to retain its requirement-specific diagnostic.
    assert accepts selected;
    selected;
  source =
    component: source: provided:
    let
      project = builtins.fromTOML (builtins.readFile (source + "/pyproject.toml"));
    in
    check {
      inherit component provided;
      requirements = requirementsOf project;
    };
}
