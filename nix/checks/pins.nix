# Behavioral evaluation checks: reject unsupported future pins before a build.
{ lib }:
let
  checker = import ../check-pins.nix lib;
  check =
    component: requirements: provided:
    checker.check { inherit component requirements provided; };
  z3 = {
    z3-solver = "5.1.0.0";
  };
  select =
    project:
    checker.select {
      component = "angr";
      inherit project;
      dependency = "z3-solver";
      versions = [
        "5.1.0.0"
        "5.3.1.0"
      ];
    };
  reject = value: !(builtins.tryEval value).success;
in
assert check "angr" [ "z3-solver==5.1.0.0" ] z3;
assert check "angr" [ "z3-solver==5.0.0.0" ] z3;
assert check "angr" [ "archinfo==9.3.4.dev0" ] z3;
assert check "claripy" [ "z3_solver == 4.13.0.0" ] z3;
assert check "claripy" [ "z3-solver==4.13.0.0" ] { z3-solver = "5.3.1.0"; };
assert check "cle" [ "pyelftools>=0.29" ] { pyelftools = "0.33"; };
assert check "cle" [ "pyelftools" ] { pyelftools = "0.33"; };
assert check "angr" [ "z3-solver-extra==99" ] z3;
assert reject (check "angr" [ "z3-solver==99" ] z3);
assert reject (check "angr" [ "z3-solver>=99" ] z3);
assert reject (check "angr" [ "z3-solver~=5.1" ] z3);
assert reject (check "angr" [ "z3-solver==5.1.*" ] z3);
assert reject (check "angr" [ "z3-solver==5.1.0.0; sys_platform == 'linux'" ] z3);
assert reject (check "other-component" [ "z3-solver==5.0.0.0" ] z3);
assert reject (check "claripy" [ "z3-solver==4.13.0.0" ] { z3-solver = "5.2.0.0"; });
assert reject (check "angr" [ "z3-solver==5.0.0.0" ] { z3-solver = "5.2.0.0"; });
assert reject (check "angr" [ "z3-solver==5.0.0.0" ] { z3-solver = "5.3.1.0"; });
assert reject (check "cle" [ "pyelftools>=0.34" ] { pyelftools = "0.33"; });
assert reject (check "cle" [ "pyelftools==0.32" ] { pyelftools = "0.33"; });
assert select { } == "5.1.0.0";
assert select { project.dependencies = [ "z3-solver==5.0.0.0" ]; } == "5.1.0.0";
assert select { project.dependencies = [ "z3-solver==5.1.0.0" ]; } == "5.1.0.0";
assert select { project.dependencies = [ "z3_solver == 5.3.1.0" ]; } == "5.3.1.0";
assert select { build-system.requires = [ "Z3.Solver==5.3.1.0" ]; } == "5.3.1.0";
assert
  select {
    project.dependencies = [ "z3-solver==5.3.1.0" ];
    build-system.requires = [ "z3-solver==5.3.1.0" ];
  } == "5.3.1.0";
assert reject (select {
  project.dependencies = [ "z3-solver==99" ];
});
assert reject (select {
  build-system.requires = [ "z3-solver==99" ];
});
assert reject (select {
  project.dependencies = [ "z3-solver==5.1.0.0" ];
  build-system.requires = [ "z3-solver==5.3.1.0" ];
});
assert reject (select {
  project.dependencies = [ "z3-solver==5.3.1.0" ];
  build-system.requires = [ "z3-solver==5.1.0.0" ];
});
true
