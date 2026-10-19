# Read a package's version out of its own source, so a release bump in the
# checkout does not leave a stale literal behind in the nix expressions.
#
#   versionOf sources.angr "angr/__init__.py" "__version__"   ->  "9.3.5.dev0"
#
# Match the attribute at the start of a line. Since `.` matches newlines and
# the prefix is greedy, an unanchored `version` also matches a later
# `target-version` in TOML.
src: file: attr:
let
  m = builtins.match "(.*\n)?${attr} *= *\"([^\"]+)\".*" (builtins.readFile (src + "/${file}"));
in
if m == null then throw "cannot read ${attr} from ${file}" else builtins.elemAt m 1
