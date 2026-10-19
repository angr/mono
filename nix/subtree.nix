# Copy part of a source tree into the store, keeping (or dropping) named paths.
#
# For a fixed name, only the retained tree affects this source path's identity.
# Derivations can still depend on values read separately, such as a version.
lib:

let
  discard = builtins.unsafeDiscardStringContext;

  # Where `p` sits under `root`, as a relative path. The filter is handed
  # paths under `root`, so stripping the prefix is exact; a path that does not
  # start with it is a bug, and throwing is better than a silently empty or
  # silently complete source (both look like success).
  relativeTo =
    root: p:
    let
      rootStr = discard (toString root);
      s = discard (toString p);
      direct = lib.removePrefix (rootStr + "/") s;
    in
    if direct != s then direct else throw "subtree: cannot place '${s}' under '${rootStr}'";
in
{
  # Keep only the listed paths.
  #
  # The filter runs on directories too, so an ancestor of a kept path has to be
  # accepted or the descent stops there. That is what the `hasPrefix rel' k`
  # clause is for.
  subtree =
    root: name: keep:
    builtins.path {
      path = root;
      inherit name;
      filter =
        p: _type:
        let
          rel = relativeTo root p;
          rel' = rel + "/";
        in
        lib.any (k: rel == k || lib.hasPrefix (k + "/") rel || lib.hasPrefix rel' k) keep;
    };

  # Keep everything except the listed paths.
  subtreeExcept =
    root: name: drop:
    builtins.path {
      path = root;
      inherit name;
      filter =
        p: _type:
        let
          rel = relativeTo root p;
        in
        !(lib.any (d: rel == d || lib.hasPrefix (d + "/") rel) drop);
    };
}
