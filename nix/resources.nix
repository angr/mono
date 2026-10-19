# Resource output identities depend on their content, not the GUI version or
# the directory containing a selected component snapshot. The exported values
# are path-like: immutable inputs produce derivations, local trees store paths.
{
  pkgs,
  managementSource,
}:
let
  resourceSources = managementSource.resourceSources or { };
  resource =
    name: directory:
    let
      selected = resourceSources.${name} or (managementSource + "/angrmanagement/resources/${directory}");
      immutable = builtins.isAttrs selected && selected ? narHash;
      # A supplied hash describes every byte: do not filter an immutable
      # source and then claim its original hash still describes the result.
      content =
        if immutable then
          selected
        else
          builtins.path {
            path = selected;
            name = "angr-${name}";
            filter =
              path: _type:
              let
                base = baseNameOf path;
              in
              base != ".git" && base != "__pycache__" && !(pkgs.lib.hasSuffix ".pyc" base);
          };
    in
    # A flake package must be a derivation. Mono's immutable fetchTree inputs
    # already carry their NAR hashes, so their packages are fixed-output builds.
    # Arbitrary external snapshots use builtins.path directly, without an
    # impure fetch or a hash-computing build during evaluation. For recursive
    # SHA-256 addresses, the same name and content give the same store path in
    # both cases. Both preserve the resource directory itself as the output.
    if immutable then
      pkgs.runCommand "angr-${name}"
        {
          outputHash = selected.narHash;
          outputHashAlgo = "sha256";
          outputHashMode = "recursive";
          preferLocalBuild = true;
        }
        ''
          mkdir -p "$out"
          cp -a ${content}/. "$out/"
        ''
    else
      content;
in
{
  flirt-signatures = resource "flirt-signatures" "flirt_signatures";
  library-docs = resource "library-docs" "library_docs";
}
