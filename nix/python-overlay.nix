# Compatibility entrypoint for consumers of mono's Python overlay.
{
  lib,
  src,
  angrDataSrc ? null,
  sources ? null,
  withPyxdia ? true,
}:
python-final: python-prev:
let
  pkgs = python-final.pkgs;
  componentSources = if sources == null then import ./sources.nix { inherit pkgs src; } else sources;
in
(import ./overlay.nix {
  inherit pkgs angrDataSrc withPyxdia;
  sources = componentSources;
  python = python-prev.python;
})
  python-final
  python-prev
