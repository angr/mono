# z3-solver, from upstream's platform wheels.
#
# angr's build and runtime Z3 pins must agree: rustylib links against libz3
# through z3-sys, while angr/_z3.py loads site-packages/z3/lib/libz3.so before
# importing the extension. Both must resolve to the same library.
#
# Linux wheels need autoPatchelfHook for their shared-library dependencies.
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
  python,
  angrSource,
}:

let
  wheels = {
    "5.1.0.0" = {
      x86_64-linux = {
        name = "z3_solver-${version}-py3-none-manylinux_2_27_x86_64.whl";
        path = "34/de/30329041d9a2dda11308576a80b5db17060e4b03a7ba7f550437fb38dd6b";
        hash = "sha256-362eMJ1wELH/a9sz8hVwoWA+9HJzcyIccRenREjwz+8=";
      };
      aarch64-linux = {
        name = "z3_solver-${version}-py3-none-manylinux_2_38_aarch64.whl";
        path = "ec/49/7db70c39fefde52eb5571ae709fa370260536439082d36b9ed1ab36bd1a0";
        hash = "sha256-Hc/My0sCeVHXrfJntbI256Z7hDPMNY2ALcsCgBUVh78=";
      };
      aarch64-darwin = {
        name = "z3_solver-${version}-py3-none-macosx_13_0_arm64.whl";
        path = "01/9a/cdb6db09d6aff6a803a94505aa24666db5e47df7aad0f2b1b0ddcb52ed12";
        hash = "sha256-OZo4qF14QQXl31oFwEpYFIG/24CvdCR3nPdvqEO05mw=";
      };
    };
    "5.3.1.0" = {
      x86_64-linux = {
        name = "z3_solver-${version}-py3-none-manylinux_2_27_x86_64.whl";
        path = "e9/ed/c327d486ef65228c367ef0f5c306abb3c805538c75db99600f68714ebb46";
        hash = "sha256-Pi4AvIDndoSdkX2qGU8zdZ/6YdZSioWc/Ekj7jJ3o4Y=";
      };
      aarch64-linux = {
        name = "z3_solver-${version}-py3-none-manylinux_2_38_aarch64.whl";
        path = "ca/dd/801aa58027558e8b9de4a2589c42ae6e4108e4db54ac8e373b77a8abe1db";
        hash = "sha256-vJQHLGEXlUpOy8gJln3wYuNzyyA+qpAdBSR7LAWP1Pc=";
      };
      aarch64-darwin = {
        name = "z3_solver-${version}-py3-none-macosx_13_0_arm64.whl";
        path = "c8/cd/4be9cece79a8021a84bd2ce544c24331d86269876fc44054c48816ce8b7c";
        hash = "sha256-48HlD3l3ECiz1um23FdR/aambA76zsM2Ta8Md9RMZAU=";
      };
    };
  };
  version = (import ./check-pins.nix lib).select {
    component = "angr";
    project = builtins.fromTOML (builtins.readFile (angrSource + "/pyproject.toml"));
    dependency = "z3-solver";
    # Preserve the oldest compatible package for historical source trees.
    versions = lib.sort lib.versionOlder (builtins.attrNames wheels);
  };
  wheel =
    wheels.${version}.${stdenv.hostPlatform.system}
      or (throw "no z3-solver ${version} wheel for ${stdenv.hostPlatform.system}");
in
python.pkgs.buildPythonPackage {
  pname = "z3-solver";
  inherit version;
  format = "wheel";

  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/${wheel.path}/${wheel.name}";
    inherit (wheel) hash;
  };

  nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib ];

  pythonImportsCheck = [ "z3" ];

  # Where the extension's link step and angr/_z3.py both have to point.
  passthru.libraryDir = "${placeholder "out"}/${python.sitePackages}/z3/lib";

  meta = {
    description = "Python bindings and shared library for the Z3 theorem prover";
    homepage = "https://github.com/Z3Prover/z3";
    license = lib.licenses.mit;
  };
}
