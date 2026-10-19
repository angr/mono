# z3-solver, from upstream's platform wheels.
#
# The version is the reason this is not nixpkgs' z3. angr pins
# `z3-solver==5.1.0.0` in both its build and its runtime dependencies, and the
# pin is load-bearing: angr/rustylib links against libz3 through z3-sys, and
# angr/_z3.py ctypes-loads the libz3 that sits *inside the z3 package*
# (`site-packages/z3/lib/libz3.so`) before importing the extension, so the
# library the extension links against and the library the interpreter loads
# have to be the same file. nixpkgs' z3 python bindings have that layout too,
# but at another version (4.16.0 at the pin), and the bindings are tied to one
# Z3 release.
#
# Linux wheels need autoPatchelfHook for their shared-library dependencies.
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
  python,
}:

let
  version = "5.1.0.0";
  wheels = {
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
  wheel =
    wheels.${stdenv.hostPlatform.system}
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
