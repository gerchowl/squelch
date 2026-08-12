{
  description = "squelch — file a genuinely useful bug report without leaking the machine";

  inputs = {
    # The Rust language pack under review: vig-os/devkit#1429.
    devkit.url = "github:vig-os/devkit/feature/1400-rust-language-pack";
    nixpkgs.follows = "devkit/nixpkgs";
  };

  outputs =
    {
      devkit,
      nixpkgs,
      ...
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      forEachSystem =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            devkit.lib.mkRustProject {
              # devkit.overlays.default is NOT optional: mkProjectShell pulls
              # nix/devtools.nix, which references `vig-utils` from pkgs. A
              # plain nixpkgs makes `rust.devShell` throw `undefined variable
              # 'vig-utils'` while the checks still evaluate fine. Reported to
              # vig-os/devkit#1429.
              pkgs = import nixpkgs {
                inherit system;
                overlays = [ devkit.overlays.default ];
              };
              src = ./.;
              # squelch is mostly feature-gated: `gh-cli`, `endpoint` and
              # `serde` add 4 tests and a good deal of code that a
              # default-features build never compiles, so clippy would never
              # see it. mkRustProject has no `features`/`cargoExtraArgs`
              # argument; `buildEnv` is merged verbatim into crane's
              # commonArgs, so it is the only reachable seam. Documented as
              # being for CMAKE_*/PKG_CONFIG_PATH — using it this way is a
              # workaround, reported to vig-os/devkit#1429.
              buildEnv = {
                cargoExtraArgs = "--all-features";
              };
              # For ./rust-toolchain.toml. Changes when the channel or the
              # component list does; the build failure prints the new one.
              toolchainHash = "sha256-mvUGEOHYJpn3ikC5hckneuGixaC+yGrkMM/liDIDgoU=";
            }
          )
        );
    in
    {
      devShells = forEachSystem (rust: { default = rust.devShell; });
      checks = forEachSystem (rust: rust.checks);
      packages = forEachSystem (rust: rust.packages);
    };
}
