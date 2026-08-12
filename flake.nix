{
  description = "squelch — file a genuinely useful bug report without leaking the machine";

  inputs = {
    # The Rust language pack under review: vig-os/devkit#1429, plus the
    # consumer fixes this repo's adoption produced (vig-os/devkit#1452, which
    # targets the pack branch). Repoint at the pack branch once #1452 merges,
    # and at a release tag once the pack does.
    devkit.url = "github:vig-os/devkit/feature/1450-rust-pack-consumer-hardening";
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
          let
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ devkit.overlays.default ];
            };
          in
          f pkgs (
            devkit.lib.mkRustProject {
              # devkit.overlays.default is NOT optional: mkProjectShell pulls
              # nix/devtools.nix, which references `vig-utils` from pkgs. A
              # plain nixpkgs makes `rust.devShell` throw `undefined variable
              # 'vig-utils'` while the checks still evaluate fine. Reported to
              # vig-os/devkit#1429.
              inherit pkgs;
              src = ./.;
              # `--all-features`: squelch is mostly feature-gated — `gh-cli`,
              # `endpoint` and `serde` add tests and a good deal of code a
              # default-features build never compiles, so clippy would never
              # see it.
              #
              # `--workspace`: this repo is a root package WITH members, and
              # cargo defaults to the root package alone in that layout. Without
              # it the whole `apps/squelch-demo` end-to-end suite is skipped and
              # the check still reports success — nextest said "59 tests across
              # 1 binary" while thirteen e2e tests sat there unrun.
              cargoExtraArgs = "--all-features --workspace";
              # For ./rust-toolchain.toml. Changes when the channel or the
              # component list does; the build failure prints the new one.
              toolchainHash = "sha256-mvUGEOHYJpn3ikC5hckneuGixaC+yGrkMM/liDIDgoU=";
            }
          )
        );
    in
    {
      devShells = forEachSystem (_: rust: { default = rust.devShell; });
      packages = forEachSystem (_: rust: rust.packages);

      checks = forEachSystem (
        pkgs: rust:
        rust.checks
        // {
          # Every feature combination must COMPILE — the pack's checks all run
          # with one feature set, and `--all-features` is the set least likely
          # to break. It hid a real one: `endpoint` uses `serde_json::json!`
          # but did not depend on serde_json, so the crate failed to build for
          # any consumer with `default-features = false, features = ["endpoint"]`
          # while every check here stayed green.
          #
          # `--no-dev-deps` is the load-bearing flag. dev-dependencies list
          # serde_json unconditionally, so anything built with tests links it
          # anyway and the missing dependency stays invisible.
          #
          # Scoped to `-p squelch` because the feature matrix that matters is
          # the published crate's; the demo app has no features of its own.
          #
          # Built through mkRustProject's documented escape hatches rather than
          # a knob, because the pack has no feature-matrix check and its curated
          # tool map has no cargo-hack entry.
          feature-powerset = rust.craneLib.mkCargoDerivation (
            rust.commonArgs
            // {
              inherit (rust) cargoArtifacts;
              pnameSuffix = "-feature-powerset";
              nativeBuildInputs = (rust.commonArgs.nativeBuildInputs or [ ]) ++ [ pkgs.cargo-hack ];
              buildPhaseCargoCommand = ''
                cargo hack check -p squelch --feature-powerset --no-dev-deps --locked
              '';
            }
          );
        }
      );
    };
}
