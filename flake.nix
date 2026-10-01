{
  description = "squelch — file a genuinely useful bug report without leaking the machine";

  inputs = {
    # The Rust language pack under review: vig-os/devkit#1429, now carrying the
    # consumer fixes this repo's adoption produced (#1452, merged). Repoint at
    # a release tag once the pack itself lands on devkit's dev branch.
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
          let
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ devkit.overlays.default ];
            };
            # Shared by BOTH mkRustProject calls below, which is the point of
            # naming it: crane's source filter walks the crate directories for
            # cargo sources, so neither of these reaches a sandbox on its own,
            # and `tests/issue_form.rs` `include_str!`s both. Passing them to
            # one project and not the other is exactly the drift that broke the
            # x86_64-linux run — the MSRV project has its own `cleanSrc`, and
            # it also runs the test suite.
            extraSrcFiles = [
              ".github/ISSUE_TEMPLATE/bug.yml"
              "README.md"
              # `tests/issue_form.rs` also asserts that every relative link in the
              # README and the ADR index resolves, so the ADRs have to be in the
              # sandbox. A `docs/` path missing here fails the check on a file
              # nobody changed, which is the same class of surprise as the missing
              # `bug.yml` above.
              "docs"
            ];
            # The same project at the MSRV `Cargo.toml` declares, for one
            # question only: does it still compile there?
            #
            # Clippy, rustdoc, cargo-deny and nextest are all off: running them
            # on an old compiler measures the compiler, not the crate — lints
            # move, and a lint that did not exist yet failing here would say
            # nothing about whether a consumer pinned there can use this.
            #
            # crane's `buildPackage` still runs `cargo test` in its check phase,
            # so the suite does execute at the MSRV. That is worth having and is
            # why this project needs the same `extraSrcFiles` as the main one.
            msrv = devkit.lib.mkRustProject {
              inherit pkgs;
              src = ./.;
              inherit extraSrcFiles;
              # `-p squelch` and NOT `--workspace`: the MSRV is a promise
              # about the PUBLISHED crate, and the demo app is not published.
              #
              # `--all-features` because the promise has to cover the features
              # a consumer can turn on — and it is `endpoint` that sets the
              # floor here, by way of ureq → url → idna → idna_adapter.
              cargoExtraArgs = "-p squelch --all-features";
              toolchainFile = ./.msrv/rust-toolchain.toml;
              toolchainHash = "sha256-X/4ZBHO3iW0fOenQ3foEvscgAPJYl2abspaBThDOukI=";
              clippy = false;
              fmt = false;
              nextest = false;
              doc = false;
              doctest = false;
              deny = false;
              auditable = false;
            };
          in
          f pkgs msrv (
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
              inherit extraSrcFiles;
              # For ./rust-toolchain.toml. Changes when the channel or the
              # component list does; the build failure prints the new one.
              toolchainHash = "sha256-mvUGEOHYJpn3ikC5hckneuGixaC+yGrkMM/liDIDgoU=";
            }
          )
        );
    in
    {
      devShells = forEachSystem (_: _: rust: { default = rust.devShell; });
      packages = forEachSystem (_: _: rust: rust.packages);

      checks = forEachSystem (
        pkgs: msrv: rust:
        rust.checks
        // {
          # `rust-version` is a promise about this crate's API surface, and it
          # was verified by nothing. A declared but unverified MSRV is a FALSE
          # promise, not a weak one — the failure lands on the downstream, who
          # has no way to tell it from their own mistake.
          #
          # It said 1.74 when nothing checked, and 1.74 cannot build this crate
          # at all. The number in Cargo.toml is now whatever this check passes
          # with, or the declaration comes out.
          msrv = msrv.checks.workspace;
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
              # `--offline`, not `--locked`. `--no-dev-deps` rewrites the real
              # Cargo.toml while it runs, and once a dev-dependency is dev-ONLY
              # (proptest, the YAML parser) the lock then describes packages the
              # manifest no longer mentions, so `--locked` refuses. `--offline`
              # is just as hermetic here: crane has vendored every dependency
              # and the sandbox has no network to fall back to.
              buildPhaseCargoCommand = ''
                cargo hack check -p squelch --feature-powerset --no-dev-deps --offline
              '';
            }
          );
        }
      );
    };
}
