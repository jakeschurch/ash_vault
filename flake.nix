{
  description = "AshVault — encrypted Ash resource attributes with crypto-erasure";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Native toolchain. This is the part the host is missing: there is a
        # cargo on PATH but no linker at all, so anything with a NIF — a Rust
        # cipher/key cache, or bcrypt_elixir via ash_authentication — cannot
        # link. Everything here is build-time only; none of it ends up in the
        # library's runtime dependencies.
        native = with pkgs; [
          # C toolchain: `cc`/`ld` for elixir_make NIFs and as cargo's linker.
          gcc
          gnumake
          pkg-config

          # Rust, for a future `ash_vault_rustler` providing an
          # AshVault.Cipher + KeyCache that holds key material outside the
          # BEAM heap so eviction can actually zero it.
          cargo
          rustc
          rust-analyzer
          clippy
          rustfmt

          # `pg_dump` and `psql`. The acceptance suite currently shells into
          # the postgres container for pg_dump because the host has neither;
          # with these on PATH it can talk to localhost:5432 directly.
          postgresql_16

          # OpenBao CLI, for inspecting transit keys and tombstones by hand.
          openbao
        ];

        beam = with pkgs; [ erlang_28 elixir_1_18 ];
      in
      {
        # Default: native tooling only, inheriting the host's Elixir/OTP.
        #
        # Deliberate. The host runs Elixir 1.20.4 / OTP 29 and the whole suite
        # (395 tests) was built and verified against it; nixpkgs currently
        # pins 1.18.5 / OTP 28. Adding those here would downgrade the
        # toolchain under you and invalidate _build on every shell entry. Use
        # the `full` shell below when you want the pinned, reproducible one.
        devShells.default = pkgs.mkShell {
          packages = native;

          shellHook = ''
            echo "ashvault dev shell — native toolchain"
            echo "  elixir : $(elixir --version 2>/dev/null | tail -1 || echo 'not found (inherited from host)')"
            echo "  cc     : $(cc --version 2>/dev/null | head -1 || echo missing)"
            echo "  cargo  : $(cargo --version 2>/dev/null || echo missing)"
            echo "  pg_dump: $(pg_dump --version 2>/dev/null || echo missing)"
            echo ""
            echo "services expected by the tagged suites:"
            echo "  postgres  localhost:5432   (mix test --include postgres)"
            echo "  openbao   127.0.0.1:8200   (mix test --include openbao)"
          '';
        };

        # Fully pinned, for CI and for reproducing a build from scratch.
        # Note this is OTP 28 / Elixir 1.18, not the host's 29 / 1.20.
        devShells.full = pkgs.mkShell {
          packages = native ++ beam;

          shellHook = ''
            echo "ashvault dev shell — FULL (pinned BEAM)"
            echo "  $(elixir --version | tail -1)"
            echo ""
            echo "This pins Elixir 1.18.5 / OTP 28, which differs from the"
            echo "host toolchain the suite was verified on (1.20.4 / OTP 29)."
            echo "Expect a full recompile; run 'mix deps.compile --force' if"
            echo "you see beam-file version errors."
          '';
        };
      });
}
