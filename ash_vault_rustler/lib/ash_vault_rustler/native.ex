defmodule AshVaultRustler.Native do
  @moduledoc """
  Raw NIF bindings for the `ashvault_nif` crate. Not a public API.

  Use `AshVaultRustler.KeyCache`, `AshVaultRustler.Cipher` and
  `AshVaultRustler.KeyProviders.Opaque` instead. These functions take and return the
  crate's own encodings and perform no validation beyond what the crate does.

  ## Slot encoding

  Slots cross the boundary as integers, because a small closed set of integers cannot be
  mis-decoded and needs no atom table:

    * `-1` — the current key
    * `-2` — the tombstone
    * `n > 0` — key version `n`

  ## TTL encoding

  Milliseconds, with any negative value meaning "never expires". Only a tombstone is ever
  given a negative TTL.

  ## Panics

  Every function here returns a value or raises in the *calling process*. Rustler wraps
  each NIF body in `catch_unwind`, so a panic in Rust becomes an `ErlangError` for the
  caller rather than an aborted VM. `panic_for_test/0` exists purely so that claim can be
  tested rather than asserted; see `test/panic_test.exs`.

  ## Distribution: source build by default, precompiled behind a switch

  Building from source needs a Rust toolchain and a linker, which is a real adoption
  cost. `rustler_precompiled` removes it by downloading a verified artifact instead — but
  only once a tagged release with CI artifacts exists, because a `base_url` pointing at a
  release that is not there turns every `mix test` into a NIF load failure. That is a far
  worse default than requiring a toolchain.

  So the switch is wired and **off**. With `ASH_VAULT_RUSTLER_PRECOMPILED` unset, this is
  a plain `use Rustler` and nothing about the build changes. Set it at compile time to
  take the precompiled path:

      ASH_VAULT_RUSTLER_PRECOMPILED=1 mix compile

  `ASH_VAULT_RUSTLER_BUILD=1` forces a source build on that path, which is what CI uses
  to produce the artifacts in the first place.

  Both are read at **compile** time, so changing either needs a `mix deps.compile
  ash_vault_rustler --force` to take effect. `README.md` has the release checklist,
  including the one-line change that makes precompiled the default.
  """

  # The consumer-facing default. Flipping this literal to `true` — after the first
  # release exists and `checksum-Elixir.AshVaultRustler.Native.exs` is committed — is what
  # makes precompiled artifacts the default; the environment variable then becomes the
  # opt-out rather than the opt-in.
  @precompiled_by_default true

  @precompiled? @precompiled_by_default or
                  System.get_env("ASH_VAULT_RUSTLER_PRECOMPILED") in ["1", "true"]

  @targets ~w(
    aarch64-apple-darwin
    x86_64-apple-darwin
    aarch64-unknown-linux-gnu
    x86_64-unknown-linux-gnu
    aarch64-unknown-linux-musl
    x86_64-unknown-linux-musl
  )

  @doc false
  @spec precompiled?() :: boolean()
  def precompiled?, do: @precompiled?

  @doc false
  @spec targets() :: [String.t()]
  def targets, do: @targets

  if @precompiled? do
    # Declared inside the branch: outside it they are unused, and an unused module
    # attribute is a `--warnings-as-errors` failure in the default (source) build.
    @version Mix.Project.config()[:version]
    @force_build? System.get_env("ASH_VAULT_RUSTLER_BUILD") in ["1", "true"]

    use RustlerPrecompiled,
      otp_app: :ash_vault_rustler,
      crate: "ashvault_nif",
      base_url:
        "https://github.com/jakeschurch/ash_vault/releases/download/" <>
          "ash_vault_rustler-v#{@version}",
      version: @version,
      targets: @targets,
      # Must match what CI actually builds. RustlerPrecompiled's default list
      # includes 2.15, and it downloads every declared version — so leaving this
      # out makes `mix nif.checksum` 404 on artifacts that were never built.
      # One artifact per target at 2.16 covers OTP 24+, since a NIF built for
      # 2.16 loads on any OTP speaking 2.16 or later.
      nif_versions: ["2.16"],
      force_build: @force_build?
  else
    use Rustler, otp_app: :ash_vault_rustler, crate: "ashvault_nif"
  end

  @typedoc "An opaque reference to a Rust-side cache."
  @opaque cache :: reference()

  @typedoc "An opaque reference to one key held outside the BEAM heap."
  @opaque key_handle :: reference()

  @doc "Create a cache bounded by entry count and total key bytes."
  @spec cache_new(non_neg_integer(), non_neg_integer()) :: cache()
  def cache_new(_max_entries, _max_bytes), do: err()

  @doc "Read a slot: `{:ok, secret, meta, generation}` or `{:miss, generation}`."
  @spec cache_fetch(cache(), binary(), integer()) ::
          {:ok, binary(), binary(), non_neg_integer()}
          | {:miss, non_neg_integer()}
          | {:error, :invalid_slot}
  def cache_fetch(_cache, _scope, _slot), do: err()

  @doc "Write a slot. `:stale` means the generation fence rejected the write."
  @spec cache_put(
          cache(),
          binary(),
          integer(),
          binary(),
          binary(),
          integer(),
          non_neg_integer()
        ) :: :ok | :stale
  def cache_put(_cache, _scope, _slot, _secret, _meta, _ttl_ms, _generation), do: err()

  @doc "Drop every entry for a scope, zeroing each one, and bump its generation."
  @spec cache_evict_scope(cache(), binary()) :: :ok
  def cache_evict_scope(_cache, _scope), do: err()

  @doc "Drop everything, bumping every known scope's generation."
  @spec cache_evict_all(cache()) :: :ok
  def cache_evict_all(_cache), do: err()

  @doc "`{entries, bytes}` currently held."
  @spec cache_stats(cache()) :: {non_neg_integer(), non_neg_integer()}
  def cache_stats(_cache), do: err()

  @doc "The scope's current generation."
  @spec cache_generation(cache(), binary()) :: non_neg_integer()
  def cache_generation(_cache, _scope), do: err()

  @doc "An opaque handle to a cached key, without the bytes becoming an Elixir term."
  @spec cache_key_handle(cache(), binary(), integer()) :: {:ok, key_handle()} | :miss
  def cache_key_handle(_cache, _scope, _slot), do: err()

  @doc """
  Wrap 32 key bytes in a handle. The binary passed in is the caller's to worry about.

  Returns `{:error, :invalid_key_size}` for anything that is not exactly 32 bytes.
  """
  @spec key_handle_new(binary()) :: key_handle() | {:error, :invalid_key_size}
  def key_handle_new(_key), do: err()

  @doc "The handle's key size in bytes."
  @spec key_handle_byte_size(key_handle()) :: non_neg_integer()
  def key_handle_byte_size(_handle), do: err()

  @doc "Whether the handle's pages are locked into RAM."
  @spec key_handle_mlocked(key_handle()) :: boolean()
  def key_handle_mlocked(_handle), do: err()

  @doc "Constant-time comparison of a handle against candidate bytes."
  @spec key_handle_matches(key_handle(), binary()) :: boolean()
  def key_handle_matches(_handle, _candidate), do: err()

  @doc "`{locked, failed}` counts for `mlock` since the NIF was loaded."
  @spec mlock_status() :: {non_neg_integer(), non_neg_integer()}
  def mlock_status, do: err()

  @doc "AES-256-GCM encrypt on a normal scheduler."
  @spec encrypt(binary(), binary(), binary()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, atom()}
  def encrypt(_key, _plaintext, _aad), do: err()

  @doc "AES-256-GCM encrypt on a dirty CPU scheduler."
  @spec encrypt_dirty(binary(), binary(), binary()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, atom()}
  def encrypt_dirty(_key, _plaintext, _aad), do: err()

  @doc "AES-256-GCM decrypt on a normal scheduler."
  @spec decrypt(binary(), binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def decrypt(_key, _ciphertext, _nonce, _tag, _aad), do: err()

  @doc "AES-256-GCM decrypt on a dirty CPU scheduler."
  @spec decrypt_dirty(binary(), binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def decrypt_dirty(_key, _ciphertext, _nonce, _tag, _aad), do: err()

  @doc "Encrypt against an opaque handle. The key never becomes an Elixir term."
  @spec encrypt_handle(key_handle(), binary(), binary()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, atom()}
  def encrypt_handle(_handle, _plaintext, _aad), do: err()

  @doc "Encrypt against an opaque handle, on a dirty CPU scheduler."
  @spec encrypt_handle_dirty(key_handle(), binary(), binary()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, atom()}
  def encrypt_handle_dirty(_handle, _plaintext, _aad), do: err()

  @doc "Decrypt against an opaque handle. The key never becomes an Elixir term."
  @spec decrypt_handle(key_handle(), binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def decrypt_handle(_handle, _ciphertext, _nonce, _tag, _aad), do: err()

  @doc "Decrypt against an opaque handle, on a dirty CPU scheduler."
  @spec decrypt_handle_dirty(key_handle(), binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def decrypt_handle_dirty(_handle, _ciphertext, _nonce, _tag, _aad), do: err()

  @doc "Encrypt against a cached key without materialising it."
  @spec encrypt_cached(cache(), binary(), integer(), binary(), binary()) ::
          {:ok, {binary(), binary(), binary()}} | {:error, atom()} | :miss
  def encrypt_cached(_cache, _scope, _slot, _plaintext, _aad), do: err()

  @doc "Decrypt against a cached key without materialising it."
  @spec decrypt_cached(cache(), binary(), integer(), binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()} | :miss
  def decrypt_cached(_cache, _scope, _slot, _ciphertext, _nonce, _tag, _aad), do: err()

  @doc false
  @spec panic_for_test() :: no_return()
  def panic_for_test, do: err()

  @doc false
  @spec deliberate_test_panic_atom() :: atom()
  def deliberate_test_panic_atom, do: err()

  defp err, do: :erlang.nif_error(:nif_not_loaded)
end
