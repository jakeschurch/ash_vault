defmodule AshVaultRustler.Cipher do
  @moduledoc """
  AES-256-GCM in Rust, wire-compatible with `AshVault.Ciphers.AES.GCM` in both directions.

  Same cipher id (`:aes_256_gcm_v1`), same 12-byte nonce, same 16-byte tag, same AAD, so
  the two are interchangeable on stored bytes: a value written by one decrypts with the
  other. That is deliberate and is the point of keeping the id — switching implementations
  must never strand a single existing row.

  Because the id is shared, this cipher is installed by *replacing* the registry entry
  rather than adding one:

      config :ash_vault, :ciphers, %{"aes_256_gcm_v1" => AshVaultRustler.Cipher}

  and/or on the vault directly:

      use AshVault.Vault, key_provider: MyApp.Keys, cipher: AshVaultRustler.Cipher

  Set both if you want every historical value decrypted by this implementation;
  `AshVault.Vault.Runtime` resolves the cipher for decryption from the envelope, not from
  the vault, so the registry is what governs reads.

  ## Why you would

  The pure-Elixir cipher is fine. The reason to use this one is the *opaque key* path: it
  accepts an `%AshVault.Key{}` handle, so the key never becomes an Elixir term at all. See
  `AshVaultRustler.KeyProviders.Opaque`. With a plain binary key there is no security
  difference worth claiming — the same bytes are on the same heap either way.

  ## Rejections match, exactly

  A tag that is not 16 bytes and a nonce that is not 12 bytes are rejected *before* the
  key reaches the AEAD, for the same reason the Elixir cipher does it: OTP's
  `:crypto.crypto_one_time_aead/7` accepts a truncated tag and compares only its leading
  bytes, which made a ≤256-guess forgery possible through an attacker-controlled
  `tag_len` in the envelope. `aes-gcm`'s fixed-size types would reject those anyway; the
  explicit checks make the two implementations reject the same inputs for the same stated
  reason rather than by coincidence.

  ## Scheduler

  Encrypt and decrypt run on a normal scheduler below `dirty_threshold_bytes/0` and on a
  dirty CPU scheduler at or above it. The default was measured on this machine; see the
  package README for the numbers. Override if your hardware differs:

      config :ash_vault_rustler, dirty_threshold_bytes: 65_536
  """

  @behaviour AshVault.Cipher

  alias AshVaultRustler.Native

  @key_bytes 32
  @nonce_bytes 12
  @tag_bytes 16

  # Measured on this host (AES-NI, `mix run bench/scheduler_bench.exs`): 64 B took 0.7 us,
  # 64 KiB took 46 us, 256 KiB took 319 us and 1 MiB took 1529 us — so the BEAM's ~1 ms
  # budget is crossed somewhere around 700 KiB. Dispatching to a dirty scheduler costs a
  # fixed ~0.5-1 us (16 B: 1.20 us normal vs 1.73 us dirty), which is why the threshold is
  # not simply zero.
  #
  # 64 KiB is chosen rather than 512 KiB because AES without hardware acceleration is
  # roughly an order of magnitude slower: 64 KiB still lands under 1 ms on such a CPU,
  # 256 KiB would not. It is also far above any realistic encrypted column, so in practice
  # every AshVault field operation stays on a normal scheduler and pays no dispatch cost.
  @default_dirty_threshold 65_536

  @doc """
  The stable cipher id, `:aes_256_gcm_v1` — the same as `AshVault.Ciphers.AES.GCM`.
  """
  @impl AshVault.Cipher
  @spec id() :: :aes_256_gcm_v1
  def id, do: :aes_256_gcm_v1

  @doc """
  The required key size in bytes, `32`.
  """
  @impl AshVault.Cipher
  @spec key_bytes() :: pos_integer()
  def key_bytes, do: @key_bytes

  @doc false
  @spec nonce_bytes() :: pos_integer()
  def nonce_bytes, do: @nonce_bytes

  @doc false
  @spec tag_bytes() :: pos_integer()
  def tag_bytes, do: @tag_bytes

  @doc """
  Plaintext size at or above which the AEAD is dispatched to a dirty CPU scheduler.
  """
  @spec dirty_threshold_bytes() :: pos_integer()
  def dirty_threshold_bytes do
    Application.get_env(:ash_vault_rustler, :dirty_threshold_bytes, @default_dirty_threshold)
  end

  @doc """
  Encrypt with a fresh random nonce, under a binary key or an opaque `AshVault.Key`.
  """
  @impl AshVault.Cipher
  @spec encrypt(binary(), AshVault.Key.t(), binary()) ::
          {:ok, AshVault.Cipher.payload()} | {:error, term()}
  def encrypt(plaintext, key, aad)
      when is_binary(plaintext) and is_binary(key) and is_binary(aad) do
    if byte_size(key) == @key_bytes do
      dispatch(
        byte_size(plaintext),
        fn -> Native.encrypt(key, plaintext, aad) end,
        fn -> Native.encrypt_dirty(key, plaintext, aad) end
      )
      |> to_payload()
    else
      {:error, {:invalid_key_size, byte_size(key)}}
    end
  end

  def encrypt(plaintext, %AshVault.Key{ref: ref}, aad)
      when is_binary(plaintext) and is_reference(ref) and is_binary(aad) do
    dispatch(
      byte_size(plaintext),
      fn -> Native.encrypt_handle(ref, plaintext, aad) end,
      fn -> Native.encrypt_handle_dirty(ref, plaintext, aad) end
    )
    |> to_payload()
  rescue
    # A handle minted by something other than this package decodes as a foreign resource
    # and the NIF raises `badarg`. That is a configuration fault, not tampering, so it
    # gets the error the contract reserves for it.
    ArgumentError -> {:error, :opaque_key_unsupported}
  end

  def encrypt(_plaintext, _key, _aad), do: {:error, :opaque_key_unsupported}

  @doc """
  Decrypt a payload, verifying the tag against `aad`.

  Returns `{:error, :auth_failed}` when the tag does not verify, when the tag is not
  exactly 16 bytes, or when the nonce is not exactly 12 bytes — the same collapsing the
  Elixir cipher does, so that neither implementation lets an attacker distinguish a bad
  tag from a bad length.
  """
  @impl AshVault.Cipher
  @spec decrypt(AshVault.Cipher.payload(), AshVault.Key.t(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt(%{ciphertext: ciphertext, nonce: nonce, tag: tag}, key, aad)
      when is_binary(ciphertext) and is_binary(nonce) and is_binary(tag) and is_binary(key) and
             is_binary(aad) do
    if byte_size(key) == @key_bytes do
      dispatch(
        byte_size(ciphertext),
        fn -> Native.decrypt(key, ciphertext, nonce, tag, aad) end,
        fn -> Native.decrypt_dirty(key, ciphertext, nonce, tag, aad) end
      )
      |> to_plaintext()
    else
      {:error, {:invalid_key_size, byte_size(key)}}
    end
  end

  def decrypt(%{ciphertext: ciphertext, nonce: nonce, tag: tag}, %AshVault.Key{ref: ref}, aad)
      when is_binary(ciphertext) and is_binary(nonce) and is_binary(tag) and is_reference(ref) and
             is_binary(aad) do
    dispatch(
      byte_size(ciphertext),
      fn -> Native.decrypt_handle(ref, ciphertext, nonce, tag, aad) end,
      fn -> Native.decrypt_handle_dirty(ref, ciphertext, nonce, tag, aad) end
    )
    |> to_plaintext()
  rescue
    ArgumentError -> {:error, :opaque_key_unsupported}
  end

  def decrypt(_payload, %AshVault.Key{}, _aad), do: {:error, :opaque_key_unsupported}
  def decrypt(_payload, _key, _aad), do: {:error, :auth_failed}

  defp dispatch(size, normal, dirty) do
    if size >= dirty_threshold_bytes(), do: dirty.(), else: normal.()
  end

  defp to_payload({:ok, {ciphertext, nonce, tag}}) do
    {:ok, %{ciphertext: ciphertext, nonce: nonce, tag: tag}}
  end

  defp to_payload({:error, :invalid_key_size}), do: {:error, {:invalid_key_size, :unknown}}
  defp to_payload({:error, reason}), do: {:error, reason}

  defp to_plaintext({:ok, plaintext}), do: {:ok, plaintext}
  defp to_plaintext({:error, :invalid_key_size}), do: {:error, {:invalid_key_size, :unknown}}

  # The Elixir cipher answers `:auth_failed` for a bad tag, a short tag and a short
  # nonce alike. Collapsing them here keeps the two implementations' observable behaviour
  # identical, and keeps the length of an attacker's forged tag from being distinguishable
  # from its contents.
  defp to_plaintext({:error, reason})
       when reason in [:auth_failed, :invalid_tag_size, :invalid_nonce_size],
       do: {:error, :auth_failed}

  defp to_plaintext({:error, reason}), do: {:error, reason}
end
