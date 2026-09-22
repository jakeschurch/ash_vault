defmodule AshVault.Errors.SerializationFailed do
  @moduledoc """
  Raised when a value could not be dumped to (or cast back from) its embedded
  representation while being encrypted or decrypted.

  Lives in its own file rather than in `AshVault.Errors` because the crypto core owns
  that module; this error belongs to the Ash extension layer.

  ## The `:reason` field is redacted

  `:reason` is the raw return of `Ash.Type.dump_to_embedded/3` or
  `Ash.Type.cast_from_embedded/3`, tagged with which callback produced it. That return is
  **type-controlled**: every built-in Ash type returns a bare `:error` or
  `{:error, index: 0}`, but the `Ash.Type` contract permits
  `{:error, message: "...", value: value}` — and a custom type that takes that option puts
  the rejected value, which for AshVault is plaintext, into an `Ash.Error` that gets
  logged, rendered and shipped to APM.

  So `exception/1` rewrites `:reason` before it is ever stored on the struct — not in
  `message/1`, because `inspect(error)` and Ash's own error aggregation read the struct
  directly. The rewrite is an **allowlist**: the tuple/list/map *shape* is preserved,
  keyword and map *keys* are preserved verbatim, and every leaf value survives only if it
  is an atom or an integer. Anything else — binaries, floats, structs, nested data — is
  replaced by `{:redacted, kind}`, which records what was dropped without recording it.

  That keeps the whole diagnostic the task of debugging a custom type actually needs:

      {:dump_to_embedded, :error}
      {:dump_to_embedded, {:error, [index: 0]}}
      {:cast_from_embedded, {:error, [field: :email, message: {:redacted, :binary}]}}

  The one deliberate loss is `:message`. A custom type is free to write
  `{:error, message: "bad SSN: \#{value}"}`, so a message is as untrustworthy as a
  `:value`, and truncating it would still leak a prefix — which, for a short secret, is
  the whole secret. The error already carries `:resource`, `:field` and `:type`, so the
  operator knows exactly which type module to look at; read its message there, against a
  value you are allowed to see.
  """

  use Splode.Error, fields: [:resource, :field, :type, :reason], class: :invalid

  # Beyond this depth the shape has stopped being diagnostic and has started being a
  # place to hide a payload.
  @max_depth 6

  @doc """
  Build the error, redacting `:reason` so no type-controlled value is retained.

  See the moduledoc for exactly what survives.
  """
  @impl true
  def exception(opts) do
    opts
    |> update_reason()
    |> super()
  end

  defp update_reason(opts) when is_list(opts) do
    case Keyword.fetch(opts, :reason) do
      {:ok, reason} -> Keyword.put(opts, :reason, redact_reason(reason))
      :error -> opts
    end
  end

  defp update_reason(opts), do: opts

  @doc """
  Redact a raw `Ash.Type` callback return down to its shape.

  Exposed so the sanitizer can be tested directly, and so anywhere else that wants to
  put a type-controlled term in an operator-facing place can reuse the same rule.
  """
  @spec redact_reason(term()) :: term()
  def redact_reason({callback, term}) when callback in [:dump_to_embedded, :cast_from_embedded] do
    {callback, redact(term, 0)}
  end

  def redact_reason(other), do: redact(other, 0)

  defp redact(_term, depth) when depth > @max_depth, do: {:redacted, :nested}

  # Atoms and integers are the only leaves that survive. Both are, in practice, code —
  # `:error`, a field name, an array index — rather than data.
  defp redact(term, _depth) when is_atom(term) or is_integer(term), do: term

  defp redact(%struct{}, _depth), do: {:redacted, struct}

  defp redact(term, depth) when is_list(term) do
    if Keyword.keyword?(term) do
      Enum.map(term, fn {key, value} -> {key, redact(value, depth + 1)} end)
    else
      Enum.map(term, &redact(&1, depth + 1))
    end
  end

  defp redact(term, depth) when is_tuple(term) do
    term
    |> Tuple.to_list()
    |> Enum.map(&redact(&1, depth + 1))
    |> List.to_tuple()
  end

  defp redact(term, depth) when is_map(term) do
    # Map *keys* are only preserved when they are themselves code-shaped. Redacting a
    # binary key would collapse distinct keys onto one another, so the whole map goes.
    if Enum.all?(Map.keys(term), &(is_atom(&1) or is_integer(&1))) do
      Map.new(term, fn {key, value} -> {key, redact(value, depth + 1)} end)
    else
      {:redacted, :map}
    end
  end

  defp redact(term, _depth), do: {:redacted, kind(term)}

  # Exhaustive for everything `redact/2` has not already matched: atoms, integers,
  # structs, lists, tuples and maps never reach here.
  defp kind(term) when is_binary(term), do: :binary
  defp kind(term) when is_bitstring(term), do: :bitstring
  defp kind(term) when is_float(term), do: :float
  defp kind(term) when is_function(term), do: :function
  defp kind(term) when is_pid(term), do: :pid
  defp kind(term) when is_reference(term), do: :reference
  defp kind(term) when is_port(term), do: :port

  def message(%{resource: resource, field: field, type: type, reason: reason}) do
    """
    Could not serialize #{inspect(resource)}.#{field} (type #{inspect(type)}) for encryption.

    #{inspect(reason)}

    The reason above is redacted: `{:redacted, _}` stands where a type-controlled value
    was dropped, because that value is the plaintext this error exists to protect.
    """
  end
end
