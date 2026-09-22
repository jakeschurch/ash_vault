defmodule AshVault.Scope do
  @moduledoc """
  Behaviour for resolving the *encryption scope* of an operation.

  A scope is the blast radius of a key: everything sharing a scope shares key material,
  and destroying a scope's key crypto-erases everything in it. For a multitenant
  application the scope is the tenant; for a single-tenant application it is a constant.

  Implementations must return a value that is **stable across processes and releases** —
  in practice a binary. Never derive a scope from `:erlang.term_to_binary/1` of a struct:
  the term encoding is not guaranteed stable between OTP releases, and stored ciphertext
  has to outlive OTP upgrades.

  Built-in implementations: `AshVault.Scopes.AshTenant` and `AshVault.Scopes.Global`.
  """

  @doc """
  Resolve the scope for an operation, raising `AshVault.Errors.MissingScope` when it
  cannot be determined.
  """
  @callback resolve!(AshVault.Context.t()) :: term()

  @doc """
  Describe a scope-shaped term for an operator-facing error, without reproducing it.

  A scope term is, in practice, a tenant: a binary id, or the loaded record it was taken
  from. Both are routinely PII — an email address, an organisation name — and an error
  built from one travels wherever Ash sends errors: logs, Sentry, an APM trace. The
  diagnosis an operator needs from a bad scope is the *shape* ("you returned a struct,
  not a binary"), never the contents.

  So structs are named and not printed, maps report their atom keys and not their
  values, and everything else reports its type and size only.

  `AshVault.Scopes.AshTenant.describe_tenant/1` builds on this with one extra clause: for
  a struct it also says whether an `:id` was present-but-nil or absent, which is the
  whole diagnosis of an unsupported *tenant* shape. That distinction is meaningless for a
  scope that simply is not a binary, so it is not duplicated here.
  """
  @spec describe(term()) :: binary()
  def describe(term) when is_binary(term), do: "a #{byte_size(term)}-byte binary"
  def describe(term) when is_atom(term) and not is_nil(term), do: "an atom"
  def describe(nil), do: "nil"
  def describe(term) when is_integer(term), do: "an integer"
  def describe(%struct{}), do: "a %#{inspect(struct)}{}"

  def describe(term) when is_map(term) do
    "a map with keys #{inspect(term |> Map.keys() |> Enum.filter(&is_atom/1) |> Enum.sort())}"
  end

  def describe(term) when is_list(term), do: "a list of #{length(term)} element(s)"
  def describe(term) when is_tuple(term), do: "a #{tuple_size(term)}-tuple"
  def describe(term) when is_float(term), do: "a float"
  def describe(term) when is_pid(term), do: "a pid"
  def describe(term) when is_reference(term), do: "a reference"
  def describe(term) when is_function(term), do: "a function"
  def describe(_term), do: "a term of an unsupported type"

  @doc """
  A short, stable, non-reversing fingerprint of a scope key, for logs.

  A scope key is frequently PII — tenant ids are email addresses and organisation
  slugs — so it must not be interpolated into a `Logger` line. But an operator reading
  a log of rotation failures still has to tell *one* tenant's failures from *another's*,
  and correlate them with a second occurrence an hour later. A truncated SHA-256 of the
  scope key gives exactly that and nothing else: equal scopes fingerprint equally, and
  the fingerprint does not reveal the id.

  It is a log correlator, not a security boundary: the space of tenant ids is small
  enough to enumerate, so anyone holding a candidate id can confirm a match. That is
  fine — it removes the id from the log, which is what leaks.

  Takes a resolved scope key, which `AshVault.Vault.Runtime` has already checked is a
  binary. It is deliberately not total: a term that is not a scope key has no business
  being fingerprinted as one, and `AshVault.Scope.describe/1` is the function for
  reporting one that is not.
  """
  @spec fingerprint(binary()) :: binary()
  def fingerprint(scope) when is_binary(scope) do
    digest =
      :sha256
      |> :crypto.hash(scope)
      |> Base.encode16(case: :lower)
      |> binary_part(0, 12)

    "sha256:" <> digest
  end
end
