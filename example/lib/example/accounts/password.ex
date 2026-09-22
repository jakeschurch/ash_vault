defmodule Example.Accounts.HashPassword do
  @moduledoc """
  Hashes the `:password` argument into `:hashed_password`, using ash_authentication's
  own hash provider.

  `AshAuthentication.BcryptProvider` is the default `hash_provider` of the `password`
  strategy, so the stored hash is byte-for-byte what a stock AshAuthentication
  application would store. Only the *lookup* differs here — see
  `Example.Accounts.AuthUser` for why the strategy DSL itself cannot be used over an
  encrypted field.

  It runs in `before_action`, alongside `AshVault.Changes.Encrypt`. The two do not
  interact: the encrypt hook reads the `:email` argument and writes
  `encrypted_email` + `email_lookup`, this one reads `:password` and writes
  `hashed_password`.
  """

  use Ash.Resource.Change

  @doc false
  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      case Ash.Changeset.fetch_argument(changeset, :password) do
        {:ok, password} when is_binary(password) ->
          # `hash/1` only answers `:error` for a non-binary, which the guard above has
          # already excluded.
          {:ok, hashed} = AshAuthentication.BcryptProvider.hash(password)
          Ash.Changeset.force_change_attribute(changeset, :hashed_password, hashed)

        _absent ->
          changeset
      end
    end)
  end
end

defmodule Example.Accounts.VerifyPassword do
  @moduledoc """
  The second half of sign-in: check the `:password` argument against the row that
  `AshVault.Preparations.FilterByLookup` found.

  This is the part `AshAuthentication.Strategy.Password.SignInPreparation` would do,
  minus its `Query.filter(ref(identity_field) == ^identity)` — which is the one line
  that cannot work against an encrypted column
  (`deps/ash_authentication/lib/ash_authentication/strategies/password/sign_in_preparation.ex:46`).
  The password check itself, including the constant-work miss path, is ash_authentication's.

  Two details are load-bearing and easy to get wrong:

    * `hashed_password` is `public?: false`, so it has to be explicitly selected before
      the `after_action` hook can read it.
    * a *miss* still runs `simulate/0`. Returning early on "no such user" makes sign-in
      measurably faster for addresses that do not exist, which is a user-enumeration
      oracle — and with a deterministic lookup token the query itself is already an
      exact-match index probe, so the timing difference is clean.
  """

  use Ash.Resource.Preparation

  @doc false
  @impl Ash.Resource.Preparation
  def prepare(query, _opts, _context) do
    query
    |> Ash.Query.before_action(&Ash.Query.ensure_selected(&1, [:hashed_password]))
    |> Ash.Query.after_action(fn query, records ->
      password = Ash.Query.get_argument(query, :password)

      case records do
        [%{hashed_password: hashed} = record] when is_binary(hashed) ->
          if AshAuthentication.BcryptProvider.valid?(password, hashed) do
            {:ok, [record]}
          else
            {:ok, []}
          end

        _none_or_no_password ->
          AshAuthentication.BcryptProvider.simulate()
          {:ok, []}
      end
    end)
  end
end
