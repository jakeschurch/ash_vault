defmodule AshVault.Transformers.SetupMacaroons do
  @moduledoc """
  Generates, for every `macaroon` in the `ash_vault` section:

    * a generic action `:mint_<name>` (or `mint_action`) returning the token string,
      backed by `AshVault.Macaroon.Actions.Mint`, with arguments for the identity
      attribute, `:caveats` (a map) and `:ttl` (seconds)
    * a read action `:<name>_by_token` (or `read_action`) taking a sensitive `:token`
      argument, `get? true`, backed by `AshVault.Macaroon.Preparations.Verify`
    * a code interface for each: `mint_<name>(identity, opts)` and
      `<name>_by_token(token, opts)`

  An action of either name that already exists is a DSL error rather than a silent skip:
  a hand-written action of that name would not verify anything.

  The identity is resolved here only far enough to type the mint argument; the full
  checks (scope, vault, prefix, caveat types) live in
  `AshVault.Verifiers.VerifyMacaroons`, which reports them with better messages.
  """

  use Spark.Dsl.Transformer

  alias Ash.Resource.Builder
  alias AshVault.Macaroon.Definition
  alias Spark.Dsl.Transformer

  @doc false
  @impl Spark.Dsl.Transformer
  def after?(Ash.Resource.Transformers.DefaultAccept), do: true
  def after?(AshVault.Transformers.SetupEncryption), do: true
  def after?(_), do: false

  @doc false
  @impl Spark.Dsl.Transformer
  def transform(dsl) do
    dsl
    |> AshVault.Info.macaroons()
    |> Enum.reduce_while({:ok, dsl}, fn definition, {:ok, dsl} ->
      case setup(dsl, definition) do
        {:ok, dsl} -> {:cont, {:ok, dsl}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end

  defp setup(dsl, definition) do
    module = Transformer.get_persisted(dsl, :module)
    mint = Definition.mint_action(definition)
    read = Definition.read_action(definition)
    attribute = AshVault.Macaroon.Runtime.identity_attribute(dsl, definition)

    cond do
      is_nil(attribute) ->
        {:error,
         Spark.Error.DslError.exception(
           module: module,
           path: [:ash_vault, :macaroon, definition.name, :identity],
           message:
             "`identity #{inspect(definition.identity)}` must name the resource's single " <>
               "primary key attribute, or an identity with exactly one key."
         )}

      Ash.Resource.Info.action(dsl, mint) || Ash.Resource.Info.action(dsl, read) ->
        {:error,
         Spark.Error.DslError.exception(
           module: module,
           path: [:ash_vault, :macaroon, definition.name],
           message:
             "macaroon #{inspect(definition.name)} generates actions #{inspect(mint)} and " <>
               "#{inspect(read)}, but one already exists. Rename it, or set " <>
               "`mint_action`/`read_action`."
         )}

      true ->
        add_actions(dsl, definition, attribute, mint, read)
    end
  end

  defp add_actions(dsl, definition, attribute, mint, read) do
    with {:ok, identity_arg} <-
           Builder.build_action_argument(attribute.name, attribute.type,
             allow_nil?: false,
             constraints: attribute.constraints,
             description: "The record the token names."
           ),
         {:ok, caveats_arg} <-
           Builder.build_action_argument(:caveats, :map,
             allow_nil?: true,
             default: %{},
             description: "Caveats to bake into the token: declared name => value."
           ),
         {:ok, ttl_arg} <-
           Builder.build_action_argument(:ttl, :integer,
             allow_nil?: true,
             constraints: [min: 1],
             description: "Lifetime in seconds, overriding `default_ttl`."
           ),
         {:ok, token_arg} <-
           Builder.build_action_argument(:token, :string,
             allow_nil?: false,
             sensitive?: true,
             description: "The macaroon to verify."
           ),
         {:ok, preparation} <-
           Builder.build_preparation(
             {AshVault.Macaroon.Preparations.Verify, macaroon: definition.name}
           ),
         {:ok, dsl} <-
           Builder.add_action(dsl, :action, mint,
             returns: :string,
             constraints: [allow_empty?: false, trim?: false],
             allow_nil?: false,
             run: {AshVault.Macaroon.Actions.Mint, macaroon: definition.name},
             arguments: [identity_arg, caveats_arg, ttl_arg],
             description: "Mint a #{inspect(definition.name)} macaroon for one record."
           ),
         {:ok, dsl} <-
           Builder.add_action(dsl, :read, read,
             arguments: [token_arg],
             preparations: [preparation],
             get?: true,
             description:
               "Read the record a #{inspect(definition.name)} macaroon names, verifying it."
           ),
         {:ok, dsl} <- Builder.add_interface(dsl, mint, args: [attribute.name]) do
      Builder.add_interface(dsl, read, args: [:token], get?: true)
    end
  end
end
