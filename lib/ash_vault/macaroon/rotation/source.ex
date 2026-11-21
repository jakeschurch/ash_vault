defmodule AshVault.Macaroon.Rotation.Source do
  @moduledoc """
  Where the credentials under rotation are declared, and where their
  `AshVault.Macaroon.Rotation.State` is kept.

  A source owns configuration and state storage only. Minting, revocation and the
  rotation cycle are `AshVault.Macaroon.Rotation`'s; delivering tokens is the
  `AshVault.Macaroon.Rotation.Delivery`'s.

  `list/1` returning `{:ok, []}` turns rotation off (no configuration in this
  deployment) without failing the scheduled action.
  """

  alias AshVault.Macaroon.Rotation.Context
  alias AshVault.Macaroon.Rotation.Item
  alias AshVault.Macaroon.Rotation.State

  @doc "Every credential to reconcile now, with its saved state."
  @callback list(Context.t()) :: {:ok, [Item.t()]} | {:error, term()}

  @doc """
  Store the state a reconcile produced. Called once per item per reconcile, also when
  the reconcile failed. An error is reported as a `:status` failure; the next
  reconcile starts from the state saved before.
  """
  @callback save(Item.t(), State.t(), Context.t()) :: :ok | {:error, term()}

  @doc """
  A credential was revoked by rotation. For caches of verified tokens (flush them, so
  the revocation takes effect at once). Its result is ignored.
  """
  @callback revoked(id :: String.t(), Context.t()) :: term()

  @doc """
  A one-line description of an error this source returned, for logs and the stored
  failure. Without it, binaries are used as-is and anything else is
  `"unexpected error"`. Never inspect the error: it may carry request data.
  """
  @callback describe_error(term()) :: String.t() | nil

  @optional_callbacks revoked: 2, describe_error: 1
end

defmodule AshVault.Macaroon.Rotation.Delivery do
  @moduledoc """
  How a minted token reaches its consumers.

  Rotation calls a delivery in two steps, possibly many reconciles apart:

    1. `stage/3`, right after minting: put the token somewhere only the minting service
       can read it. A failure revokes the new credential at once, because nobody holds
       it.
    2. `staged/2` then `deliver/4` per consumer not yet holding it, retried every
       reconcile until each succeeds. The token is read back from staging each time;
       rotation itself keeps no token between reconciles.

  Every callback must be idempotent: a crash between a write and the state being saved
  repeats the write.

  A delivery never confirms that a consumer *picked up* the token, and must not read
  the consumer's copy to find out. Pickup is proven by use: the superseded credential
  is revoked only once its `last_used_at` has been quiet for the quiet period. A
  consumer that reads its copy only at start needs a restart once the copy changes;
  that belongs to whatever syncs the copy (for Kubernetes, Stakater Reloader on the
  synced Secret), not to rotation.

  `AshVault.Macaroon.Rotation.OpenBaoKV` is a delivery to OpenBao KV v2, for consumers
  that read through External Secrets Operator.
  """

  alias AshVault.Macaroon.Rotation.Context
  alias AshVault.Macaroon.Rotation.Secret

  @doc "Stage the token minted for credential `id`."
  @callback stage(Context.t(), id :: String.t(), Secret.t()) :: :ok | {:error, term()}

  @doc """
  The staged token, if staging still holds credential `id`'s. `:lost` (staging was
  replaced or deleted) revokes that credential and starts over with a new one.
  """
  @callback staged(Context.t(), id :: String.t()) ::
              {:ok, Secret.t()} | :lost | {:error, term()}

  @doc "Hand credential `id`'s token to one consumer (an element of `spec.consumers`)."
  @callback deliver(Context.t(), consumer :: term(), id :: String.t(), Secret.t()) ::
              :ok | {:error, term()}

  @doc "A consumer's stable, non-secret name: recorded in the state and in failures."
  @callback consumer_name(consumer :: term()) :: String.t()

  @doc "See `c:AshVault.Macaroon.Rotation.Source.describe_error/1`."
  @callback describe_error(term()) :: String.t() | nil

  @optional_callbacks describe_error: 1
end
