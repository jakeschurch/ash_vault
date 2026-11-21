defmodule AshVault.Macaroon.Rotation.Secret do
  @moduledoc """
  A minted token on its way to a `AshVault.Macaroon.Rotation.Delivery`.

  The only way to the bytes is `reveal/1`, called by the delivery at the moment it
  writes them. `inspect/1` prints `#AshVault.Macaroon.Rotation.Secret<redacted>`, so a
  secret caught in a log line, an error tuple, a crash report or a telemetry handler
  shows nothing. It implements no encoder: `Jason.encode!/1` of a struct holding one
  raises rather than serializing the token.
  """

  @enforce_keys [:value]
  defstruct [:value]

  @opaque t :: %__MODULE__{value: binary()}

  @doc false
  @spec new(binary()) :: t()
  def new(value) when is_binary(value) and value != "", do: %__MODULE__{value: value}

  @doc "The token. Call it only where the token is written to its destination."
  @spec reveal(t()) :: binary()
  def reveal(%__MODULE__{value: value}), do: value

  defimpl Inspect do
    def inspect(_secret, _opts), do: "#AshVault.Macaroon.Rotation.Secret<redacted>"
  end
end
