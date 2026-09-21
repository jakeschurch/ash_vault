defmodule AshVault.Context do
  @moduledoc """
  The non-secret context of a single encrypt or decrypt operation.

  A context identifies *what* is being encrypted — the resource module and the field
  name — plus an opaque bag of Ash-supplied information (`:ash_context`).

  It never contains key material, plaintext or ciphertext.

  The Ash integration layer puts at least
  `%{tenant: term(), actor: term(), context: map()}` into `:ash_context`, but the crypto
  core assumes nothing beyond "a map, or `nil`".
  """

  @enforce_keys [:resource, :field]
  defstruct [:resource, :field, :ash_context]

  @type t :: %__MODULE__{resource: module(), field: atom(), ash_context: map() | nil}
end
