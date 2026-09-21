defmodule AshVault.Context do
  @moduledoc """
  The non-secret context of a single encrypt or decrypt operation.

  A context identifies *what* is being encrypted — the resource module and the field
  name — plus an opaque bag of Ash-supplied information (`:ash_context`).

  It never contains key material, plaintext or ciphertext.

  `:ash_context` holds the **raw Ash context** handed to a change or calculation —
  `Ash.Resource.Change.Context` or `Ash.Resource.Calculation.Context` — both of which
  carry `:tenant` as a top-level field alongside a `:source_context` map. The crypto core
  assumes no more than "a map, a struct, or `nil`" and never requires a particular struct
  module, so a plain map works too.
  """

  @enforce_keys [:resource, :field]
  defstruct [:resource, :field, :ash_context]

  @type t :: %__MODULE__{resource: module(), field: atom(), ash_context: map() | struct() | nil}
end
