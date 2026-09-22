defmodule AshVault.Erasure do
  @moduledoc """
  The record of a completed crypto-erasure: what was erased, and when.

  Returned by the generic `destroy` key-lifecycle action
  (`AshVault.Actions.DestroyKeys`), which is the one AshVault operation whose *having
  happened* is the thing an auditor asks about later.

  It exists because the action used to return `:ok` — and, through
  `Ash.run_action/1`'s `{:ok, result}` wrapper, reached callers as the eyebrow-raising
  `{:ok, :ok}`. A bare `true` would have read no better: the useful answer to "did the
  erasure run?" is *which scope, and at what time*, which is exactly what a caller
  otherwise has to reconstruct from the arguments it passed and a clock it read itself.

  The `:scope` is the resolved scope key — the same binary that names the key material
  in the provider, so it is what an operator greps for in OpenBao or in the `Local` key
  root. It is frequently a tenant id and therefore frequently PII; it is returned to the
  caller that asked for this specific scope to be erased, but treat it as you would the
  tenant id itself if you go on to log it. `AshVault.Scope.fingerprint/1` is the
  loggable form.

  `:destroyed_at` is taken after the provider confirms the erasure, never before, so it
  is a time by which the key material was definitely gone rather than a time at which
  the attempt started.
  """

  @typedoc "A completed erasure: the scope that was erased, and when it completed."
  @type t :: %__MODULE__{scope: term(), destroyed_at: DateTime.t()}

  defstruct [:scope, :destroyed_at]
end
