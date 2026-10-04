defmodule AshVault.Macaroon.Ttl do
  @moduledoc """
  Behaviour for a dynamic `default_ttl`: the lifetime of a token, decided at mint time.

      default_ttl MyApp.Macaroons.TtlByPlan
      default_ttl {MyApp.Macaroons.TtlByPlan, enterprise: 90 * 86_400}
      default_ttl fn input -> if input.tenant == "internal", do: 86_400, else: 3_600 end
      max_ttl 90 * 86_400

  `c:ttl/2` receives the mint action's `Ash.ActionInput` (tenant, actor via
  `input.context.private.actor`, arguments) and returns seconds or `:infinity`.

  A dynamic `default_ttl` requires a static `max_ttl`, and the result is always clamped to
  it — a function can never mint a token that outlives `max_ttl`, whatever it returns.
  A result that is neither a positive integer nor `:infinity`, or a raise, refuses the
  mint.
  """

  @doc "The lifetime, in seconds, of the token being minted."
  @callback ttl(input :: Ash.ActionInput.t(), opts :: keyword()) :: pos_integer() | :infinity
end

defmodule AshVault.Macaroon.Ttl.Function do
  @moduledoc false
  @behaviour AshVault.Macaroon.Ttl

  @impl AshVault.Macaroon.Ttl
  def ttl(input, opts) do
    case Keyword.fetch!(opts, :fun) do
      {module, function, args} -> apply(module, function, [input | args])
      fun when is_function(fun, 1) -> fun.(input)
    end
  end
end

defmodule AshVault.Macaroon.KeyWindow do
  @moduledoc """
  Behaviour for a dynamic `accepted_key_versions`: how many recent `:mac` key versions a
  scope accepts, decided at verify time.

      accepted_key_versions MyApp.Macaroons.WindowByTenant
      accepted_key_versions {MyApp.Macaroons.WindowByTenant, default: 1}
      accepted_key_versions {MyApp.Macaroons, :window, []}   # MFA, called with scope first

  A module (optionally with opts) or an MFA, never an inline function: the window is a
  security boundary evaluated for every verification, and belongs in named, testable code.

  `c:accepted_key_versions/2` receives the token's scope and returns a positive integer
  or `:all`. Anything else — or a raise — **fails closed to `1`**: only the current key
  version is accepted.
  """

  @doc "The number of recent `:mac` key versions `scope` accepts, or `:all`."
  @callback accepted_key_versions(scope :: binary(), opts :: keyword()) :: pos_integer() | :all
end
