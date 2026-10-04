defmodule AshVault.Macaroon.Caveat do
  @moduledoc """
  Behaviour for a caveat check: decides whether one caveat value admits the request.

      caveat :ip, :string, check: MyApp.Caveats.Ip
      caveat :ip, :string, check: {MyApp.Caveats.Ip, trust_proxy?: true}
      caveat :ip, :string, check: fn ip, ctx -> ctx.context[:remote_ip] == ip end

  `c:check/3` returns `:ok` or `true` to admit, and anything else — `false`,
  `{:error, reason}`, `nil` — to refuse. Refusal is the default for every answer that is
  not an explicit yes.

  ## Checks must only narrow

  Every caveat a token carries must admit the request, so appending a caveat can only
  shrink what the token allows — **provided each check depends only on its own value
  and the request**. A check must never widen access because of its value (an `admin:
  true` caveat that grants more), and must never consult other caveats. That is what
  makes `AshVault.Macaroon.attenuate/2` safe to hand to token holders.

  A check that raises fails the request; it is not rescued.
  """

  @doc "Decide whether `value` admits the request described by `context`."
  @callback check(
              value :: term(),
              context :: AshVault.Macaroon.CheckContext.t(),
              opts :: keyword()
            ) ::
              :ok | boolean() | {:error, term()}

  @doc false
  @spec admits?({module(), keyword()}, term(), AshVault.Macaroon.CheckContext.t()) :: boolean()
  def admits?({module, opts}, value, context) do
    case module.check(value, context, opts) do
      :ok -> true
      true -> true
      _refused -> false
    end
  end
end

defmodule AshVault.Macaroon.Caveat.Function do
  @moduledoc false
  @behaviour AshVault.Macaroon.Caveat

  @impl AshVault.Macaroon.Caveat
  def check(value, context, opts) do
    case Keyword.fetch!(opts, :fun) do
      {module, function, args} -> apply(module, function, [value, context | args])
      fun when is_function(fun, 2) -> fun.(value, context)
    end
  end
end
