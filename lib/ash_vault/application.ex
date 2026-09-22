defmodule AshVault.Application do
  @moduledoc false

  use Application

  # Captured at compile time on purpose. `Mix.env/0` does not exist at runtime in a
  # release, and a dependency compiles under the *consuming* application's `MIX_ENV`, so
  # this is that application's environment, not this library's.
  @env Mix.env()

  @impl true
  def start(_type, _args) do
    maybe_warn_about_crash_dumps()

    children = []

    opts = [strategy: :one_for_one, name: AshVault.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Compiled away entirely outside `:prod`, rather than checked at runtime. A runtime
  # `@env == :prod` leaves the logging branch in a `:test` build as code the compiler can
  # prove unreachable, which is a `--warnings-as-errors` failure in every project that
  # depends on this one.
  if @env == :prod do
    @doc false
    @spec maybe_warn_about_crash_dumps() :: :ok
    def maybe_warn_about_crash_dumps do
      require Logger

      case crash_dump_warning(:prod, System.get_env("ERL_CRASH_DUMP_SECONDS"), enabled?()) do
        nil -> :ok
        message -> Logger.warning(message)
      end
    end
  else
    @doc false
    @spec maybe_warn_about_crash_dumps() :: :ok
    def maybe_warn_about_crash_dumps, do: :ok
  end

  @doc """
  The boot warning text, or `nil` when there is nothing to say.

  Split out from `start/2` so the decision is testable without booting an application
  under a different `Mix.env/0`.

  ## Why this warning exists at all

  A library warning about host configuration is usually presumptuous, and this one was
  weighed against that. Three things decided it:

    * The unsafe state is the **default**. With `ERL_CRASH_DUMP_SECONDS` unset, OTP 29
      writes `erl_crash.dump` on an abnormal termination — verified, not assumed. A
      crash dump is process memory on disk: decrypted plaintext, and key material for
      every provider that holds it on the BEAM heap. That is outside every protection
      this library offers, including crypto-erasure, since a destroyed scope's key
      survives in the dump.
    * It happened **twice while building this library**, in a project whose entire
      subject is key hygiene. Two 11-12 MB dumps, one of them referencing the key
      provider modules.
    * It is one environment variable, and the fix is one line.

  ## What keeps it from being noise

    * It fires **only when the variable is unset** — that is, only when nobody has made a
      decision. An operator who set it to `30` because they need dumps has decided, and
      hears nothing. The warning says "this was never considered", never "your choice is
      wrong".
    * It fires **only in `:prod`**. A development machine legitimately wants dumps, and a
      test run that warned on every boot would train everyone to ignore it.
    * It fires **once**, at boot, and is suppressible:

          config :ash_vault, warn_on_crash_dumps?: false

  What it deliberately does **not** do is check `ulimit -c`. Core dumps are the same
  hazard, but reading the limit is not portable, and a warning that is right about one
  half of a problem and silent about the other teaches the wrong lesson. The message
  points at `documentation/topics/operations.md`, which covers both.
  """
  @spec crash_dump_warning(atom(), String.t() | nil, boolean()) :: String.t() | nil
  def crash_dump_warning(env, crash_dump_seconds, enabled?)

  def crash_dump_warning(_env, _crash_dump_seconds, false), do: nil
  def crash_dump_warning(env, _crash_dump_seconds, _enabled?) when env != :prod, do: nil
  def crash_dump_warning(_env, value, _enabled?) when is_binary(value), do: nil

  def crash_dump_warning(_env, nil, true) do
    """
    AshVault: ERL_CRASH_DUMP_SECONDS is not set, so this node will write an \
    erl_crash.dump if it terminates abnormally.

    A crash dump is process memory on disk. It can contain decrypted plaintext and, for \
    any key provider that holds key material on the BEAM heap, the keys themselves — \
    including keys for scopes that have since been crypto-erased. Nothing in AshVault \
    protects a value once it is in that file.

    To turn crash dumps off, before the VM starts:

        export ERL_CRASH_DUMP_SECONDS=0
        ulimit -c 0            # core dumps are the same hazard; AshVault cannot check this

    If you need crash dumps, set ERL_CRASH_DUMP_SECONDS to the number of seconds you \
    want to allow and treat the file with the care you give the key material itself. \
    Setting it at all silences this warning: it fires only when neither choice has been \
    made.

    See "Crash dumps and core dumps" in the AshVault operations guide. To silence this \
    warning without changing anything:

        config :ash_vault, warn_on_crash_dumps?: false
    """
  end

  @doc false
  @spec enabled?() :: boolean()
  def enabled?, do: Application.get_env(:ash_vault, :warn_on_crash_dumps?, true)
end
