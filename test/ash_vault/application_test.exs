defmodule AshVault.ApplicationTest do
  @moduledoc """
  The boot-time crash-dump warning: when it fires, when it must not, and that it says
  what to do.

  A crash dump is process memory on disk — decrypted plaintext, and keys for every
  provider that holds them on the BEAM heap, including scopes that have since been
  crypto-erased. It is outside every protection this library offers, and with
  `ERL_CRASH_DUMP_SECONDS` unset it is what OTP does by default. Two such dumps appeared
  while building this library.

  The counter-risk is a library that nags about host configuration, so the restraint is
  as much under test as the warning: `:prod` only, unset only, suppressible.
  """

  # `async: false`: the suppression test mutates `:ash_vault`'s application environment,
  # which is VM-global.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshVault.Application, as: App

  describe "when the warning fires" do
    test "in prod, with the variable unset and the warning enabled" do
      assert message = App.crash_dump_warning(:prod, nil, true)
      assert message =~ "ERL_CRASH_DUMP_SECONDS is not set"
    end

    test "it names the hazard in terms of this library's own guarantee" do
      message = App.crash_dump_warning(:prod, nil, true)

      assert message =~ "process memory on disk"
      assert message =~ "crypto-erased"
    end

    # A warning that says only "this is dangerous" gets muted. This one has to carry the
    # fix, the alternative, and the off switch.
    test "it says exactly what to do, including the hazard it cannot check" do
      message = App.crash_dump_warning(:prod, nil, true)

      assert message =~ "export ERL_CRASH_DUMP_SECONDS=0"
      assert message =~ "ulimit -c 0"
      assert message =~ "config :ash_vault, warn_on_crash_dumps?: false"
    end
  end

  describe "when it must stay silent" do
    # The whole defence against "presumptuous library". Setting the variable to anything
    # is a decision; the warning is about the absence of one, not about the answer.
    test "the variable being set to anything at all is a decision, and decisions are respected" do
      for value <- ["0", "-1", "30", "", "nonsense"] do
        refute App.crash_dump_warning(:prod, value, true),
               "a set ERL_CRASH_DUMP_SECONDS of #{inspect(value)} must not warn"
      end
    end

    test "dev and test want crash dumps and must never see it" do
      for env <- [:dev, :test, :staging] do
        refute App.crash_dump_warning(env, nil, true)
      end
    end

    test "it is suppressible even in the exact case it was written for" do
      refute App.crash_dump_warning(:prod, nil, false)
    end
  end

  describe "the suppression switch" do
    test "defaults to on" do
      assert App.enabled?()
    end

    test "config turns it off" do
      Application.put_env(:ash_vault, :warn_on_crash_dumps?, false)
      on_exit(fn -> Application.delete_env(:ash_vault, :warn_on_crash_dumps?) end)

      refute App.enabled?()
    end
  end

  describe "the boot hook" do
    test "logs nothing in this suite, which runs in :test" do
      # The compile-time-captured env is `:test` here, so the real entry point is silent
      # no matter what the environment variable says. If this ever fails, every test run
      # in every dependent project just grew a warning.
      log = capture_log(fn -> assert :ok = App.maybe_warn_about_crash_dumps() end)

      refute log =~ "ERL_CRASH_DUMP_SECONDS"
    end
  end
end
