defmodule AshVaultRustler.PrecompiledSwitchTest do
  @moduledoc """
  The `rustler_precompiled` switch is wired but off, and must stay off until a release
  exists.

  Pointing `base_url` at a release that is not published does not fail at release time —
  it fails at *every consumer's* `mix compile`, as a NIF that cannot be downloaded and
  was not built. This file is the tripwire: flipping `@precompiled_by_default` in
  `AshVaultRustler.Native` without the rest of the checklist in `README.md` fails here
  first, in this repository, rather than in somebody else's build.

  When the first release genuinely ships, the assertions below are what you update — and
  updating them should feel like the deliberate act it is.
  """

  use ExUnit.Case, async: true

  alias AshVaultRustler.Native

  test "the default build is still from source" do
    refute Native.precompiled?(),
           """
           AshVaultRustler.Native is compiled against rustler_precompiled.

           If that is deliberate, work through "Releasing a precompiled NIF" in
           ash_vault_rustler/README.md — in particular, a committed
           checksum-Elixir.AshVaultRustler.Native.exs and a published release at the
           base_url — and then update this test.

           If it is not deliberate, ASH_VAULT_RUSTLER_PRECOMPILED is set in this shell.
           """
  end

  test "the checksum file is absent, which is the other half of why the switch is off" do
    # `RustlerPrecompiled` will not use a downloaded artifact without it, so its absence
    # and the switch being off have to move together.
    refute File.exists?(
             Path.join(__DIR__, "../checksum-Elixir.AshVaultRustler.Native.exs")
             |> Path.expand()
           )
  end

  test "the target list is the one the release workflow builds" do
    # The workflow's matrix and this list are two copies of one fact. A target here that
    # CI does not build is a download error for whoever runs it; a target CI builds that
    # is not here is a wasted job. Read from the workflow so they cannot drift silently.
    workflow =
      Path.join(__DIR__, "../../.github/workflows/nif-release.yml")
      |> Path.expand()
      |> File.read!()

    for target <- Native.targets() do
      assert workflow =~ target,
             "#{target} is in AshVaultRustler.Native but not built by nif-release.yml"
    end
  end
end
