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

  test "the default build uses the precompiled NIF" do
    assert Native.precompiled?(),
           """
           AshVaultRustler.Native is compiling from source by default.

           Since v0.1.0 the default is the precompiled artifact, so that a consumer
           without a Rust toolchain can use this package. If you turned it off
           deliberately, update this test; if not, @precompiled_by_default in
           lib/ash_vault_rustler/native.ex has been changed.

           A source build is still available per-machine with
           ASH_VAULT_RUSTLER_BUILD=1, which is what CI uses.
           """
  end

  test "the checksum file is committed, which is the other half of the switch" do
    # `RustlerPrecompiled` refuses a downloaded artifact without it, so the file being
    # present and the switch being on have to move together. Deleting it breaks every
    # consumer without a Rust toolchain, and nothing else in the suite would notice.
    assert File.exists?(
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
