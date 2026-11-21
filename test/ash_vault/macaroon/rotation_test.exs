defmodule AshVault.Macaroon.RotationTest do
  # Not async: the key provider is the default-named Memory and the world is a named
  # Agent.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshVault.KeyProviders.Memory
  alias AshVault.Macaroon.Rotation
  alias AshVault.Macaroon.Rotation.{Secret, Spec, State}
  alias AshVault.Test.RotatedCredential
  alias AshVault.Test.Rotation.World

  @day 86_400
  @ref "ns/pr-farm"
  @events [:reconciled, :status, :failure, :minted, :promoted, :retired]

  setup do
    start_supervised!({Memory, name: Memory})
    start_supervised!({World, %{@ref => spec()}})
    :ok
  end

  defp spec(overrides \\ []) do
    struct!(
      %Spec{
        attributes: %{label: "rotation " <> @ref},
        caveats: %{},
        lifetime: 30 * @day,
        quiet_period: 3600,
        consumers: [%{name: "nix-csi/pr"}, %{name: "argo/ci"}]
      },
      overrides
    )
  end

  defp reconcile(now) do
    :ok = Rotation.run(RotatedCredential, :cred, now: now)
    World.state(@ref)
  end

  defp token(name) do
    {_id, token} = World.copy(name)
    token
  end

  defp verifies?(token) do
    match?({:ok, %RotatedCredential{}}, RotatedCredential.cred_by_token(token, authorize?: false))
  end

  defp row(id), do: Ash.get!(RotatedCredential, id, authorize?: false)
  defp rows, do: Ash.read!(RotatedCredential, authorize?: false)

  defp touch(id, at) do
    id |> row() |> Ash.Changeset.for_update(:touch, %{last_used_at: at}) |> Ash.update!()
  end

  defp time(value) do
    {:ok, at, _} = DateTime.from_iso8601(value)
    at
  end

  describe "the cycle" do
    test "bootstrap mints, stages and delivers; the state holds ids and times only" do
      now = DateTime.utc_now()
      state = reconcile(now)

      assert state["phase"] == "Ready"
      id = state["current"]["id"]
      assert state["pending"] == nil and state["previous"] == nil and state["failure"] == nil
      assert {^id, _} = World.copy("nix-csi/pr")
      assert {^id, _} = World.copy("argo/ci")
      assert token("nix-csi/pr") == token("argo/ci")
      assert verifies?(token("nix-csi/pr"))
      assert Map.keys(state["current"]["delivered"]) |> Enum.sort() == ["argo/ci", "nix-csi/pr"]

      assert_in_delta DateTime.diff(time(state["current"]["rotateAt"]), now), 20 * @day, 1
      assert_in_delta DateTime.diff(time(state["current"]["expiresAt"]), now), 30 * @day, 1
      refute inspect(state) =~ token("argo/ci")
      assert row(id).label == "rotation " <> @ref
    end

    test "nothing is minted before two thirds of the lifetime" do
      now = DateTime.utc_now()
      first = reconcile(now)
      second = reconcile(DateTime.add(now, 19 * @day))
      assert second["current"]["id"] == first["current"]["id"]
      assert second["phase"] == "Ready"
      assert length(rows()) == 1
    end

    test "at two thirds a successor is delivered; both stay valid through the overlap" do
      now = DateTime.utc_now()
      old = reconcile(now)["current"]["id"]
      old_token = token("nix-csi/pr")

      state = reconcile(DateTime.add(now, 20 * @day + 60))
      new = state["current"]["id"]

      assert new != old
      assert state["previous"]["id"] == old
      assert state["previous"]["supersededAt"]
      assert state["phase"] == "Rotating"
      assert token("nix-csi/pr") != old_token
      assert verifies?(token("nix-csi/pr"))
      assert verifies?(old_token)
    end

    test "the predecessor is revoked only once it went unused for the quiet period" do
      now = DateTime.utc_now()
      old = reconcile(now)["current"]["id"]
      old_token = token("nix-csi/pr")
      rotated = DateTime.add(now, 20 * @day + 60)
      reconcile(rotated)

      in_use = DateTime.add(rotated, 50 * 60)
      touch(old, in_use)

      state = reconcile(DateTime.add(rotated, 70 * 60))
      assert state["previous"]["id"] == old
      assert state["previous"]["inUse"] == true
      assert is_nil(row(old).revoked_at)

      state = reconcile(DateTime.add(in_use, 61 * 60))
      assert state["previous"] == nil
      assert state["phase"] == "Ready"
      refute is_nil(row(old).revoked_at)
      assert old in World.get(:revoked)
      refute verifies?(old_token)
      assert verifies?(token("nix-csi/pr"))
    end

    test "a predecessor that expired on its own is dropped" do
      now = DateTime.utc_now()
      old = reconcile(now)["current"]["id"]
      rotated = DateTime.add(now, 20 * @day + 60)
      reconcile(rotated)
      touch(old, DateTime.add(now, 31 * @day))

      state = reconcile(DateTime.add(now, 31 * @day))
      assert state["previous"] == nil
    end

    test "a credential revoked out of band is replaced at once" do
      now = DateTime.utc_now()
      id = reconcile(now)["current"]["id"]
      id |> row() |> Ash.Changeset.for_update(:revoke, %{}) |> Ash.update!()

      state = reconcile(DateTime.add(now, 60))
      assert state["current"]["id"] != id
      refute World.copy("argo/ci") |> elem(0) == id
    end

    test "a consumer added later is handed the current credential" do
      now = DateTime.utc_now()
      id = reconcile(now)["current"]["id"]

      World.update(:specs, fn specs ->
        Map.put(
          specs,
          @ref,
          spec(consumers: [%{name: "nix-csi/pr"}, %{name: "argo/ci"}, %{name: "new/one"}])
        )
      end)

      state = reconcile(DateTime.add(now, 60))
      assert state["current"]["id"] == id
      assert {^id, _} = World.copy("new/one")
      assert state["failure"] == nil
    end

    test "the generated rotate action reconciles" do
      assert {:ok, true} =
               RotatedCredential
               |> Ash.ActionInput.for_action(:rotate, %{})
               |> Ash.run_action()

      assert World.state(@ref)["phase"] == "Ready"
    end
  end

  describe "failures never leave consumers without a valid token" do
    test "a failed issue changes nothing" do
      World.update(:specs, &Map.put(&1, @ref, spec(attributes: %{label: "refuse"})))
      state = reconcile(DateTime.utc_now())
      assert state["failure"]["reason"] == "Mint"
      assert state["phase"] == "Failed"
      assert state["current"] == nil
      assert rows() == []
    end

    test "a failed issue at rotation keeps the current credential" do
      now = DateTime.utc_now()
      current = reconcile(now)["current"]["id"]
      World.update(:specs, &Map.put(&1, @ref, spec(attributes: %{label: "refuse"})))

      state = reconcile(DateTime.add(now, 21 * @day))
      assert state["current"]["id"] == current
      assert state["pending"] == nil
      assert state["failure"]["reason"] == "Mint"
      assert state["phase"] == "Ready"
      assert verifies?(token("argo/ci"))
    end

    test "a failed staging keeps the current credential and revokes the orphan" do
      now = DateTime.utc_now()
      current = reconcile(now)["current"]["id"]

      World.fail([:stage])
      state = reconcile(DateTime.add(now, 21 * @day))
      assert state["current"]["id"] == current
      assert state["pending"] == nil
      assert state["failure"]["reason"] == "Staging"

      orphans = Enum.reject(rows(), &(&1.id == current))
      assert orphans != [] and Enum.all?(orphans, &(not is_nil(&1.revoked_at)))
      assert verifies?(token("argo/ci"))
    end

    test "an undelivered consumer holds the rotation at pending; only it is retried" do
      now = DateTime.utc_now()
      current = reconcile(now)["current"]["id"]
      old_token = token("argo/ci")

      World.fail([{:deliver, "argo/ci"}])
      later = DateTime.add(now, 21 * @day)
      state = reconcile(later)
      pending = state["pending"]["id"]
      assert state["current"]["id"] == current
      assert state["failure"]["reason"] == "Distribution"
      assert state["failure"]["message"] =~ "argo/ci"
      refute state["failure"]["message"] =~ "nix-csi/pr"
      assert Map.keys(state["pending"]["delivered"]) == ["nix-csi/pr"]
      assert {^pending, _} = World.copy("nix-csi/pr")
      assert verifies?(old_token)

      # The delivered consumer is not written again.
      World.update(:copies, &Map.put(&1, "nix-csi/pr", {pending, "marker"}))
      World.fail([])
      state = reconcile(DateTime.add(later, 60))
      assert state["current"]["id"] == pending
      assert state["previous"]["id"] == current
      assert state["failure"] == nil
      assert World.copy("nix-csi/pr") == {pending, "marker"}
    end

    test "unreadable staging retries without revoking" do
      now = DateTime.utc_now()
      reconcile(now)
      World.fail([:staged])
      state = reconcile(DateTime.add(now, 21 * @day))
      pending = state["pending"]["id"]
      assert state["failure"]["reason"] == "Distribution"
      assert is_nil(row(pending).revoked_at)
    end

    test "staging that lost the pending token revokes it and mints again" do
      now = DateTime.utc_now()
      reconcile(now)
      World.fail([{:deliver, "nix-csi/pr"}])
      later = DateTime.add(now, 21 * @day)
      lost = reconcile(later)["pending"]["id"]

      World.update(:staging, &Map.delete(&1, @ref))
      World.fail([])
      state = reconcile(DateTime.add(later, 60))
      refute is_nil(row(lost).revoked_at)
      assert state["failure"]["reason"] == "StagingLost"
      assert state["pending"] == nil

      state = reconcile(DateTime.add(later, 120))
      assert state["current"]["id"] not in [nil, lost]
      assert state["failure"] == nil
    end

    test "an invalid spec is reported, not acted on" do
      World.update(:specs, &Map.put(&1, @ref, {:invalid, "lifetimeDays must be 1..90"}))
      state = reconcile(DateTime.utc_now())

      assert state["failure"] == %{
               "reason" => "InvalidSpec",
               "message" => "lifetimeDays must be 1..90",
               "time" => state["failure"]["time"]
             }

      assert rows() == []

      World.update(:specs, &Map.put(&1, @ref, spec(lifetime: 400 * @day)))
      state = reconcile(DateTime.utc_now())
      assert state["failure"]["reason"] == "InvalidSpec"
      assert state["failure"]["message"] =~ "max_ttl"

      World.update(:specs, &Map.put(&1, @ref, spec(consumers: [])))
      assert reconcile(DateTime.utc_now())["failure"]["reason"] == "InvalidSpec"
      assert rows() == []
    end

    test "a failed save is reported and the next reconcile starts from the last saved state" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:ash_vault, :macaroon, :rotation, :failure]
        ])

      World.fail([:save])
      :ok = Rotation.run(RotatedCredential, :cred, now: DateTime.utc_now())
      assert_received {_, ^ref, %{count: 1}, %{reason: :status, rotation: @ref}}
      assert World.state(@ref) == nil
    end

    test "a failed list is an error" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:ash_vault, :macaroon, :rotation, :failure]
        ])

      World.fail([:list])
      assert {:error, _} = Rotation.run(RotatedCredential, :cred)
      assert_received {_, ^ref, %{count: 1}, %{reason: :list, rotation: "*"}}

      assert {:ok, false} =
               RotatedCredential
               |> Ash.ActionInput.for_action(:rotate, %{})
               |> Ash.run_action()
    end
  end

  describe "telemetry and secrecy" do
    test "status measurements per credential" do
      ref =
        :telemetry_test.attach_event_handlers(self(), [
          [:ash_vault, :macaroon, :rotation, :status]
        ])

      reconcile(DateTime.utc_now())

      assert_received {_, ^ref,
                       %{healthy: 1, pending: 0, predecessor_in_use: 0, expires_in: expires},
                       %{rotation: @ref, macaroon: :cred, resource: RotatedCredential}}

      assert_in_delta expires, 30 * @day, 2
    end

    test "no token reaches logs, telemetry or the saved state" do
      events = for event <- @events, do: [:ash_vault, :macaroon, :rotation, event]
      ref = :telemetry_test.attach_event_handlers(self(), events)
      now = DateTime.utc_now()

      log =
        capture_log([level: :debug], fn ->
          reconcile(now)
          World.fail([{:deliver, "argo/ci"}])
          reconcile(DateTime.add(now, 21 * @day))
          World.fail([:stage])
          World.update(:copies, &Map.delete(&1, "argo/ci"))
        end)

      tokens = for {_name, {_id, token}} <- World.get(:copies), do: token
      assert tokens != []

      received = collect(ref, [])
      assert length(received) > 4

      for token <- tokens do
        refute log =~ token
        refute inspect(received) =~ token
        refute inspect(World.get(:states)) =~ token
      end
    end

    test "a secret never inspects to its value" do
      secret = Secret.new("avrot_supersecret")
      refute inspect(secret) =~ "supersecret"
      refute inspect({:error, %{secret: secret}}) =~ "supersecret"
      assert Secret.reveal(secret) == "avrot_supersecret"
      assert_raise Protocol.UndefinedError, fn -> Jason.encode!(%{s: secret}) end
    end
  end

  describe "state" do
    test "round-trips through the stored form, which clears what is gone" do
      now = DateTime.utc_now()
      reconcile(now)
      stored = World.state(@ref)
      assert stored |> State.from_map() |> State.to_map() == stored
      assert Map.has_key?(stored, "pending") and Map.has_key?(stored["current"], "supersededAt")
      assert State.from_map(nil) == %State{}
    end
  end

  defp collect(ref, acc) do
    receive do
      {_event, ^ref, measurements, metadata} -> collect(ref, [{measurements, metadata} | acc])
    after
      0 -> acc
    end
  end
end
