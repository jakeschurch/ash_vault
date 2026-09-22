defmodule AshVault.TelemetryTest.Actor do
  @moduledoc "An actor shaped like a real one: an id, and two things that must not leak."
  defstruct [:id, :email, :hashed_password]
end

defmodule AshVault.TelemetryTest do
  @moduledoc """
  AshVault's answer to ash_cloak's `on_decrypt` hook.

  The point of these events is a compliance audit log, so the test is in two halves:
  the metadata must carry *enough* (who, what resource, what field, when, what outcome),
  and it must carry *nothing else* — no plaintext, no ciphertext, no key material, and no
  actor beyond an identifier.

  The "nothing else" half deep-walks the entire metadata term rather than checking named
  keys, because the failure mode being guarded against is a secret arriving nested inside
  a struct somebody added to the metadata later.
  """

  # Not async: the vault talks to the default-named Memory provider.
  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Memory
  alias AshVault.TelemetryTest.Actor
  alias AshVault.Test.EtsUser
  alias AshVault.Test.Vault

  @events for prefix <- [
                [:ash_vault, :encrypt],
                [:ash_vault, :decrypt],
                [:ash_vault, :key, :rotate],
                [:ash_vault, :key, :destroy]
              ],
              suffix <- [:start, :stop, :exception],
              do: prefix ++ [suffix]

  @plaintext "ssn-987-65-4321"
  @tenant "acme"

  @actor %AshVault.TelemetryTest.Actor{
    id: "actor-0001",
    email: "auditor@example.com",
    hashed_password: "$2b$12$NOTAREALHASHBUTSTILLSECRET"
  }

  setup do
    start_supervised!({Memory, name: Memory})

    handler = "ash-vault-telemetry-test-#{System.unique_integer([:positive])}"
    test = self()

    :telemetry.attach_many(
      handler,
      @events,
      fn event, measurements, metadata, _config ->
        send(test, {:telemetry, event, measurements, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler) end)
    :ok
  end

  defp drain(acc \\ []) do
    receive do
      {:telemetry, event, measurements, metadata} ->
        drain([{event, measurements, metadata} | acc])
    after
      0 -> Enum.reverse(acc)
    end
  end

  # `drain/1` empties the mailbox, so it may only be called once per assertion pass.
  # Everything drained is accumulated here instead, and the accumulator is what the
  # assertions filter.
  defp captured do
    events = Process.get(:captured, []) ++ drain()
    Process.put(:captured, events)
    events
  end

  # Forget everything emitted so far — used after setup steps whose events are not what
  # the test is about.
  defp clear! do
    drain()
    Process.put(:captured, [])
    :ok
  end

  defp events_named(name), do: Enum.filter(captured(), fn {event, _, _} -> event == name end)

  defp only(name) do
    assert [{^name, measurements, metadata}] = events_named(name)
    {measurements, metadata}
  end

  # Collect every binary anywhere in a term: inside lists, tuples, map keys, map values
  # and struct fields. A shallow `refute metadata[:x] == secret` would not catch a secret
  # that arrived nested, which is the whole failure mode here.
  defp all_binaries(term, acc \\ [])
  defp all_binaries(term, acc) when is_binary(term), do: [term | acc]

  defp all_binaries(%_struct{} = term, acc) do
    term |> Map.from_struct() |> all_binaries(acc)
  end

  defp all_binaries(term, acc) when is_map(term) do
    Enum.reduce(term, acc, fn {key, value}, acc -> all_binaries(value, all_binaries(key, acc)) end)
  end

  defp all_binaries(term, acc) when is_list(term), do: Enum.reduce(term, acc, &all_binaries/2)

  defp all_binaries(term, acc) when is_tuple(term) do
    term |> Tuple.to_list() |> all_binaries(acc)
  end

  defp all_binaries(_term, acc), do: acc

  defp refute_leaks(metadata, secrets) do
    found = all_binaries(metadata)

    for secret <- secrets, is_binary(secret), byte_size(secret) > 0, leak <- found do
      refute String.contains?(leak, secret),
             """
             telemetry metadata leaked a secret.

               secret:   #{inspect(secret, limit: 10, printable_limit: 64)}
               found in: #{inspect(leak, limit: 10, printable_limit: 64)}
               metadata: #{inspect(metadata, limit: 20, printable_limit: 64)}
             """
    end

    # An actor struct in the metadata would be a leak even if its fields happened to be
    # empty on this run.
    refute Enum.any?(Map.values(metadata), &match?(%Actor{}, &1))
  end

  # After a destroy there is no key to check against any more; `refute_leaks/2` skips the
  # nil, and the tests that care capture the key before destroying it.
  defp secrets do
    key =
      case Memory.current_key(@tenant) do
        {:ok, %{key: key}} -> key
        _other -> nil
      end

    [@plaintext, @actor.email, @actor.hashed_password, key]
  end

  defp create! do
    EtsUser
    |> Ash.Changeset.for_create(:create, %{org_id: @tenant, name: "n", ssn: @plaintext},
      tenant: @tenant,
      actor: @actor
    )
    |> Ash.create!(actor: @actor)
  end

  defp lifecycle_context do
    %AshVault.Context{
      resource: EtsUser,
      field: :__key_lifecycle__,
      ash_context: %{tenant: @tenant, actor: @actor, phase: :write, source_context: %{}}
    }
  end

  describe "[:ash_vault, :encrypt]" do
    test "spans the write and carries who/what/outcome" do
      create!()

      {start_measurements, start_metadata} = only([:ash_vault, :encrypt, :start])
      {stop_measurements, stop_metadata} = only([:ash_vault, :encrypt, :stop])

      assert is_integer(start_measurements.system_time)
      assert is_integer(stop_measurements.duration)

      assert start_metadata.resource == EtsUser
      assert start_metadata.field == :ssn
      assert start_metadata.phase == :write
      assert start_metadata.actor_type == Actor
      assert start_metadata.actor_id == "actor-0001"

      assert stop_metadata.result == :ok
      refute Map.get(stop_metadata, :error)
    end

    test "leaks neither plaintext, ciphertext, key material nor the actor" do
      record = create!()
      secrets = [Map.get(record, :encrypted_ssn) | secrets()]

      for {_event, _measurements, metadata} <- captured(), do: refute_leaks(metadata, secrets)
    end
  end

  describe "[:ash_vault, :decrypt]" do
    test "spans the read and names the vault" do
      record = create!()
      clear!()

      assert %{ssn: @plaintext} =
               EtsUser
               |> Ash.get!(record.id, tenant: @tenant, actor: @actor)
               |> Ash.load!([:ssn], tenant: @tenant, actor: @actor)

      {_, metadata} = only([:ash_vault, :decrypt, :stop])

      assert metadata.resource == EtsUser
      assert metadata.field == :ssn
      assert metadata.phase == :read
      assert metadata.vault == Vault
      assert metadata.actor_id == "actor-0001"
      assert metadata.result == :ok
    end

    test "leaks nothing on the read path either" do
      record = create!()
      clear!()

      EtsUser
      |> Ash.get!(record.id, tenant: @tenant, actor: @actor)
      |> Ash.load!([:ssn], tenant: @tenant, actor: @actor)

      secrets = [Map.get(record, :encrypted_ssn) | secrets()]

      for {_event, _measurements, metadata} <- captured(), do: refute_leaks(metadata, secrets)
    end

    test "a failure is a :stop with result: :error, and only the error MODULE" do
      record = create!()
      :ok = AshVault.destroy_keys!(Vault, @tenant)
      clear!()

      assert {:error, _} =
               EtsUser
               |> Ash.get!(record.id, tenant: @tenant, actor: @actor)
               |> Ash.load([:ssn], tenant: @tenant, actor: @actor)

      {_, metadata} = only([:ash_vault, :decrypt, :stop])

      # `decrypt_value/5` rescues and returns a value, so a destroyed key is a :stop, not
      # an :exception. A handler that only watched :exception would see nothing.
      assert metadata.result == :error
      assert metadata.error == AshVault.Errors.KeyDestroyed
      assert events_named([:ash_vault, :decrypt, :exception]) == []
      refute_leaks(metadata, secrets())
    end
  end

  describe "[:ash_vault, :key, :rotate]" do
    test "carries the scope and the version it minted" do
      create!()
      clear!()

      assert {:ok, 2} = AshVault.rotate_key!(Vault, @tenant, lifecycle_context())

      {_, start_metadata} = only([:ash_vault, :key, :rotate, :start])
      {measurements, metadata} = only([:ash_vault, :key, :rotate, :stop])

      assert start_metadata.scope == @tenant
      assert start_metadata.key_version == nil

      assert is_integer(measurements.duration)
      assert metadata.scope == @tenant
      assert metadata.vault == Vault
      assert metadata.key_version == 2
      assert metadata.result == :ok
      assert metadata.actor_id == "actor-0001"

      refute_leaks(metadata, secrets())
    end

    test "works without a context, for the mix-task path" do
      create!()
      clear!()

      assert {:ok, 2} = AshVault.rotate_key!(Vault, @tenant)

      {_, metadata} = only([:ash_vault, :key, :rotate, :stop])
      assert metadata.scope == @tenant
      assert metadata.actor_id == nil
      assert metadata.actor_type == nil
    end
  end

  describe "[:ash_vault, :key, :destroy]" do
    test "the compliance-critical event fires, with actor, scope and outcome" do
      create!()
      secrets = secrets()
      clear!()

      assert :ok = AshVault.destroy_keys!(Vault, @tenant, lifecycle_context())

      assert [{_, _, _}] = events_named([:ash_vault, :key, :destroy, :start])
      {measurements, metadata} = only([:ash_vault, :key, :destroy, :stop])

      assert is_integer(measurements.duration)
      assert metadata.scope == @tenant
      assert metadata.vault == Vault
      assert metadata.result == :ok
      assert metadata.actor_type == Actor
      assert metadata.actor_id == "actor-0001"

      # The key is gone; the record that it was destroyed must not contain it.
      refute_leaks(metadata, secrets)
    end

    test "carries the raw scope AND a fingerprint, and the two agree" do
      create!()
      clear!()

      assert :ok = AshVault.destroy_keys!(Vault, @tenant, lifecycle_context())

      {_, metadata} = only([:ash_vault, :key, :destroy, :stop])

      # The raw scope stays, deliberately: a compliance record of an erasure has to be
      # able to name the tenant it erased, and a fingerprint cannot. The fingerprint is
      # there so a handler forwarding to an APM has something safe to forward — a
      # convenience, not a mitigation. See `AshVault.Telemetry`.
      assert metadata.scope == @tenant
      assert metadata.scope_fingerprint == AshVault.Scope.fingerprint(@tenant)
      assert metadata.scope_fingerprint =~ ~r/^sha256:[0-9a-f]{12}$/
      refute metadata.scope_fingerprint =~ @tenant
    end

    test "rotate carries the fingerprint too" do
      create!()
      clear!()

      assert {:ok, 2} = AshVault.rotate_key!(Vault, @tenant, lifecycle_context())

      {_, metadata} = only([:ash_vault, :key, :rotate, :stop])
      assert metadata.scope == @tenant
      assert metadata.scope_fingerprint == AshVault.Scope.fingerprint(@tenant)
    end

    test "a raise inside the span is an :exception, and there is no :stop" do
      create!()
      :ok = AshVault.destroy_keys!(Vault, @tenant)
      clear!()

      assert_raise AshVault.Errors.KeyDestroyed, fn ->
        AshVault.rotate_key!(Vault, @tenant, lifecycle_context())
      end

      assert [{_, measurements, metadata}] = events_named([:ash_vault, :key, :rotate, :exception])
      assert events_named([:ash_vault, :key, :rotate, :stop]) == []

      assert is_integer(measurements.duration)
      assert metadata.kind == :error
      assert %AshVault.Errors.KeyDestroyed{} = metadata.reason
      assert metadata.scope == @tenant
      assert metadata.actor_id == "actor-0001"

      # `:reason` and `:stacktrace` are `:telemetry.span/3`'s own contract for the
      # `:exception` event, so the error struct IS in this one event's metadata. It must
      # still hold no plaintext, no ciphertext and no key material.
      refute_leaks(metadata, secrets())
    end
  end

  describe "actor_identity/1" do
    test "never lets a non-scalar id through" do
      assert %{actor_type: Actor, actor_id: nil} =
               AshVault.Telemetry.actor_identity(%Actor{id: %{nested: "id"}})
    end

    test "reduces a struct to its module and id" do
      assert %{actor_type: Actor, actor_id: "actor-0001"} =
               AshVault.Telemetry.actor_identity(@actor)
    end

    test "handles bare maps, scalars, nil and anything else" do
      assert %{actor_type: :map, actor_id: 7} = AshVault.Telemetry.actor_identity(%{id: 7})

      assert %{actor_type: :scalar, actor_id: "system"} =
               AshVault.Telemetry.actor_identity("system")

      assert %{actor_type: nil, actor_id: nil} = AshVault.Telemetry.actor_identity(nil)
      assert %{actor_type: :unknown, actor_id: nil} = AshVault.Telemetry.actor_identity({:a, :b})
    end
  end

  describe "result_metadata/1" do
    test "keeps the error module and nothing else" do
      error = AshVault.Errors.MissingScope.exception(tenant: "a secret description")

      assert %{result: :error, error: AshVault.Errors.MissingScope} =
               AshVault.Telemetry.result_metadata({:error, error})
    end
  end
end
