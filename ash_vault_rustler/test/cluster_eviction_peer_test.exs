defmodule AshVaultRustler.ClusterEvictionPeerTest do
  @moduledoc """
  `AshVault.KeyProviders.Cached.evict_scope/2` driven across a **real** cluster.

  `AshVaultRustler.ClusterEvictionTest` covers `classify_evictions/2` against every shape
  `:erpc` produces, which is the decision. It cannot cover the four lines that *reach*
  that decision: `Node.list(:connected)` is empty on a single node, so the
  `:erpc.multicall/5` call is skipped entirely in an ordinary run. Those four lines are
  where "reported success while a peer still holds the key" would live, and the whole
  crypto-erasure guarantee of this provider is that they cannot.

  So this file stands up actual peer nodes with `:peer.start_link/1`, connects them, and
  evicts. Each peer runs `AshVaultRustler.Test.EvictStub` as its cache backend — pushed
  over with `:code.load_binary/3` rather than by booting the application there, because
  the property under test is the fan-out, not the cache. The stub reads its answer from
  the peer's own `:persistent_term`, so one peer can acknowledge while another refuses.

  `async: false`, and every node name is randomized: `Node.list(:connected)` is VM-global
  state, and a neighbouring suite's cluster would otherwise be fanned out to as well.
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Cached
  alias AshVaultRustler.Test.EvictStub

  @moduletag :cluster

  @stub EvictStub
  @scope "peer_evict_scope"

  setup_all do
    case ensure_distributed() do
      {:ok, started} ->
        on_exit(fn -> if started, do: :net_kernel.stop() end)
        :ok

      {:error, reason} ->
        # Never a silent skip: if distribution cannot start here, the four lines stay
        # uncovered and whoever reads this output has to know that.
        {:ok, skip_reason: reason}
    end
  end

  setup context do
    if reason = context[:skip_reason] do
      {:ok, skip: "distribution unavailable: #{inspect(reason)}"}
    else
      :ok
    end
  end

  # ── cluster plumbing ──────────────────────────────────────────────────────────────

  defp ensure_distributed do
    if Node.alive?() do
      {:ok, false}
    else
      name = :"ashvault_primary_#{System.unique_integer([:positive])}@127.0.0.1"

      case :net_kernel.start([name, :longnames]) do
        {:ok, _pid} ->
          Node.set_cookie(:ashvault_cluster_eviction_cookie)
          {:ok, true}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # The stub is the only module the peer needs. Pushing the loaded beam directly avoids
  # giving the peer this project's code paths, which would drag in the NIF — and a peer
  # that cannot load the NIF would fail for a reason that has nothing to do with eviction.
  defp start_peer!(opts \\ []) do
    name = :"ashvault_peer_#{System.unique_integer([:positive])}"

    {:ok, pid, node} =
      :peer.start_link(%{
        name: name,
        host: ~c"127.0.0.1",
        longnames: true,
        args: [~c"-setcookie", ~c"ashvault_cluster_eviction_cookie"]
      })

    on_exit(fn -> safe_stop(pid) end)

    unless opts[:without_stub] do
      {_module, binary, filename} = :code.get_object_code(@stub)
      {:module, @stub} = :erpc.call(node, :code, :load_binary, [@stub, filename, binary])
    end

    if answer = opts[:answer] do
      :ok = :erpc.call(node, @stub, :answer, [answer])
    end

    %{pid: pid, node: node}
  end

  defp safe_stop(pid) do
    :peer.stop(pid)
  catch
    _kind, _reason -> :ok
  end

  defp opts(overrides \\ []) do
    %{
      provider: AshVault.KeyProviders.Memory,
      backend: @stub,
      cache_name: :peer_evict_cache,
      ttl: 30_000,
      historical_ttl: 30_000,
      max_entries: 16,
      max_bytes: 4096,
      cluster: true,
      evict_timeout: 2_000
    }
    |> Map.merge(Map.new(overrides))
  end

  # ── the tests ─────────────────────────────────────────────────────────────────────

  describe "evict_scope/2 across a real cluster" do
    test "the multicall path really runs — two peers are connected and both answer" do
      a = start_peer!()
      b = start_peer!()

      # The precondition the single-node suite can never satisfy. Without it the rest of
      # this file would pass by skipping the branch it claims to cover.
      connected = Node.list(:connected)
      assert a.node in connected
      assert b.node in connected

      assert :ok = Cached.evict_scope(@scope, opts())
    end

    test "a peer answering {:error, reason} fails the eviction, named" do
      ok_peer = start_peer!()
      bad_peer = start_peer!(answer: {:error, :cache_unavailable})

      assert {:error, {:nodes_failed, failures}} = Cached.evict_scope(@scope, opts())

      assert failures == [{bad_peer.node, :cache_unavailable}]
      refute Enum.any?(failures, fn {node, _} -> node == ok_peer.node end)
    end

    test "a peer that cannot run the call at all fails the eviction" do
      # The stub is never loaded there, so `:erpc` answers with an `:undef` exception —
      # a node that is reachable but cannot acknowledge. Fail closed.
      silent = start_peer!(without_stub: true)

      assert {:error, {:nodes_failed, failures}} = Cached.evict_scope(@scope, opts())
      assert [{node, reason}] = failures
      assert node == silent.node
      assert match?({:error, {:exception, :undef, _}}, reason)
    end

    test "a peer that does not answer in time fails the eviction" do
      slow = start_peer!(answer: {:sleep, 30_000})

      assert {:error, {:nodes_failed, failures}} =
               Cached.evict_scope(@scope, opts(evict_timeout: 100))

      assert [{node, {:error, {:erpc, :timeout}}}] = failures
      assert node == slow.node
    end

    test "a peer that vanishes mid-flight fails the eviction rather than being skipped" do
      # Killed while it is sleeping inside the call: the node is in `Node.list/1` when
      # the fan-out starts and gone before it answers. This is the case an operator
      # actually hits — a rolling deploy during an erasure.
      doomed = start_peer!(answer: {:sleep, 30_000})

      task = Task.async(fn -> Cached.evict_scope(@scope, opts(evict_timeout: 10_000)) end)

      Process.sleep(200)
      safe_stop(doomed.pid)

      assert {:error, {:nodes_failed, failures}} = Task.await(task, 15_000)
      assert [{node, _reason}] = failures
      assert node == doomed.node
    end

    test "a peer whose eviction raises fails the eviction" do
      angry = start_peer!(answer: :raise)

      assert {:error, {:nodes_failed, failures}} = Cached.evict_scope(@scope, opts())
      assert [{node, {:error, {:exception, :evict_stub_told_to_raise, _stack}}}] = failures
      assert node == angry.node
    end

    test "cluster: false does not fan out, even with peers connected" do
      peer = start_peer!(answer: {:error, :cache_unavailable})
      assert peer.node in Node.list(:connected)

      # The escape hatch has to actually escape: a deployment that has opted out must not
      # be failed by a peer it deliberately ignores.
      assert :ok = Cached.evict_scope(@scope, opts(cluster: false))
    end
  end

  describe "destroy/2 across a real cluster" do
    setup do
      start_supervised!({AshVault.KeyProviders.Memory, name: AshVault.KeyProviders.Memory})
      :ok
    end

    test "a node that does not acknowledge fails the destroy" do
      _bad = start_peer!(answer: {:error, :cache_unavailable})

      assert {:error, {:cache_evict_failed, {:nodes_failed, [_ | _]}}} =
               Cached.destroy("destroy_#{System.unique_integer([:positive])}", opts())
    end

    test "every node acknowledging is what lets a destroy report success" do
      _a = start_peer!()
      _b = start_peer!()

      assert :ok = Cached.destroy("destroy_#{System.unique_integer([:positive])}", opts())
    end
  end
end
