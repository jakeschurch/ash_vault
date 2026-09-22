defmodule AshVault.KeyProviders.OpenBaoClassifyTest do
  @moduledoc """
  The fail-closed tombstone and transit-key classifiers, tested directly.

  These need no server: the bodies below were captured with `curl` against
  `openbao/openbao:2.6.2` (the shapes that decide erasure), plus the shapes an ingress
  or reverse proxy in front of it produces — which are precisely the ones that cannot
  be provoked from a healthy dev server, and precisely the ones that used to fail open.
  """

  use ExUnit.Case, async: true

  alias AshVault.Errors.ProviderUnavailable
  alias AshVault.KeyProviders.OpenBao

  # Verified live: GET /v1/ashvault/data/tombstones/<absent> → 404 {"errors":[]}
  @genuinely_absent %{"errors" => []}

  # Verified live: an existing tombstone → 200 with data.data and data.metadata
  @present %{
    "request_id" => "75c6592e",
    "data" => %{
      "data" => %{"destroyed_at" => "2026-09-22T00:32:29Z"},
      "metadata" => %{"created_time" => "2026-09-22T00:32:29Z", "version" => 1}
    }
  }

  # Verified live: a soft-deleted tombstone → 404 with data.data == nil and metadata
  @soft_deleted %{
    "data" => %{
      "data" => nil,
      "metadata" => %{"deletion_time" => "2026-09-22T00:32:29Z", "version" => 1}
    }
  }

  # Verified live: a missing KV mount → 404, status-identical to "no tombstone here"
  @route_missing %{
    "errors" => ["no handler for route \"nosuchmount/data/tombstones/x\". route entry not found."]
  }

  describe "classify_tombstone/2 — the resurrection direction" do
    test "a genuinely absent secret is the only 404 that means :absent" do
      assert OpenBao.classify_tombstone(404, @genuinely_absent) == :absent
    end

    test "a soft-deleted tombstone counts as destroyed: it existed" do
      assert OpenBao.classify_tombstone(404, @soft_deleted) == :destroyed
    end

    # Finding 2. The provider used to mount the KV engine here and retry — which
    # creates the store EMPTY, so the retry gets the genuine-absence shape and every
    # destroyed tenant resurrects. Auto-provisioning the store that holds your
    # tombstones is fail-open by construction.
    test "a missing KV mount is an outage, never :absent" do
      assert OpenBao.classify_tombstone(404, @route_missing) ==
               {:unavailable, :kv_mount_unavailable}
    end

    # Finding 4, resurrection direction. `errors/1` returned [] for ANY body that was
    # not a parsed JSON map — an ingress HTML 404 during a config reload, a gateway
    # error page — so a destroyed tenant read as intact.
    test "a 404 whose body is not a positively-absent JSON body is an outage" do
      for body <- [
            "<html><head><title>404 Not Found</title></head></html>",
            "",
            nil,
            [],
            %{},
            %{"errors" => nil},
            %{"errors" => ["permission denied"]},
            %{"data" => nil},
            %{"message" => "not found"}
          ] do
        assert {:unavailable, _} = OpenBao.classify_tombstone(404, body),
               "a 404 with body #{inspect(body)} must not read as :absent"
      end
    end
  end

  describe "classify_tombstone/2 — the outage-as-erasure direction" do
    test "a 200 carrying a KV-v2 data map is destroyed" do
      assert OpenBao.classify_tombstone(200, @present) == :destroyed
    end

    # Finding 4, other direction. `status: 200 -> {:error, :destroyed}` with no body
    # check: a proxy answering 200 at the tombstone path made EVERY scope report
    # KeyDestroyed. Fail-closed, but exactly the confusion threat-model §8 forbids.
    test "a 200 that is not a KV-v2 read is an outage, not erasure" do
      for body <- [
            "<html><body>Welcome to nginx</body></html>",
            "OK",
            nil,
            %{},
            %{"data" => nil},
            %{"data" => "ok"},
            %{"errors" => []}
          ] do
        assert {:unavailable, _} = OpenBao.classify_tombstone(200, body),
               "a 200 with body #{inspect(body)} must not read as :destroyed"
      end
    end

    test "every other status is an outage" do
      for status <- [201, 204, 301, 400, 401, 403, 429, 500, 502, 503] do
        assert {:unavailable, _} = OpenBao.classify_tombstone(status, @present)
        assert {:unavailable, _} = OpenBao.classify_tombstone(status, @genuinely_absent)
      end
    end
  end

  describe "classify_transit_key/2" do
    # Finding 5. `destroy/1` decided "there was nothing to delete" by matching the bare
    # substring "not found" on the *config* call, issued before any delete — a string
    # that also appears in policy denials and proxy-surfaced 400s. On a match the
    # delete was never issued, the tombstone was written, and the operator closed the
    # ticket on a key that is still present and still exportable.
    test "absence must be positively identified, never inferred from a message" do
      assert OpenBao.classify_transit_key(404, %{"errors" => []}) == :absent

      assert OpenBao.classify_transit_key(200, %{"data" => %{"latest_version" => 1}}) ==
               :present

      for {status, body} <- [
            {400, %{"errors" => ["could not delete key; not found"]}},
            {400, %{"errors" => ["no existing key named x could be found"]}},
            {403, %{"errors" => ["1 error occurred: permission denied, key not found"]}},
            {400, %{"errors" => ["unknown key"]}},
            {404, "<html>404 not found</html>"},
            {404, %{"errors" => ["permission denied"]}},
            {404, %{}},
            {200, "<html>ok</html>"},
            {502, %{"errors" => []}}
          ] do
        assert {:unavailable, _} = OpenBao.classify_transit_key(status, body),
               "#{status} #{inspect(body)} must not be read as a definite key state"
      end
    end

    test "a missing transit mount is an outage, not an absent key" do
      assert OpenBao.classify_transit_key(404, @route_missing) ==
               {:unavailable, :transit_mount_unavailable}
    end
  end

  describe "created_at/2 (finding 11)" do
    # OpenBao fabricated `created_at: DateTime.utc_now()` whenever the metadata was
    # missing or unparseable. A key that is always "created now" is never older than a
    # max_age, so age-based rotation never fires and nothing logs.
    # AshVault.KeyProviders.Local explicitly refuses the same fabrication.
    test "real metadata is read, in whole unix seconds" do
      meta = %{"latest_version" => 2, "keys" => %{"1" => 1_700_000_000, "2" => 1_700_000_060}}

      assert {:ok, first} = OpenBao.created_at(meta, 1)
      assert {:ok, second} = OpenBao.created_at(meta, 2)
      assert DateTime.to_unix(first) == 1_700_000_000
      assert DateTime.compare(second, first) == :gt
    end

    test "the ISO-8601 `creation_time` shape is read too" do
      meta = %{"keys" => %{"1" => %{"creation_time" => "2024-01-01T00:00:00Z"}}}

      assert {:ok, ~U[2024-01-01 00:00:00Z]} = OpenBao.created_at(meta, 1)
    end

    test "missing or unparseable metadata is an error, never a fabricated `now`" do
      for {meta, version} <- [
            {%{}, 1},
            {%{"keys" => %{}}, 1},
            {%{"keys" => %{"1" => 1_700_000_000}}, 2},
            {%{"keys" => %{"1" => nil}}, 1},
            {%{"keys" => %{"1" => "not a time"}}, 1},
            {%{"keys" => %{"1" => %{"creation_time" => "nope"}}}, 1},
            {%{"keys" => %{"1" => %{}}}, 1},
            {%{"keys" => "not a map"}, 1}
          ] do
        assert {:error, %ProviderUnavailable{reason: {:malformed_key_metadata, _}}} =
                 OpenBao.created_at(meta, version),
               "fabricated a timestamp for #{inspect(meta)} version #{inspect(version)}"
      end
    end
  end
end
