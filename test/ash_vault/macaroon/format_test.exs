defmodule AshVault.Macaroon.FormatTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias AshVault.Macaroon
  alias AshVault.Macaroon.CaveatCodec
  alias AshVault.Macaroon.Chain
  alias AshVault.Macaroon.Envelope
  alias AshVault.Macs.HmacSha256

  @key <<1::256>>
  @aad "ashvault:v1|acme|AshVault.Test.ApiClient|macaroon:api"
  @expires ~U[2030-01-01 00:00:00.000000Z]

  defp vector_token do
    {:ok, expires} = CaveatCodec.encode("expires_at", :datetime, @expires)
    {:ok, ip} = CaveatCodec.encode("ip", :string, "1.2.3.4")

    env = %Envelope{
      prefix: "avtest",
      scope: "acme",
      key_version: 1,
      id: "user-1",
      caveats: [expires, ip],
      sig: <<0::256>>
    }

    {:ok, root} = HmacSha256.mac(Chain.root_data(env), @key, @aad)
    %{env | sig: Chain.extend(root, env.caveats)}
  end

  describe "fixed vectors" do
    test "caveat encodings are frozen" do
      assert CaveatCodec.encode("ip", :string, "1.2.3.4") ==
               {:ok, <<2, "ip", 1, 0, 7, "1.2.3.4">>}

      assert CaveatCodec.encode("n", :integer, -2) == {:ok, <<1, "n", 2, -2::signed-64>>}
      assert CaveatCodec.encode("b", :boolean, true) == {:ok, <<1, "b", 3, 1>>}

      assert CaveatCodec.encode("t", :datetime, ~U[1970-01-01 00:00:01Z]) ==
               {:ok, <<1, "t", 4, 1_000_000::signed-64>>}

      assert CaveatCodec.encode("l", :string_list, ["a", "bc"]) ==
               {:ok, <<1, "l", 5, 2, 0, 1, "a", 0, 2, "bc">>}

      assert CaveatCodec.encode("p", :integer_list, [80]) ==
               {:ok, <<1, "p", 6, 1, 80::signed-64>>}
    end

    test "the root data and chain are the documented construction" do
      env = vector_token()

      root_data =
        "ashvault:macaroon:root:v1|" <>
          <<6::64>> <>
          "avtest" <> <<1>> <> <<4::64>> <> "acme" <> <<1::64>> <> <<6::64>> <> "user-1"

      assert Chain.root_data(env) == root_data

      root =
        :crypto.mac(
          :hmac,
          :sha256,
          @key,
          "ashvault:mac:v1|" <> <<byte_size(@aad)::64>> <> @aad <> root_data
        )

      sig =
        Enum.reduce(env.caveats, root, fn caveat, sig ->
          :crypto.mac(
            :hmac,
            :sha256,
            sig,
            "ashvault:macaroon:caveat:v1|" <> <<byte_size(caveat)::64>> <> caveat
          )
        end)

      assert env.sig == sig
    end

    test "the token string is frozen" do
      {:ok, token} = Envelope.encode(vector_token())

      assert token ==
               "avtest_AQRhY21lAAAAAQZ1c2VyLTECABQKZXhwaXJlc19hdAQABroWlEcgAAANAmlwAQAHMS4yLjMuNM" <>
                 "gGX9Oll80VPil-b54aRqqj3__8z0WZRRqs041GmxV3"

      assert {:ok, %Envelope{} = decoded} = Envelope.decode(token)
      assert decoded == vector_token()
    end

    test "a chain step is not the bare HMAC of the caveat" do
      sig = <<9::256>>
      refute Chain.step(sig, "x") == HmacSha256.hmac(sig, "x")
    end
  end

  describe "strict envelope decoding" do
    setup do
      {:ok, token} = Envelope.encode(vector_token())
      [_prefix, encoded] = String.split(token, "_", parts: 2)
      {:ok, payload} = Base.url_decode64(encoded, padding: false)
      %{token: token, payload: payload}
    end

    defp wrap(payload), do: "avtest_" <> Base.url_encode64(payload, padding: false)

    test "trailing bytes are rejected", %{payload: payload} do
      assert Envelope.decode(wrap(payload <> <<0>>)) == {:error, :malformed}
    end

    test "truncation anywhere is rejected", %{payload: payload} do
      for size <- 0..(byte_size(payload) - 1) do
        assert {:error, _} = Envelope.decode(wrap(binary_part(payload, 0, size)))
      end
    end

    test "an unknown version is rejected", %{payload: <<_v, rest::binary>>} do
      assert Envelope.decode(wrap(<<2, rest::binary>>)) == {:error, :unsupported_version}
    end

    test "key version zero is rejected" do
      payload = <<1, 4, "acme", 0::32, 1, "x", 0, 0::256>>
      assert Envelope.decode(wrap(payload)) == {:error, :malformed}
    end

    test "an oversized caveat list is rejected" do
      caveats = for _ <- 1..33, do: <<0, 3, 1, "b", 3, 1>>
      payload = <<1, 4, "acme", 1::32, 1, "x", 33>> <> Enum.join(caveats) <> <<0::256>>
      assert Envelope.decode(wrap(payload)) == {:error, :malformed}
    end

    test "a scope with control characters is rejected" do
      payload = <<1, 2, "a\n", 1::32, 1, "x", 0, 0::256>>
      assert Envelope.decode(wrap(payload)) == {:error, :malformed}
    end

    test "non-canonical base64 is rejected", %{token: token} do
      assert Envelope.decode(token <> "=") == {:error, :malformed}
      assert Envelope.decode(String.replace(token, "-", "+")) == {:error, :malformed}

      [_prefix, encoded] = String.split(token, "_", parts: 2)
      {:ok, payload} = Base.url_decode64(encoded, padding: false)
      body = String.slice(encoded, 0..-2//1)
      alphabet = ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

      for char <- alphabet, alias = body <> <<char>>, alias != encoded do
        case Base.url_decode64(alias, padding: false) do
          {:ok, ^payload} -> assert Envelope.decode("avtest_" <> alias) == {:error, :malformed}
          _other -> :ok
        end
      end
    end

    test "oversized tokens are rejected before decoding" do
      assert Envelope.decode("avtest_" <> String.duplicate("A", Envelope.max_token_bytes())) ==
               {:error, :malformed}
    end

    test "bad prefixes are rejected" do
      for prefix <- ["", "a", "Av", "a_b", "1ab", String.duplicate("a", 33)] do
        refute Envelope.valid_prefix?(prefix)
      end

      assert Envelope.decode("no-separator") == {:error, :malformed}
      assert Envelope.decode(nil) == {:error, :malformed}
    end

    test "non-canonical caveat encodings are rejected" do
      assert CaveatCodec.decode(<<1, "b", 3, 2>>) == :error
      assert CaveatCodec.decode(<<1, "s", 1, 0, 2, 0xFF, 0xFE>>) == :error
      assert CaveatCodec.decode(<<1, "s", 1, 0, 1, "a", 0>>) == :error
      assert CaveatCodec.decode(<<1, "S", 3, 1>>) == :error
      assert CaveatCodec.decode(<<1, "l", 5, 0>>) == :error
      assert CaveatCodec.decode(<<1, "b", 9, 1>>) == :error
    end
  end

  describe "attenuate/2" do
    setup do
      {:ok, token} = Envelope.encode(vector_token())
      %{token: token}
    end

    test "appends caveats and extends the chain", %{token: token} do
      assert {:ok, narrower} = Macaroon.attenuate(token, actions: ["read"], port: 443)
      {:ok, env} = Envelope.decode(narrower)
      original = vector_token()

      assert length(env.caveats) == 4
      assert Enum.take(env.caveats, 2) == original.caveats
      assert env.sig == Chain.extend(original.sig, Enum.drop(env.caveats, 2))
    end

    test "refuses values outside the format", %{token: token} do
      assert Macaroon.attenuate(token, x: %{a: 1}) == {:error, :invalid_caveat}
      assert Macaroon.attenuate(token, [{"Bad", "x"}]) == {:error, :invalid_caveat}
      assert Macaroon.attenuate(token, x: []) == {:error, :invalid_caveat}
      assert Macaroon.attenuate("nope", x: "y") == {:error, :malformed}
    end

    test "never produces a token over the caveat limit", %{token: token} do
      many = for i <- 1..31, do: {:n, i}
      assert Macaroon.attenuate(token, many) == {:error, :invalid_caveat}
      assert {:ok, _} = Macaroon.attenuate(token, Enum.take(many, 30))
    end
  end

  describe "chain properties" do
    defp caveat_gen do
      gen all(
            name <- StreamData.member_of(~w(ip port tag)),
            value <- StreamData.string(:alphanumeric, min_length: 1, max_length: 12)
          ) do
        {:ok, bytes} = CaveatCodec.encode(name, :string, value)
        bytes
      end
    end

    property "only the exact chain verifies: tamper, reorder, truncate and append fail" do
      check all(
              caveats <- StreamData.list_of(caveat_gen(), min_length: 2, max_length: 6),
              extra <- caveat_gen(),
              flip <- StreamData.integer(0..255) |> StreamData.filter(&(&1 != 0))
            ) do
        root = :crypto.strong_rand_bytes(32)
        sig = Chain.extend(root, caveats)

        assert Chain.equal?(Chain.extend(root, caveats), sig)

        reordered = Enum.reverse(caveats)

        if reordered != caveats,
          do: refute(Chain.equal?(Chain.extend(root, reordered), sig))

        refute Chain.equal?(Chain.extend(root, Enum.drop(caveats, -1)), sig)
        refute Chain.equal?(Chain.extend(root, caveats ++ [extra]), sig)

        [first | rest] = caveats
        <<byte, tail::binary>> = first
        tampered = [<<Bitwise.bxor(byte, flip), tail::binary>> | rest]
        refute Chain.equal?(Chain.extend(root, tampered), sig)

        assert Chain.equal?(Chain.extend(sig, [extra]), Chain.extend(root, caveats ++ [extra]))
      end
    end
  end
end
