defmodule AshVault.Extension.SerializerTest do
  use ExUnit.Case, async: true

  alias AshVault.Errors.InvalidCiphertext
  alias AshVault.Errors.SerializationFailed
  alias AshVault.Errors.UnsupportedEnvelope
  alias AshVault.Serializer
  alias AshVault.Test.EtsUser
  alias AshVault.Test.Profile

  defp roundtrip(value, field) do
    %{type: type, constraints: constraints} = Ash.Resource.Info.calculation(EtsUser, field)

    binary = Serializer.serialize!(value, type, constraints, EtsUser, field)
    assert <<"AVP", 1::8, _rest::binary>> = binary

    {binary, Serializer.deserialize(binary, type, constraints, EtsUser, field)}
  end

  describe "wire format" do
    test "is the explicit AVP header plus an uncompressed ETF term" do
      {binary, _} = roundtrip("a@b.c", :email)

      assert <<"AVP", 1::8, payload::binary>> = binary
      assert :erlang.binary_to_term(payload) == "a@b.c"
      assert Serializer.magic() == "AVP"
      assert Serializer.version() == 1
    end

    test "never writes a compressed term" do
      {<<"AVP", 1::8, payload::binary>>, _} = roundtrip(String.duplicate("a", 10_000), :email)

      refute match?(<<131, 80, _::binary>>, payload)
    end
  end

  describe "round trips" do
    test "scalar" do
      assert {_, {:ok, "a@b.c"}} = roundtrip("a@b.c", :email)
    end

    test "nil" do
      assert {_, {:ok, nil}} = roundtrip(nil, :email)
    end

    test "array of scalars" do
      assert {_, {:ok, ["x", "y", "z"]}} = roundtrip(["x", "y", "z"], :tags)
    end

    test "empty array" do
      assert {_, {:ok, []}} = roundtrip([], :tags)
    end

    test "embedded resource" do
      profile = %Profile{nickname: "nick", age: 7}

      assert {_, {:ok, loaded}} = roundtrip(profile, :profile)
      assert loaded.nickname == "nick"
      assert loaded.age == 7
    end

    test "embedded resource dumps to a plain map, never a struct" do
      %{type: type, constraints: constraints} =
        Ash.Resource.Info.calculation(EtsUser, :profile)

      <<"AVP", 1::8, payload::binary>> =
        Serializer.serialize!(
          %Profile{nickname: "nick", age: 7},
          type,
          constraints,
          EtsUser,
          :profile
        )

      dumped = :erlang.binary_to_term(payload)

      assert is_map(dumped)
      refute is_struct(dumped)
      assert dumped["nickname"] == "nick" or dumped[:nickname] == "nick"
    end

    test "array of embedded resources" do
      contacts = [%Profile{nickname: "c1", age: 1}, %Profile{nickname: "c2", age: 2}]

      assert {_, {:ok, [one, two]}} = roundtrip(contacts, :contacts)
      assert one.nickname == "c1"
      assert two.age == 2
    end
  end

  describe "decode rejections" do
    defp deserialize(binary) do
      %{type: type, constraints: constraints} = Ash.Resource.Info.calculation(EtsUser, :email)
      Serializer.deserialize(binary, type, constraints, EtsUser, :email)
    end

    test "a foreign binary is not a plaintext" do
      assert {:error, %InvalidCiphertext{reason: :not_an_ash_vault_plaintext}} =
               deserialize("nope")

      assert {:error, %InvalidCiphertext{}} = deserialize("")
      assert {:error, %InvalidCiphertext{}} = deserialize(:erlang.term_to_binary("a@b.c"))
    end

    test "an unknown plaintext version is reported as the plaintext layer" do
      assert {:error, %UnsupportedEnvelope{version: 99} = error} =
               deserialize(<<"AVP", 99::8, "whatever">>)

      assert error.vars[:layer] == :plaintext
    end

    test "a compressed ETF payload is refused before decoding" do
      compressed = :erlang.term_to_binary(List.duplicate("a", 10_000), compressed: 9)
      assert <<131, 80, _::binary>> = compressed

      assert {:error, %InvalidCiphertext{reason: :compressed_term_refused}} =
               deserialize(<<"AVP", 1::8, compressed::binary>>)
    end

    test "garbage after a valid header does not raise" do
      assert {:error, %InvalidCiphertext{reason: {:binary_to_term, _}}} =
               deserialize(<<"AVP", 1::8, 131, 255, 255, 255>>)
    end

    test "a term that cannot be cast back is a SerializationFailed" do
      %{type: type, constraints: constraints} = Ash.Resource.Info.calculation(EtsUser, :tags)

      binary = <<"AVP", 1::8, :erlang.term_to_binary(%{not: "a list"})::binary>>

      assert {:error, %SerializationFailed{field: :tags}} =
               Serializer.deserialize(binary, type, constraints, EtsUser, :tags)
    end
  end

  describe "serialize!/5 failures" do
    test "a value the type cannot dump raises SerializationFailed" do
      %{type: type, constraints: constraints} = Ash.Resource.Info.calculation(EtsUser, :tags)

      assert_raise SerializationFailed, fn ->
        Serializer.serialize!(%{not: "a list"}, type, constraints, EtsUser, :tags)
      end
    end
  end
end
