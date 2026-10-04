defmodule AshVault.Macs.HmacSha256Test do
  use ExUnit.Case, async: true

  alias AshVault.Macs.HmacSha256

  doctest AshVault.Mac
  doctest AshVault.Macs.HmacSha256

  @key :crypto.strong_rand_bytes(32)

  # RFC 4231 §4, HMAC-SHA-256 column. Run against the bare primitive: the framed `mac/3`
  # is not HMAC of the raw data, by design.
  @rfc4231 [
    {1, :binary.copy(<<0x0B>>, 20), "Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
    {2, "Jefe", "what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
    {3, :binary.copy(<<0xAA>>, 20), :binary.copy(<<0xDD>>, 50),
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
    {4, :binary.list_to_bin(Enum.to_list(1..25)), :binary.copy(<<0xCD>>, 50),
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
    {6, :binary.copy(<<0xAA>>, 131), "Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"},
    {7, :binary.copy(<<0xAA>>, 131),
     "This is a test using a larger than block-size key and a larger than block-size data. " <>
       "The key needs to be hashed before being used by the HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"}
  ]

  describe "RFC 4231 test vectors" do
    for {number, key, data, expected} <- @rfc4231 do
      @key_bytes key
      @data data
      @expected expected

      test "test case #{number}" do
        assert Base.encode16(HmacSha256.hmac(@key_bytes, @data), case: :lower) == @expected
      end
    end

    test "test case 5 (truncated to 128 bits)" do
      tag = HmacSha256.hmac(:binary.copy(<<0x0C>>, 20), "Test With Truncation")

      assert Base.encode16(binary_part(tag, 0, 16), case: :lower) ==
               "a3b6167473100ee06e0c796c2955552b"
    end
  end

  describe "mac/3" do
    test "is HMAC-SHA256 over the frozen frame, 32 raw bytes" do
      assert {:ok, tag} = HmacSha256.mac("data", @key, "aad")
      assert byte_size(tag) == 32
      assert tag == HmacSha256.hmac(@key, AshVault.Mac.frame("data", "aad"))
      refute tag == HmacSha256.hmac(@key, "data")
    end

    test "is deterministic and depends on data, aad and key" do
      {:ok, tag} = HmacSha256.mac("data", @key, "aad")
      assert {:ok, ^tag} = HmacSha256.mac("data", @key, "aad")

      refute {:ok, tag} == HmacSha256.mac("datA", @key, "aad")
      refute {:ok, tag} == HmacSha256.mac("data", @key, "aaD")
      refute {:ok, tag} == HmacSha256.mac("data", :crypto.strong_rand_bytes(32), "aad")
    end

    test "the aad length prefix stops a boundary shift from colliding" do
      assert HmacSha256.mac("bc", @key, "a") != HmacSha256.mac("c", @key, "ab")
      assert HmacSha256.mac("", @key, "ab") != HmacSha256.mac("ab", @key, "")
    end

    test "refuses a key of the wrong size as a configuration fault" do
      assert {:error, {:invalid_key_size, 16}} = HmacSha256.mac("d", <<0::128>>, "a")

      assert {:error, {:invalid_key_size, 64}} =
               HmacSha256.verify("d", <<0::256>>, <<0::512>>, "a")
    end

    test "refuses an opaque handle rather than falling back to anything" do
      handle = %AshVault.Key{ref: make_ref(), owner: __MODULE__}

      assert {:error, :opaque_key_unsupported} = HmacSha256.mac("d", handle, "a")
      assert {:error, :opaque_key_unsupported} = HmacSha256.verify("d", <<0::256>>, handle, "a")
    end
  end

  describe "verify/4" do
    setup do
      {:ok, tag} = HmacSha256.mac("payload", @key, "ctx")
      %{tag: tag}
    end

    test "accepts the tag it minted", %{tag: tag} do
      assert :ok = HmacSha256.verify("payload", tag, @key, "ctx")
    end

    test "rejects tampered data, aad, key or tag", %{tag: tag} do
      <<first, rest::binary>> = tag
      flipped = <<Bitwise.bxor(first, 1), rest::binary>>
      last_flipped = binary_part(tag, 0, 31) <> <<Bitwise.bxor(:binary.last(tag), 0x80)>>

      assert {:error, :invalid_tag} = HmacSha256.verify("Payload", tag, @key, "ctx")
      assert {:error, :invalid_tag} = HmacSha256.verify("payload", tag, @key, "ctX")

      assert {:error, :invalid_tag} =
               HmacSha256.verify("payload", tag, :crypto.strong_rand_bytes(32), "ctx")

      assert {:error, :invalid_tag} = HmacSha256.verify("payload", flipped, @key, "ctx")
      assert {:error, :invalid_tag} = HmacSha256.verify("payload", last_flipped, @key, "ctx")
    end

    # `:crypto.hash_equals/2` raises on unequal lengths. A truncated, padded, empty or
    # non-binary tag is a wrong tag, never a crash.
    test "a tag of the wrong length or type is :invalid_tag, never a raise", %{tag: tag} do
      for bad <- [binary_part(tag, 0, 31), tag <> <<0>>, "", nil, 42, :tag, [tag]] do
        assert {:error, :invalid_tag} = HmacSha256.verify("payload", bad, @key, "ctx"),
               "expected :invalid_tag for #{inspect(bad)}"
      end
    end

    # A timing measurement would be flaky on shared CI. What is asserted instead is the
    # code path: the compiled `verify/4` compares with `:crypto.hash_equals/2`, and does
    # not compare the tag with `==` / `===`, which short-circuit on the first differing
    # byte.
    test "compares in constant time: verify/4 calls :crypto.hash_equals/2" do
      {:ok, {HmacSha256, [abstract_code: {:raw_abstract_v1, forms}]}} =
        HmacSha256 |> :code.which() |> :beam_lib.chunks([:abstract_code])

      verify =
        Enum.find(forms, &match?({:function, _, :verify, 4, _}, &1)) ||
          flunk("verify/4 not found in the abstract code")

      calls = verify |> collect_remote_calls() |> MapSet.new()
      assert {:crypto, :hash_equals} in calls

      refute contains_binary_equality_on_tag?(verify)
    end
  end

  defp collect_remote_calls(form) do
    {_form, acc} =
      walk(form, [], fn
        {:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, _args}, acc ->
          [{module, function} | acc]

        _node, acc ->
          acc
      end)

    acc
  end

  # `==`, `=:=`, `/=` and `=/=` on two variables, one of them the tag.
  defp contains_binary_equality_on_tag?(form) do
    {_form, found?} =
      walk(form, false, fn
        {:op, _, op, left, right}, acc when op in [:==, :"=:=", :"/=", :"=/="] ->
          acc or tag_var?(left) or tag_var?(right)

        _node, acc ->
          acc
      end)

    found?
  end

  defp tag_var?({:var, _, name}), do: name |> Atom.to_string() |> String.contains?("tag")
  defp tag_var?(_other), do: false

  defp walk(node, acc, fun) when is_tuple(node) do
    acc = fun.(node, acc)

    node
    |> Tuple.to_list()
    |> Enum.reduce({node, acc}, fn child, {node, acc} ->
      {_child, acc} = walk(child, acc, fun)
      {node, acc}
    end)
  end

  defp walk(node, acc, fun) when is_list(node) do
    Enum.reduce(node, {node, acc}, fn child, {node, acc} ->
      {_child, acc} = walk(child, acc, fun)
      {node, acc}
    end)
  end

  defp walk(node, acc, _fun), do: {node, acc}
end
