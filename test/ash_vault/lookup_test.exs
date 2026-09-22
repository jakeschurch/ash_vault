defmodule AshVault.LookupTest do
  @moduledoc """
  The crypto half of searchable fields: HKDF against RFC 5869's own vectors, the
  derivation's separation properties, and normalization.

  Nothing here touches Ash. The extension-level behaviour lives in
  `AshVault.SearchableFieldsTest`; the one property everything rests on has its own file,
  `AshVault.LookupRotationTest`.
  """

  use ExUnit.Case, async: true

  alias AshVault.Lookup

  defp hex(string), do: Base.decode16!(string, case: :mixed)

  # https://datatracker.ietf.org/doc/html/rfc5869#appendix-A — the three SHA-256 cases.
  # A.4-A.7 are SHA-1 and do not apply.
  describe "RFC 5869 test vectors" do
    test "A.1 — basic test case with SHA-256" do
      ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      salt = hex("000102030405060708090a0b0c")
      info = hex("f0f1f2f3f4f5f6f7f8f9")

      prk =
        hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

      okm =
        hex(
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )

      assert Lookup.hkdf_extract(ikm, salt) == prk
      assert Lookup.hkdf_expand(prk, info, 42) == okm
      assert Lookup.hkdf(ikm, salt, info, 42) == okm
    end

    test "A.2 — longer inputs and outputs with SHA-256" do
      ikm =
        hex(
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" <>
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" <>
            "404142434445464748494a4b4c4d4e4f"
        )

      salt =
        hex(
          "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" <>
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" <>
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )

      info =
        hex(
          "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" <>
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" <>
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        )

      prk = hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")

      okm =
        hex(
          "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" <>
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" <>
            "cc30c58179ec3e87c14c01d5c1f3434f1d87"
        )

      assert Lookup.hkdf_extract(ikm, salt) == prk
      assert Lookup.hkdf_expand(prk, info, 82) == okm
      assert Lookup.hkdf(ikm, salt, info, 82) == okm
    end

    test "A.3 — zero-length salt and info with SHA-256" do
      ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
      prk = hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")

      okm =
        hex(
          "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        )

      # The RFC defines an absent salt as HashLen zero bytes; `hkdf_extract/2` does that
      # substitution, which is exactly what this vector pins.
      assert Lookup.hkdf_extract(ikm, "") == prk
      assert Lookup.hkdf_expand(prk, "", 42) == okm
      assert Lookup.hkdf(ikm, "", "", 42) == okm
    end

    test "expand refuses more than 255 * HashLen bytes, as the RFC requires" do
      prk = :crypto.strong_rand_bytes(32)

      assert 255 * 32 == byte_size(Lookup.hkdf_expand(prk, "", 255 * 32))

      assert_raise ArgumentError, ~r/cannot produce more than 8160 bytes/, fn ->
        Lookup.hkdf_expand(prk, "", 255 * 32 + 1)
      end
    end
  end

  describe "info/2" do
    test "is a frozen, human-inspectable binary" do
      assert Lookup.info(AshVault.Test.EtsAccount, :email) ==
               "ash_vault:lookup:v1|AshVault.Test.EtsAccount|email"
    end
  end

  describe "derive_field_key/3" do
    setup do
      %{ikm: :crypto.strong_rand_bytes(32)}
    end

    test "is 32 bytes and deterministic", %{ikm: ikm} do
      key = Lookup.derive_field_key(ikm, AshVault.Test.EtsAccount, :email)

      assert byte_size(key) == 32
      assert key == Lookup.derive_field_key(ikm, AshVault.Test.EtsAccount, :email)
    end

    test "separates fields", %{ikm: ikm} do
      refute Lookup.derive_field_key(ikm, AshVault.Test.EtsAccount, :email) ==
               Lookup.derive_field_key(ikm, AshVault.Test.EtsAccount, :handle)
    end

    test "separates resources", %{ikm: ikm} do
      refute Lookup.derive_field_key(ikm, AshVault.Test.EtsAccount, :email) ==
               Lookup.derive_field_key(ikm, AshVault.Test.EtsContact, :email)
    end

    test "separates provider keys — which is what separates scopes" do
      a = Lookup.derive_field_key(:crypto.strong_rand_bytes(32), AshVault.Test.EtsAccount, :email)
      b = Lookup.derive_field_key(:crypto.strong_rand_bytes(32), AshVault.Test.EtsAccount, :email)

      refute a == b
    end
  end

  describe "token/2" do
    test "is a deterministic 32-byte HMAC" do
      key = :crypto.strong_rand_bytes(32)

      assert byte_size(Lookup.token(key, "jake@example.com")) == 32
      assert Lookup.token(key, "jake@example.com") == Lookup.token(key, "jake@example.com")
      refute Lookup.token(key, "jake@example.com") == Lookup.token(key, "jane@example.com")
    end
  end

  describe "normalize/2" do
    test ":none leaves the value alone" do
      assert Lookup.normalize(" Jake@Example.COM ", :none) == {:ok, " Jake@Example.COM "}
    end

    test ":downcase downcases but does not trim" do
      assert Lookup.normalize(" Jake@Example.COM ", :downcase) == {:ok, " jake@example.com "}
    end

    test ":downcase_trim does both" do
      assert Lookup.normalize(" Jake@Example.COM ", :downcase_trim) == {:ok, "jake@example.com"}
    end

    test "nil passes straight through, for every strategy" do
      for strategy <- [:none, :downcase, :downcase_trim] do
        assert Lookup.normalize(nil, strategy) == {:ok, nil}
      end
    end

    test "an MFA is applied with the value first" do
      assert Lookup.normalize("abc", {String, :replace, ["b", "-"]}) == {:ok, "a-c"}
    end

    test "a 1-arity function is applied" do
      assert Lookup.normalize("abc", &String.upcase/1) == {:ok, "ABC"}
    end

    test "an Ash.CiString is unwrapped — the type gate allows it, so this must handle it" do
      assert Lookup.normalize(Ash.CiString.new("Jake@Example.com"), :downcase) ==
               {:ok, "jake@example.com"}
    end

    test "a non-binary is an error, never a silent to_string/1" do
      assert {:error, {:not_a_binary, :none, _description}} =
               Lookup.normalize(%{a: 1}, :none)

      assert {:error, {:not_a_binary, _fun, _description}} =
               Lookup.normalize("abc", fn _ -> 42 end)
    end

    test "the error describes the value's shape and never reproduces it" do
      assert {:error, {:not_a_binary, :none, description}} =
               Lookup.normalize(%AshVault.Test.Profile{nickname: "topsecret"}, :none)

      assert description == "a %AshVault.Test.Profile{}"
      refute description =~ "topsecret"
    end
  end
end
