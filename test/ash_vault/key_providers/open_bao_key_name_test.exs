defmodule AshVault.KeyProviders.OpenBaoKeyNameTest do
  @moduledoc """
  The one property that keeps `AshVault.KeyProviders.OpenBao`'s two transit key names in
  separate namespaces.

  `lookup_key_name/1` is `key_name/1` with `"_lookup"` appended. If any scope `s1`
  existed with `key_name(s1) == lookup_key_name(s2)`, then **one tenant's lookup key
  would be another tenant's data key** — and the lookup key is deliberately never
  rotated, so `s1` would be pinned to a key `rotate/1` cannot move while anyone holding
  `s2`'s lookup key could decrypt `s1`'s data.

  It holds, but only by an arithmetic accident of unpadded base64url: the moduledoc on
  `lookup_key_name/1` gives the three cases. Accidents deserve a test, because the
  property survives no change to the encoding — hex instead of base64url, `padding: true`,
  or a suffix ending in a character whose low bits happen to be zero would all
  reintroduce it. Every test here fails if any of those change.

  Pure name arithmetic — no server, so this file is deliberately **not** tagged
  `:openbao` and runs in a plain `mix test`.
  """

  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  alias AshVault.KeyProviders.OpenBao

  @suffix "_lookup"

  # A scope is any binary the vault's `AshVault.Scope` produced. `validate_scope!/1`
  # accepts exactly that and nothing else, so the generator is `binary()` — including the
  # empty binary, which is a legal (if useless) scope and the shortest encoding there is.
  defp scope, do: StreamData.binary()

  describe "the structural property" do
    property "no scope's key_name/1 ever ends with the lookup suffix" do
      # This is the discriminating form. A pairwise `key_name(s1) != lookup_key_name(s2)`
      # over random scopes passes trivially and would keep passing if the property broke:
      # two random scopes never collide. What actually makes the namespaces disjoint is
      # that the data-key namespace cannot *reach* the lookup namespace at all.
      check all(scope <- scope(), max_runs: 2_000) do
        refute String.ends_with?(OpenBao.key_name(scope), @suffix)
      end
    end

    property "the derived consequence: no scope's key_name/1 is any scope's lookup_key_name/1" do
      check all(s1 <- scope(), s2 <- scope(), max_runs: 500) do
        refute OpenBao.key_name(s1) == OpenBao.lookup_key_name(s2)
      end
    end

    property "and the two names are never equal for the same scope either" do
      check all(scope <- scope(), max_runs: 500) do
        refute OpenBao.key_name(scope) == OpenBao.lookup_key_name(scope)
      end
    end

    # The adversarial direction: a scope *chosen* so its encoding lands next to the
    # suffix. `key_name/1` is injective in the scope, so the only way to end with
    # `"_lookup"` is to encode bytes that produce those characters — and the property
    # above says that cannot happen. These are the near misses.
    property "a scope whose encoding is deliberately steered at the suffix still misses" do
      check all(prefix <- StreamData.binary(min_length: 0, max_length: 6), max_runs: 500) do
        for candidate <- [prefix, prefix <> @suffix, prefix <> "_looku", @suffix <> prefix] do
          refute String.ends_with?(OpenBao.key_name(candidate), @suffix)
        end
      end
    end

    # Exhaustive over every scope short enough to enumerate, which covers all three
    # length residues several times over. A property test samples; this one does not.
    test "exhaustively, for every scope of up to two bytes" do
      scopes =
        [<<>>] ++
          for(a <- 0..255, do: <<a>>) ++
          for(a <- 0..255, b <- 0..255, do: <<a, b>>)

      for scope <- scopes do
        refute String.ends_with?(OpenBao.key_name(scope), @suffix)
      end
    end
  end

  # The property above is the assertion that matters; these pin the *reasoning* behind
  # it, so that a change to the alphabet breaks the explanation in the moduledoc rather
  # than leaving a stale proof beside working code.
  describe "the arithmetic the proof rests on" do
    # Without this, `@suffix` is a test-local constant with nothing tying it to the code.
    # Changing `lookup_key_name/1` to append something else — including a suffix ending
    # in a character whose low bits ARE zero, which is precisely the reintroduction case
    # the moduledoc warns about — would leave every property above asserting happily
    # about a string the implementation no longer uses. `open_bao_test.exs` pins this too,
    # but it is `:openbao`-tagged and skipped in a plain `mix test`.
    test "the suffix under test is the suffix the implementation appends" do
      for scope <- ["x", "", "tenant_42", <<0, 255>>] do
        assert OpenBao.lookup_key_name(scope) == OpenBao.key_name(scope) <> @suffix
      end
    end

    test "the suffix's final character is base64url index 41, whose low bits are not zero" do
      alphabet = ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

      index = Enum.find_index(alphabet, &(&1 == ?p))

      assert index == 41

      # A final character in a 3-character group carries 4 data bits (low 2 must be 0);
      # in a 2-character group it carries 2 (low 4 must be 0). `?p` satisfies neither.
      assert (index &&& 3) != 0
      assert (index &&& 15) != 0
    end

    test "every character of the suffix is in the base64url alphabet — the suffix alone proves nothing" do
      alphabet = ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

      for char <- String.to_charlist(@suffix) do
        assert char in alphabet,
               "#{inspect(<<char>>)} is outside base64url, which would make this property " <>
                 "hold for a reason the moduledoc does not give"
      end
    end

    property "unpadded base64url never has a length congruent to 1 mod 4" do
      check all(bytes <- StreamData.binary(), max_runs: 500) do
        assert rem(byte_size(Base.url_encode64(bytes, padding: false)), 4) != 1
      end
    end

    # The sharpest thing found while proving this: the suffix is NOT unreachable in
    # general. Canonical unpadded base64url strings ending in `"_lookup"` exist — all 64
    # of them are 8 characters long. They are unreachable here only because an 8-character
    # `key_name/1` suffix would need `enc(s2)` to be 1 character, and 1 is the one length
    # unpadded base64 cannot have. Pinned so nobody "simplifies" the moduledoc down to the
    # `?p` argument alone, which would be an incomplete proof.
    test "the suffix is reachable in general — the length rule, not ?p, excludes that case" do
      assert {:ok, bytes} = Base.url_decode64("A_lookup", padding: false)
      assert Base.url_encode64(bytes, padding: false) == "A_lookup"
      assert byte_size("A_lookup") == 8
      assert rem(8 - byte_size(@suffix), 4) == 1
    end

    test "the encoding is unpadded, which the length argument requires" do
      # With padding on, every name would be a multiple of 4 and the residue argument
      # would say nothing. This asserts the configuration the proof assumes.
      refute String.contains?(OpenBao.key_name("a"), "=")
      assert OpenBao.key_name("a") == "ashvault_" <> Base.url_encode64("a", padding: false)
    end
  end
end
