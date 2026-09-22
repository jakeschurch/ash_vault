defmodule AshVault.SearchableFieldsTest do
  @moduledoc """
  Extension-level behaviour of `searchable?: true`: what the transformer generates, what
  the write path stores, what the two query paths return, and what happens when the scope
  is missing or destroyed.

  Runs on ETS. The parts that need a real unique index — `unique?` enforcement and the
  `EXPLAIN` assertion — are in `AshVault.SearchableFieldsPostgresTest`.
  """

  use ExUnit.Case, async: false

  require Ash.Query

  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.EtsAccount
  alias AshVault.Test.EtsContact
  alias AshVault.Test.EtsSecretDoc
  alias AshVault.Test.EtsNonBinaryScopeDoc

  setup do
    start_supervised!({Memory, name: Memory})
    %{org: "org_#{System.unique_integer([:positive])}"}
  end

  defp create!(org, attrs) do
    EtsAccount
    |> Ash.Changeset.for_create(:create, Map.merge(%{org_id: org}, attrs))
    |> Ash.create!(tenant: org)
  end

  defp find(org, field, value) do
    EtsAccount
    |> AshVault.Query.filter_by(field, value, tenant: org)
    |> Ash.read!(tenant: org)
  end

  describe "the generated schema" do
    test "a lookup attribute is added, private, sensitive, nullable and filterable" do
      attribute = Ash.Resource.Info.attribute(EtsAccount, :email_lookup)

      assert attribute.type == Ash.Type.Binary
      refute attribute.public?
      assert attribute.sensitive?
      assert attribute.allow_nil?
      assert attribute.filterable?
    end

    test "non-searchable fields get no lookup attribute" do
      refute Ash.Resource.Info.attribute(EtsAccount, :note_lookup)
    end

    test "the plaintext attribute is still removed, exactly as for a plain encrypt" do
      refute Ash.Resource.Info.attribute(EtsAccount, :email)
      assert Ash.Resource.Info.attribute(EtsAccount, :encrypted_email)
      assert Ash.Resource.Info.calculation(EtsAccount, :email)
    end

    test "a `by_<field>` read action is generated, with a sensitive argument" do
      action = Ash.Resource.Info.action(EtsAccount, :by_email)

      assert action.type == :read
      assert [argument] = action.arguments
      assert argument.name == :email
      assert argument.sensitive?
      refute argument.allow_nil?
    end

    test "the generated action carries the filter preparation" do
      action = Ash.Resource.Info.action(EtsAccount, :by_email)

      assert Enum.any?(action.preparations, fn preparation ->
               match?({AshVault.Preparations.FilterByLookup, _}, preparation.preparation)
             end)
    end

    test "an identity is generated only for `unique?`, and only on the lookup key" do
      # EtsAccount is searchable but not unique; SearchUser (Postgres) is both.
      refute Ash.Resource.Info.identity(EtsAccount, :email_lookup_unique)

      identity = Ash.Resource.Info.identity(AshVault.Test.SearchUser, :email_lookup_unique)

      # `keys` is [:email_lookup] ONLY — Ash adds the multitenancy attribute itself for
      # the index and for pre/eager check, and `keys` is also the identity's public
      # contract for `Ash.get/3` and upserts.
      assert identity.keys == [:email_lookup]
      refute identity.all_tenants?
      assert identity.nils_distinct?
    end
  end

  describe "the write path" do
    test "stores a deterministic token beside the randomized ciphertext", %{org: org} do
      a = create!(org, %{email: "jake@example.com"})
      b = create!(org, %{email: "jake@example.com"})

      assert is_binary(a.email_lookup)
      assert byte_size(a.email_lookup) == 32

      # The whole point: the ciphertext differs every time, the token does not.
      refute a.encrypted_email == b.encrypted_email
      assert a.email_lookup == b.email_lookup
    end

    test "a different value produces a different token", %{org: org} do
      a = create!(org, %{email: "jake@example.com"})
      b = create!(org, %{email: "jane@example.com"})

      refute a.email_lookup == b.email_lookup
    end

    test "tokens are separated by field", %{org: org} do
      record = create!(org, %{email: "same@example.com", handle: "same@example.com"})

      refute record.email_lookup == record.handle_lookup
    end

    test "tokens are separated by resource", %{org: org} do
      account = create!(org, %{email: "same@example.com"})

      contact =
        EtsContact
        |> Ash.Changeset.for_create(:create, %{org_id: org, email: "same@example.com"})
        |> Ash.create!(tenant: org)

      refute account.email_lookup == contact.email_lookup
    end

    test "tokens are separated by scope", %{org: org} do
      other = org <> "_other"

      a = create!(org, %{email: "same@example.com"})

      b =
        EtsAccount
        |> Ash.Changeset.for_create(:create, %{org_id: other, email: "same@example.com"})
        |> Ash.create!(tenant: other)

      refute a.email_lookup == b.email_lookup
    end

    test "tokens are stable across processes", %{org: org} do
      record = create!(org, %{email: "stable@example.com"})

      # The ETS table is `private? true`, so the token is recomputed in the other
      # process rather than read back through the data layer. Recomputation is the
      # property that matters anyway: a token derived from anything process-local would
      # differ here.
      elsewhere =
        Task.async(fn ->
          AshVault.Lookup.token_for!(
            EtsAccount,
            :email,
            "stable@example.com",
            AshVault.Context.Builder.from_query(
              Ash.Query.set_tenant(Ash.Query.new(EtsAccount), org),
              :email,
              %{tenant: org, actor: nil, source_context: %{}}
            )
          )
        end)
        |> Task.await()

      assert elsewhere == record.email_lookup
    end

    test "a nil plaintext produces a nil token", %{org: org} do
      record = create!(org, %{email: nil})

      assert is_nil(record.email_lookup)
    end

    test "an update recomputes the token", %{org: org} do
      record = create!(org, %{email: "old@example.com"})

      updated =
        record
        |> Ash.Changeset.for_update(:update, %{email: "new@example.com"})
        |> Ash.update!(tenant: org)

      refute updated.email_lookup == record.email_lookup
      assert [%{id: id}] = find(org, :email, "new@example.com")
      assert id == record.id
      assert [] == find(org, :email, "old@example.com")
    end

    test "an update that does not touch the field leaves the token alone", %{org: org} do
      record = create!(org, %{email: "kept@example.com"})

      updated =
        record
        |> Ash.Changeset.for_update(:update, %{note: "a note"})
        |> Ash.update!(tenant: org)

      assert updated.email_lookup == record.email_lookup
    end

    test "the plaintext is still scrubbed from the changeset", %{org: org} do
      changeset =
        EtsAccount
        |> Ash.Changeset.for_create(:create, %{org_id: org, email: "scrub@example.com"})

      assert {:ok, _record} = Ash.create(changeset, tenant: org)
      refute inspect(changeset) =~ "scrub@example.com"
    end
  end

  describe "normalization" do
    test ":downcase_trim matches a differently-cased, padded value", %{org: org} do
      create!(org, %{email: "jake@example.com"})

      assert [_] = find(org, :email, " Jake@Example.COM ")
      assert [_] = find(org, :email, "JAKE@EXAMPLE.COM")
    end

    test ":none does not", %{org: org} do
      create!(org, %{handle: "jake"})

      assert [_] = find(org, :handle, "jake")
      assert [] == find(org, :handle, "Jake")
      assert [] == find(org, :handle, "JAKE")
    end

    test "normalization is lossy on the ciphertext too — the stored value IS normalized",
         %{org: org} do
      record = create!(org, %{email: " Jake@Example.COM "})

      loaded = Ash.load!(record, [:email], tenant: org)

      # The token must be the hash of exactly the bytes that were encrypted, so the
      # normalized value is what gets stored. Surprising, deliberate, and documented in
      # `documentation/topics/searchable-fields.md`.
      assert loaded.email == "jake@example.com"
    end

    test "a non-normalized field stores the value verbatim", %{org: org} do
      # Case, not whitespace: `Ash.Type.String` trims by default, so leading spaces are
      # gone before AshVault ever sees the value.
      record = create!(org, %{handle: "Jake"})

      assert Ash.load!(record, [:handle], tenant: org).handle == "Jake"
    end
  end

  describe "AshVault.Query.filter_by/4" do
    test "finds the row", %{org: org} do
      record = create!(org, %{email: "found@example.com"})

      assert [%{id: id}] = find(org, :email, "found@example.com")
      assert id == record.id
    end

    test "returns nothing for a value nobody stored", %{org: org} do
      create!(org, %{email: "found@example.com"})

      assert [] == find(org, :email, "absent@example.com")
    end

    test "does not cross tenants", %{org: org} do
      other = org <> "_other"
      create!(org, %{email: "shared@example.com"})

      EtsAccount
      |> Ash.Changeset.for_create(:create, %{org_id: other, email: "shared@example.com"})
      |> Ash.create!(tenant: other)

      assert [%{org_id: ^org}] = find(org, :email, "shared@example.com")
      assert [%{org_id: ^other}] = find(other, :email, "shared@example.com")
    end

    test "composes with an existing query", %{org: org} do
      kept = create!(org, %{email: "compose@example.com"})
      create!(org, %{email: "other@example.com"})

      results =
        EtsAccount
        |> Ash.Query.filter(id == ^kept.id)
        |> AshVault.Query.filter_by(:email, "compose@example.com", tenant: org)
        |> Ash.read!(tenant: org)

      assert [%{id: id}] = results
      assert id == kept.id

      # And the composition really constrains: the same filter with a value the row does
      # not hold returns nothing rather than ignoring one half.
      assert [] ==
               EtsAccount
               |> Ash.Query.filter(id == ^kept.id)
               |> AshVault.Query.filter_by(:email, "other@example.com", tenant: org)
               |> Ash.read!(tenant: org)
    end

    test "a nil value filters on is_nil rather than equality", %{org: org} do
      create!(org, %{email: nil})
      create!(org, %{email: "present@example.com"})

      assert [%{email_lookup: nil}] = find(org, :email, nil)
    end

    test "a non-searchable field is a loud ArgumentError, not an empty result", %{org: org} do
      assert_raise ArgumentError, ~r/is not a searchable encrypted field/, fn ->
        AshVault.Query.filter_by(EtsAccount, :note, "x", tenant: org)
      end
    end

    test "accepts a bare tenant, a keyword list and a context-shaped map", %{org: org} do
      create!(org, %{email: "forms@example.com"})

      for context <- [org, [tenant: org], %{tenant: org, actor: nil}] do
        assert [_] =
                 EtsAccount
                 |> AshVault.Query.filter_by(:email, "forms@example.com", context)
                 |> Ash.read!(tenant: org)
      end
    end
  end

  describe "the generated :by_<field> read action" do
    test "finds the row", %{org: org} do
      record = create!(org, %{email: "action@example.com"})

      assert [%{id: id}] =
               EtsAccount
               |> Ash.Query.for_read(:by_email, %{email: "action@example.com"}, tenant: org)
               |> Ash.read!(tenant: org)

      assert id == record.id
    end

    test "normalizes its argument the same way a write does", %{org: org} do
      create!(org, %{email: "normal@example.com"})

      assert [_] =
               EtsAccount
               |> Ash.Query.for_read(:by_email, %{email: " Normal@Example.COM "}, tenant: org)
               |> Ash.read!(tenant: org)
    end

    test "does not cross tenants", %{org: org} do
      other = org <> "_other"
      create!(org, %{email: "actionshared@example.com"})

      assert [] ==
               EtsAccount
               |> Ash.Query.for_read(:by_email, %{email: "actionshared@example.com"},
                 tenant: other
               )
               |> Ash.read!(tenant: other)
    end
  end

  describe "a missing tenant" do
    # The hazard this whole describe block exists for: an empty result here would read
    # as "no such row" at a login form, an availability check or a dedupe pass, and it
    # would sail through review.
    setup do
      doc =
        EtsSecretDoc
        |> Ash.Changeset.for_create(:create, %{label: "classified"})
        |> Ash.create!(tenant: "some_tenant")

      %{doc: doc}
    end

    test "filter_by/4 raises MissingScope" do
      assert_raise AshVault.Errors.MissingScope, fn ->
        AshVault.Query.filter_by(EtsSecretDoc, :label, "classified", nil)
      end
    end

    test "the generated read action errors, and specifically does NOT return {:ok, []}" do
      result =
        EtsSecretDoc
        |> Ash.Query.for_read(:by_label, %{label: "classified"})
        |> Ash.read()

      # Assert the negative explicitly. An error-class assertion alone would still pass
      # if someone later "fixed" this into a silent empty filter.
      refute result == {:ok, []}

      assert {:error, %Ash.Error.Invalid{errors: errors}} = result
      assert Enum.any?(errors, &match?(%AshVault.Errors.MissingScope{}, &1))
    end

    test "Ash.read! on the generated action raises" do
      assert_raise Ash.Error.Invalid, fn ->
        EtsSecretDoc
        |> Ash.Query.for_read(:by_label, %{label: "classified"})
        |> Ash.read!()
      end
    end

    test "with a tenant it finds the row, so the tests above are not vacuous", %{doc: doc} do
      assert [%{id: id}] =
               EtsSecretDoc
               |> Ash.Query.for_read(:by_label, %{label: "classified"}, tenant: "some_tenant")
               |> Ash.read!(tenant: "some_tenant")

      assert id == doc.id
    end
  end

  describe "a destroyed scope" do
    test "filter_by/4 raises KeyDestroyed rather than returning zero rows", %{org: org} do
      create!(org, %{email: "erased@example.com"})

      assert :ok = AshVault.destroy_keys!(AshVault.Test.Vault, org)

      assert_raise AshVault.Errors.KeyDestroyed, fn ->
        AshVault.Query.filter_by(EtsAccount, :email, "erased@example.com", tenant: org)
      end
    end

    test "the generated read action errors rather than returning {:ok, []}", %{org: org} do
      create!(org, %{email: "erased@example.com"})
      assert :ok = AshVault.destroy_keys!(AshVault.Test.Vault, org)

      result =
        EtsAccount
        |> Ash.Query.for_read(:by_email, %{email: "erased@example.com"}, tenant: org)
        |> Ash.read(tenant: org)

      refute result == {:ok, []}
      assert {:error, %Ash.Error.Invalid{errors: errors}} = result
      assert Enum.any?(errors, &match?(%AshVault.Errors.KeyDestroyed{}, &1))
    end
  end

  describe "a provider with no lookup_key/1" do
    test "AshVault.KeyProvider.lookup_key/2 reports it rather than raising UndefinedFunctionError" do
      assert {:error, :lookup_unsupported} =
               AshVault.KeyProvider.lookup_key(AshVault.Test.Support.UnavailableProvider, "scope")
    end

    test "supports_lookup?/1 is true for the shipped providers" do
      for provider <- [
            AshVault.KeyProviders.Memory,
            AshVault.KeyProviders.Local,
            AshVault.KeyProviders.OpenBao
          ] do
        assert AshVault.KeyProvider.supports_lookup?(provider), inspect(provider)
      end
    end

    test "reaches the write path as LookupUnsupported, not ProviderUnavailable" do
      # The verifier cannot see the provider behind a `fun/2` vault, so this resource
      # compiles and fails at runtime instead — permanently, and saying what to do.
      assert {:error, error} =
               AshVault.Test.EtsNoLookupDoc
               |> Ash.Changeset.for_create(:create, %{label: "x"})
               |> Ash.create()

      assert %Ash.Error.Invalid{errors: errors} = error
      assert [%AshVault.Errors.LookupUnsupported{} = unsupported] = errors

      message = Exception.message(unsupported)
      assert message =~ "AshVault.Test.Support.NoLookupProvider"
      assert message =~ "does not implement `AshVault.KeyProvider.lookup_key/1`"
      assert message =~ "It must NOT be derived from the key `current_key/1` returns"
    end

    test "supports_lookup?/1 unwraps a Cached wrapper to the provider underneath" do
      refute AshVault.KeyProvider.supports_lookup?(AshVault.Test.Support.CachedNoLookupProvider)

      assert AshVault.KeyProvider.supports_lookup?(AshVault.Test.Support.CachedMemoryProvider)
    end
  end

  # `field_key/3` resolved the scope by calling `scope.resolve!/1` itself, which skipped
  # the single place that enforces "a scope is a binary". The invariant still failed —
  # loudly — but as an `ArgumentError` raised by whichever provider's `validate_scope!/1`
  # saw the term first, naming the provider rather than the scope module that produced
  # it, and leaking out of a non-bang `Ash.read/2` in a shape no caller matches on.
  describe "a scope that is not a binary (ashvault-8i0)" do
    test "field_key/3 returns InvalidScope, not the provider's ArgumentError" do
      assert {:error, %AshVault.Errors.InvalidScope{} = error} =
               AshVault.Lookup.field_key(EtsNonBinaryScopeDoc, :email, %AshVault.Context{
                 resource: EtsNonBinaryScopeDoc,
                 field: :email,
                 ash_context: %{}
               })

      # The scope module, not the key provider: this is the whole point of routing
      # through the runtime. The old `ArgumentError` named the provider, and being an
      # `ArgumentError` it was not in `field_key/3`'s rescue list at all, so it escaped
      # a non-bang `Ash.read/2` raw.
      assert error.scope_module == AshVault.Test.Support.NonBinaryScope
      assert error.resource == EtsNonBinaryScopeDoc
      assert error.field == :email
      assert Exception.message(error) =~ "which is not a binary"

      # The term is described, never printed.
      assert error.scope == "a 2-tuple"
    end

    test "filter_by/4 raises InvalidScope rather than the provider's ArgumentError" do
      error =
        assert_raise AshVault.Errors.InvalidScope, fn ->
          AshVault.Query.filter_by(EtsNonBinaryScopeDoc, :email, "someone@example.com")
        end

      assert error.scope_module == AshVault.Test.Support.NonBinaryScope
    end

    # The encrypt path already raised `InvalidScope` before this fix — it went through
    # `Runtime.encrypt!/3`. Asserted here so the two halves of one write are visibly the
    # same error, which is the property that was broken: the ciphertext column failed
    # with `InvalidScope` while the lookup column failed with `ArgumentError`.
    test "the encrypt half of the same write raises the identical error" do
      error =
        assert_raise Ash.Error.Invalid, fn ->
          EtsNonBinaryScopeDoc
          |> Ash.Changeset.for_create(:create, %{email: "someone@example.com"})
          |> Ash.create!()
        end

      assert Enum.any?(error.errors, &match?(%AshVault.Errors.InvalidScope{}, &1))
    end
  end
end
