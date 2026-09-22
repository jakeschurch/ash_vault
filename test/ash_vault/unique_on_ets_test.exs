defmodule AshVault.UniqueOnEtsTest do
  @moduledoc """
  `unique?: true` on a data layer that cannot enforce an identity itself.

  PostgreSQL enforces `<field>_lookup` uniqueness with a real unique index and needs
  nothing else. ETS and Mnesia have no such mechanism: Ash refuses to accept an identity
  there without `pre_check_with`
  (`deps/ash/lib/ash/data_layer/verifiers/require_pre_check_with.ex:26-40`), and AshVault
  will not set it silently, because it is a read action on every write
  (`deps/ash/lib/ash/changeset/changeset.ex:3261-3330`).
  """

  use ExUnit.Case, async: false

  alias AshVault.KeyProviders.Memory

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  defmodule EtsUniqueUser do
    @moduledoc false
    use Ash.Resource,
      domain: AshVault.UniqueOnEtsTest.Domain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshVault]

    ash_vault do
      vault AshVault.Test.Support.GlobalVault
      scope :global

      encrypt :email,
        searchable?: true,
        unique?: true,
        normalize: :downcase_trim,
        pre_check_with: AshVault.UniqueOnEtsTest.Domain
    end

    attributes do
      uuid_primary_key :id
      attribute :email, :string, public?: true
    end

    actions do
      default_accept :*
      defaults [:read, :destroy, create: :*, update: :*]
    end
  end

  setup do
    start_supervised!({Memory, name: Memory})
    Ash.DataLayer.Ets.stop(EtsUniqueUser)
    :ok
  end

  defp create(email) do
    EtsUniqueUser
    |> Ash.Changeset.for_create(:create, %{email: email})
    |> Ash.create()
  end

  describe "with pre_check_with" do
    test "the option lands on the generated identity" do
      assert %Ash.Resource.Identity{keys: [:email_lookup], pre_check_with: Domain} =
               Ash.Resource.Info.identity(EtsUniqueUser, :email_lookup_unique)
    end

    test "a duplicate is actually rejected" do
      assert {:ok, _first} = create("dup@example.com")
      assert {:error, %Ash.Error.Invalid{}} = create("dup@example.com")

      assert 1 == length(Ash.read!(EtsUniqueUser))
    end

    test "the pre-check sees the token, not a nil" do
      # This is the property the whole thing rests on: the pre-check hook runs *after*
      # `AshVault.Changes.Encrypt`, so `email_lookup` is populated when the check queries
      # for it. If it ran first the token would be nil, `nils_distinct?: true` would skip
      # the check entirely, and duplicates would land with nothing raised — which is why
      # this asserts the duplicate is rejected through the *normalization*, something only
      # a real token comparison can do.
      assert {:ok, _first} = create("norm@example.com")
      assert {:error, %Ash.Error.Invalid{}} = create("  Norm@Example.COM  ")

      assert 1 == length(Ash.read!(EtsUniqueUser))
    end

    test "a different value is fine, and nils never conflict" do
      assert {:ok, _} = create("a@example.com")
      assert {:ok, _} = create("b@example.com")
      assert {:ok, _} = create(nil)
      assert {:ok, _} = create(nil)

      assert 4 == length(Ash.read!(EtsUniqueUser))
    end
  end

  describe "without pre_check_with" do
    test "unique?: true is a DSL error naming the option, not an Ash internals message" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          Code.compile_string("""
          defmodule AshVault.UniqueOnEtsTest.NoPreCheck do
            use Ash.Resource,
              domain: AshVault.UniqueOnEtsTest.Domain,
              data_layer: Ash.DataLayer.Ets,
              extensions: [AshVault]

            ash_vault do
              vault AshVault.Test.Support.GlobalVault
              scope :global

              encrypt :email, searchable?: true, unique?: true
            end

            attributes do
              uuid_primary_key :id
              attribute :email, :string, public?: true
            end

            actions do
              default_accept :*
              defaults [:read, create: :*]
            end
          end
          """)
        end

      message = Exception.message(error)

      assert message =~ "needs `pre_check_with:`"
      assert message =~ "Ash.DataLayer.Ets"
      assert message =~ "pre_check_with: MyApp.Domain"
      assert message =~ "query per write"
      assert message =~ "not race-free"

      # It must NOT be Ash's own message, which names an identity the user never wrote.
      refute message =~ "The data layer does not support native checking of identities"
    end

    test "searchable?: true alone still compiles on ETS" do
      Code.compile_string("""
               defmodule AshVault.UniqueOnEtsTest.SearchableOnly do
                 use Ash.Resource,
                   domain: AshVault.UniqueOnEtsTest.Domain,
                   data_layer: Ash.DataLayer.Ets,
                   extensions: [AshVault]

                 ash_vault do
                   vault AshVault.Test.Support.GlobalVault
                   scope :global

                   encrypt :email, searchable?: true, normalize: :downcase_trim
                 end

                 attributes do
                   uuid_primary_key :id
                   attribute :email, :string, public?: true
                 end

                 actions do
                   default_accept :*
                   defaults [:read, create: :*]
                 end
      end
      """)

      module = AshVault.UniqueOnEtsTest.SearchableOnly

      assert [] == Ash.Resource.Info.identities(module)
      assert Ash.Resource.Info.attribute(module, :email_lookup)
      assert Ash.Resource.Info.action(module, :by_email)
    end
  end

  describe "postgres needs none of it" do
    test "the generated identity has no pre_check_with, so no read is added per write" do
      assert %Ash.Resource.Identity{pre_check_with: nil, eager_check_with: nil} =
               Ash.Resource.Info.identity(AshVault.Test.SearchUser, :email_lookup_unique)
    end
  end
end
