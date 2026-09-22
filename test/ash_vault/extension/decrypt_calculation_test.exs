defmodule AshVault.Extension.DecryptCalculationTest do
  # Not async: every vault talks to the default-named Memory provider.
  use ExUnit.Case, async: false

  alias AshVault.Calculations.Decrypt
  alias AshVault.Errors.CiphertextIntegrityFailed
  alias AshVault.Errors.InvalidCiphertext
  alias AshVault.Errors.KeyDestroyed
  alias AshVault.KeyProviders.Memory
  alias AshVault.Test.EtsUser

  setup do
    start_supervised!({Memory, name: Memory})
    :ok
  end

  defp create!(attrs, tenant) do
    EtsUser
    |> Ash.Changeset.for_create(
      :create,
      Map.merge(%{org_id: tenant, name: "n"}, Map.new(attrs)),
      tenant: tenant
    )
    |> Ash.create!()
  end

  defp calc_context(tenant) do
    %Ash.Resource.Calculation.Context{
      actor: nil,
      tenant: tenant,
      authorize?: false,
      tracer: nil,
      domain: AshVault.Test.Domain,
      resource: EtsUser,
      type: Ash.Type.String,
      constraints: [],
      arguments: %{},
      source_context: %{}
    }
  end

  @opts [field: :encrypted_email, plain_field: :email]

  describe "load/3" do
    test "declares the backing attribute as its only dependency" do
      assert Decrypt.load(nil, @opts, nil) == [:encrypted_email]
    end
  end

  describe "calculate/3" do
    test "an empty record list is an empty result" do
      assert Decrypt.calculate([], @opts, calc_context("acme")) == {:ok, []}
    end

    test "a nil backing value decrypts to nil" do
      record = %EtsUser{encrypted_email: nil}

      assert {:ok, [nil]} = Decrypt.calculate([record], @opts, calc_context("acme"))
    end

    test "%Ash.ForbiddenField{} is passed through untouched, never decrypted" do
      forbidden = %Ash.ForbiddenField{field: :encrypted_email, type: :attribute}
      record = %EtsUser{encrypted_email: forbidden}

      assert {:ok, [^forbidden]} = Decrypt.calculate([record], @opts, calc_context("acme"))
    end

    test "mixed records keep their positions" do
      user = create!(%{email: "a@b.c"}, "acme")
      forbidden = %Ash.ForbiddenField{field: :encrypted_email, type: :attribute}

      records = [
        %EtsUser{encrypted_email: nil},
        user,
        %EtsUser{encrypted_email: forbidden}
      ]

      assert {:ok, [nil, "a@b.c", ^forbidden]} =
               Decrypt.calculate(records, @opts, calc_context("acme"))
    end

    test "returns an error value instead of raising, and never :unknown" do
      record = %EtsUser{encrypted_email: "definitely not an envelope"}

      assert {:error, %InvalidCiphertext{}} =
               Decrypt.calculate([record], @opts, calc_context("acme"))
    end
  end

  describe "through Ash.read/2" do
    test "loads decrypted values" do
      create!(%{email: "a@b.c"}, "acme")

      assert {:ok, [user]} = Ash.read(EtsUser, tenant: "acme", load: [:email])
      assert user.email == "a@b.c"
    end

    test "decrypt_by_default is off for this resource, so the calculation is opt-in" do
      user = create!(%{email: "a@b.c"}, "acme")

      assert {:ok, [read]} = Ash.read(EtsUser, tenant: "acme")
      assert %Ash.NotLoaded{} = Map.get(read, :email)
      assert is_struct(user)
    end

    test "the loaded dependency stays on the struct, but is private and sensitive" do
      create!(%{email: "a@b.c"}, "acme")

      {:ok, [read]} = Ash.read(EtsUser, tenant: "acme", load: [:email])

      assert read.email == "a@b.c"

      # EXTENSION_SPEC §7 claims Ash strips the depended-on field from the record. It does
      # not: `query.context[:private][:depended_on_fields]` is only ever *subtracted* from
      # the deselect list in `deselect_known_forbidden_fields/4`
      # (deps/ash/lib/ash/actions/read/calculations.ex:2189-2225), so the ciphertext is
      # still on the struct afterwards. What actually keeps it out of API payloads is
      # `public?: false` plus `sensitive?: true` on the backing attribute.
      assert is_binary(Map.get(read, :encrypted_email))

      attribute = Ash.Resource.Info.attribute(EtsUser, :encrypted_email)
      refute attribute.public?
      assert attribute.sensitive?
      refute inspect(read) =~ "encrypted_email"
    end

    test "a destroyed scope reads back as a clean KeyDestroyed, not an exception" do
      create!(%{email: "a@b.c"}, "doomed")

      :ok = AshVault.destroy_keys!(AshVault.Test.Vault, "doomed")

      assert {:error, %Ash.Error.Invalid{errors: errors}} =
               Ash.read(EtsUser, tenant: "doomed", load: [:email])

      assert Enum.any?(errors, &match?(%KeyDestroyed{scope: "doomed"}, &1))
      refute Enum.any?(errors, &match?(%CiphertextIntegrityFailed{}, &1))
    end

    test "one tenant cannot read another's rows" do
      create!(%{email: "acme@b.c"}, "acme")
      create!(%{email: "other@b.c"}, "other")

      assert {:ok, [acme]} = Ash.read(EtsUser, tenant: "acme", load: [:email])
      assert {:ok, [other]} = Ash.read(EtsUser, tenant: "other", load: [:email])

      assert acme.email == "acme@b.c"
      assert other.email == "other@b.c"
    end
  end

  describe "calculation context" do
    test "from_calculation/3 falls back to source_context[:private][:tenant]" do
      context = %{
        tenant: nil,
        actor: nil,
        source_context: %{private: %{tenant: "acme"}}
      }

      built = AshVault.Context.Builder.from_calculation(EtsUser, :email, context)

      assert built.ash_context.tenant == "acme"
      assert built.ash_context.phase == :read
      assert built.resource == EtsUser
      assert built.field == :email
    end
  end
end
