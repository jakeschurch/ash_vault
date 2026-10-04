defmodule AshVault.Macaroon.VerifierTest do
  # Not async: each test compiles a module.
  use ExUnit.Case, async: false

  defp define(name, macaroon_block, opts \\ []) do
    vault = Keyword.get(opts, :vault, "AshVault.Test.GlobalVault")
    scope = Keyword.get(opts, :scope, ":global")
    extra = Keyword.get(opts, :extra, "")

    ExUnit.CaptureIO.capture_io(:stderr, fn ->
      Code.eval_string("""
      defmodule #{name} do
        use Ash.Resource,
          domain: nil,
          validate_domain_inclusion?: false,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshVault]

        ash_vault do
          vault #{vault}
          scope #{scope}
      #{macaroon_block}
        end

        attributes do
          uuid_primary_key :id
          attribute :name, :string, public?: true
          attribute :meta, :map, public?: true
        end

        actions do
          defaults [:read, create: :*]
        end

      #{extra}
      end
      """)
    end)

    AshVault.Verifiers.VerifyMacaroons.verify(name.spark_dsl_config())
  end

  defp assert_error(result, fragment) do
    assert {:error, %Spark.Error.DslError{} = error} = result
    assert Exception.message(error) =~ fragment
  end

  defp block(opts) do
    """
        macaroon :m do
          prefix #{inspect(Keyword.get(opts, :prefix, "avver"))}
          identity #{inspect(Keyword.get(opts, :identity, :id))}
          default_ttl 60
          #{Keyword.get(opts, :caveats, "")}
        end
    """
  end

  test "a well-formed macaroon passes and generates actions and interfaces" do
    assert :ok = define(AshVault.Test.MacVerifyOk, block([]))
    assert Ash.Resource.Info.action(AshVault.Test.MacVerifyOk, :mint_m)
    assert Ash.Resource.Info.action(AshVault.Test.MacVerifyOk, :m_by_token).get?
    assert AshVault.Info.encrypted_fields(AshVault.Test.MacVerifyOk) == []
  end

  test "a prefix outside the charset is rejected" do
    assert_error(define(AshVault.Test.MacVerifyPrefix, block(prefix: "my_app")), "no underscore")
  end

  test "an identity that is not unique is rejected at compile time" do
    assert_raise Spark.Error.DslError, ~r/single primary key/, fn ->
      Code.eval_string("""
      defmodule AshVault.Test.MacVerifyIdentity do
        use Ash.Resource, domain: nil, validate_domain_inclusion?: false,
          data_layer: Ash.DataLayer.Ets, extensions: [AshVault]

        ash_vault do
          vault AshVault.Test.GlobalVault
          scope :global
      #{block(identity: :name)}
        end

        attributes do
          uuid_primary_key :id
          attribute :name, :string, public?: true
        end

        actions do
          defaults [:read]
        end
      end
      """)
    end
  end

  test "a caveat type with no stable encoding is rejected" do
    caveats = "caveat :meta, :map, check: fn _, _ -> true end"

    assert_error(
      define(AshVault.Test.MacVerifyType, block(caveats: caveats)),
      "no stable token encoding"
    )
  end

  test "the reserved :expires_at caveat is rejected" do
    caveats = "caveat :expires_at, :utc_datetime, check: fn _, _ -> true end"
    assert_error(define(AshVault.Test.MacVerifyReserved, block(caveats: caveats)), "reserved")
  end

  test "a check that is not a compiled caveat module is rejected" do
    caveats = "caveat :ip, :string, check: AshVault.Test.NotACaveat"
    assert_error(define(AshVault.Test.MacVerifyCheck, block(caveats: caveats)), "check/3")
  end

  test "a :tenant macaroon without multitenancy is rejected" do
    result =
      define(AshVault.Test.MacVerifyTenant, block([]),
        vault: "AshVault.Test.Vault",
        scope: ":tenant"
      )

    assert_error(result, "needs multitenancy")
  end

  test "a vault whose provider cannot serve :mac is rejected" do
    result =
      define(AshVault.Test.MacVerifyNoMac, block([]),
        vault: "AshVault.Test.Support.NoMacGlobalVault"
      )

    assert_error(result, "cannot serve :mac")
  end
end
