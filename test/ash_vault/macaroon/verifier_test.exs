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
          #{if Keyword.get(opts, :authorizers), do: "authorizers: [Ash.Policy.Authorizer],", else: ""}
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

  describe "authorize-phase caveats without MacaroonAllows" do
    @authorize "caveat :actions, {:array, :string}, phase: :authorize, check: AshVault.Macaroon.Caveats.ActionIn"

    test "warn when the resource's own policies never use the check" do
      assert {:warn, warning} = define(AshVault.Test.MacVerifyWarn, block(caveats: @authorize))
      assert warning =~ "MacaroonAllows"
    end

    test "do not warn when a policy uses it" do
      policies = """
      policies do
        policy always() do
          forbid_unless {AshVault.Checks.MacaroonAllows, macaroon: :m}
        end
      end
      """

      result =
        define(AshVault.Test.MacVerifyEnforced, block(caveats: @authorize),
          extra: policies,
          authorizers: true
        )

      assert result == :ok
    end

    test "do not warn when the macaroon requires asserted enforcement" do
      caveats = @authorize <> "\n      require_authorize_enforcement? true"
      assert :ok = define(AshVault.Test.MacVerifyStrict, block(caveats: caveats))
    end
  end

  describe "dynamic options" do
    test "a function default_ttl without a finite max_ttl is rejected" do
      macaroon = """
          macaroon :m do
            prefix "avver"
            identity :id
            default_ttl fn _input -> 60 end
          end
      """

      assert_error(define(AshVault.Test.MacVerifyTtlFn, macaroon), "requires a finite `max_ttl`")
    end

    test "a static default_ttl above max_ttl is rejected" do
      macaroon = """
          macaroon :m do
            prefix "avver"
            identity :id
            default_ttl 120
            max_ttl 60
          end
      """

      assert_error(define(AshVault.Test.MacVerifyTtlMax, macaroon), "exceeds `max_ttl`")
    end

    test "an accepted_key_versions MFA must exist" do
      macaroon = """
          macaroon :m do
            prefix "avver"
            identity :id
            default_ttl 60
            accepted_key_versions {AshVault.Test.NoSuchWindow, :window, []}
          end
      """

      assert_error(define(AshVault.Test.MacVerifyWindow, macaroon), "window/1")
    end
  end
end
