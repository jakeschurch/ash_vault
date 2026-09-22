defmodule AshVault.Errors.SerializationFailedTest do
  @moduledoc """
  `AshVault.Errors.SerializationFailed` carries the raw return of an `Ash.Type` callback.

  Every *built-in* Ash type returns a bare `:error` or `{:error, index: 0}`, so nothing
  leaks from them today. But the `Ash.Type` contract permits
  `{:error, message: ..., value: ...}`, and a custom type that takes that option would put
  plaintext into an `Ash.Error` that Ash logs, renders and ships to APM.

  These tests use a type that leaks on purpose, both ways round: through `:value`, and
  through a `:message` with the value interpolated into it.
  """

  use ExUnit.Case, async: true

  alias AshVault.Errors.SerializationFailed
  alias AshVault.Serializer
  alias AshVault.Test.Support.Resources.User

  @secret "123-45-6789-SUPER-SECRET"

  defmodule LeakyType do
    @moduledoc false
    use Ash.Type

    @impl Ash.Type
    def storage_type(_constraints), do: :string

    @impl Ash.Type
    def cast_input(value, _constraints), do: {:ok, value}

    @impl Ash.Type
    def cast_stored(value, _constraints), do: {:ok, value}

    @impl Ash.Type
    def dump_to_native(value, _constraints), do: {:ok, value}

    # Both of the leaky shapes at once: a `:value` holding the plaintext, and a `:message`
    # with the plaintext interpolated into it.
    @impl Ash.Type
    def dump_to_embedded(value, _constraints) do
      {:error, message: "cannot dump #{inspect(value)}", value: value, field: :ssn, index: 3}
    end

    @impl Ash.Type
    def cast_from_embedded(value, _constraints) do
      {:error, [[message: "cannot cast #{inspect(value)}", value: value, index: 0]]}
    end
  end

  defp rendered(error), do: Exception.message(error) <> "\n" <> inspect(error, limit: :infinity)

  describe "a leaky custom type on the encrypt path" do
    test "the plaintext is in neither the message nor the struct" do
      error =
        assert_raise SerializationFailed, fn ->
          Serializer.serialize!(@secret, LeakyType, [], User, :ssn)
        end

      text = rendered(error)

      refute text =~ @secret
      refute text =~ "123-45"
      refute text =~ "cannot dump"
    end

    test "the diagnostic shape survives: which callback, which key, which index" do
      error =
        assert_raise SerializationFailed, fn ->
          Serializer.serialize!(@secret, LeakyType, [], User, :ssn)
        end

      assert {:dump_to_embedded, {:error, details}} = error.reason

      # Keys verbatim, so the operator can see exactly which options the type used.
      assert Keyword.keys(details) == [:message, :value, :field, :index]
      # Scalars that are code rather than data survive intact.
      assert details[:field] == :ssn
      assert details[:index] == 3
      # The two that could be the plaintext do not.
      assert details[:value] == {:redacted, :binary}
      assert details[:message] == {:redacted, :binary}

      # And the resource/field/type are still there to point at the culprit.
      assert error.resource == User
      assert error.field == :ssn
      assert error.type == LeakyType
    end
  end

  describe "a leaky custom type on the decrypt path" do
    setup do
      %{blob: <<"AVP", 1::8, :erlang.term_to_binary(@secret)::binary>>}
    end

    test "the plaintext is in neither the message nor the struct", %{blob: blob} do
      assert {:error, %SerializationFailed{} = error} =
               Serializer.deserialize(blob, LeakyType, [], User, :ssn)

      text = rendered(error)

      refute text =~ @secret
      refute text =~ "cannot cast"
    end

    test "nesting is walked, not skipped", %{blob: blob} do
      assert {:error, error} = Serializer.deserialize(blob, LeakyType, [], User, :ssn)

      assert {:cast_from_embedded, {:error, [inner]}} = error.reason
      assert inner[:index] == 0
      assert inner[:value] == {:redacted, :binary}
      assert inner[:message] == {:redacted, :binary}
    end
  end

  describe "built-in types are unaffected" do
    test "a bare :error round-trips verbatim" do
      assert SerializationFailed.redact_reason({:dump_to_embedded, :error}) ==
               {:dump_to_embedded, :error}
    end

    test "{:error, index: 0} round-trips verbatim" do
      assert SerializationFailed.redact_reason({:dump_to_embedded, {:error, index: 0}}) ==
               {:dump_to_embedded, {:error, [index: 0]}}
    end

    test "a real built-in type still produces a useful reason" do
      error =
        assert_raise SerializationFailed, fn ->
          Serializer.serialize!(%{not: "an integer"}, Ash.Type.Integer, [], User, :ssn)
        end

      assert {:dump_to_embedded, redacted} = error.reason
      refute inspect(redacted) =~ "an integer"
    end
  end

  describe "redact_reason/1 rules" do
    test "keeps atoms and integers, drops everything else by kind" do
      reason =
        SerializationFailed.redact_reason(
          {:dump_to_embedded, {:error, [a: :atom, b: 1, c: "s", d: 1.5, e: self()]}}
        )

      assert {:dump_to_embedded, {:error, details}} = reason
      assert details[:a] == :atom
      assert details[:b] == 1
      assert details[:c] == {:redacted, :binary}
      assert details[:d] == {:redacted, :float}
      assert details[:e] == {:redacted, :pid}
    end

    test "names a struct without printing it" do
      assert {:redacted, URI} = SerializationFailed.redact_reason(URI.parse("https://a.example"))
    end

    test "drops a map whose keys are not themselves code-shaped" do
      assert {:redacted, :map} =
               SerializationFailed.redact_reason(%{@secret => 1})
    end

    test "keeps a map whose keys are atoms, redacting the values" do
      assert %{ssn: {:redacted, :binary}} =
               SerializationFailed.redact_reason(%{ssn: @secret})
    end

    test "stops descending rather than following a deeply nested payload" do
      deep = Enum.reduce(1..20, @secret, fn _, acc -> [acc] end)

      refute inspect(SerializationFailed.redact_reason(deep)) =~ @secret
      assert inspect(SerializationFailed.redact_reason(deep)) =~ "redacted"
    end

    test "walks a non-keyword list element by element" do
      assert [{:redacted, :binary}, 1, :x] =
               SerializationFailed.redact_reason([@secret, 1, :x])
    end
  end
end
