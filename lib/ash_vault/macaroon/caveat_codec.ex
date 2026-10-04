defmodule AshVault.Macaroon.CaveatCodec do
  @moduledoc """
  The frozen, self-describing byte encoding of one caveat.

      caveat := name_len::8  name  tag::8  value

  `name` is 1–63 bytes of `[a-z][a-z0-9_]*`. `tag` and `value`:

  | tag    | type                                    | value bytes                                 |
  | ------ | --------------------------------------- | ------------------------------------------- |
  | `0x01` | `:string`                               | `len::16 utf8`                              |
  | `0x02` | `:integer`                              | `signed-big-64`                             |
  | `0x03` | `:boolean`                              | `0x00` or `0x01`                            |
  | `0x04` | `:utc_datetime`, `:utc_datetime_usec`   | unix microseconds, `signed-big-64`          |
  | `0x05` | `{:array, :string}`                     | `count::8` then `count` × `len::16 utf8`    |
  | `0x06` | `{:array, :integer}`                    | `count::8` then `count` × `signed-big-64`   |

  Self-describing so that `AshVault.Macaroon.attenuate/2` can append a caveat without
  knowing the resource it is for; the verifier then checks each decoded tag against the
  type the `caveat` entity declares and fails closed on any disagreement.

  Decoding is strict: the value must consume the caveat exactly, strings must be valid
  UTF-8, and the decoded value must re-encode to the identical bytes. There is exactly
  one encoding of any caveat, so no two byte strings mean the same thing.
  """

  @max_name_bytes 63
  @max_list 32
  @max_caveat_bytes 256

  @type tag :: :string | :integer | :boolean | :datetime | :string_list | :integer_list
  @type value ::
          binary() | integer() | boolean() | DateTime.t() | [binary()] | [integer()]

  @min_int -0x8000000000000000
  @max_int 0x7FFFFFFFFFFFFFFF

  @doc "The largest encoded caveat accepted, in bytes: #{@max_caveat_bytes}."
  @spec max_caveat_bytes() :: pos_integer()
  def max_caveat_bytes, do: @max_caveat_bytes

  @doc """
  The value tag an Ash type encodes under, or `:error` for a type with no stable encoding.
  """
  @spec tag_for_type(term()) :: {:ok, tag()} | :error
  def tag_for_type({:array, inner}) do
    case tag_for_type(inner) do
      {:ok, :string} -> {:ok, :string_list}
      {:ok, :integer} -> {:ok, :integer_list}
      _other -> :error
    end
  end

  def tag_for_type(type) do
    case Ash.Type.get_type(type) do
      Ash.Type.String -> {:ok, :string}
      Ash.Type.Integer -> {:ok, :integer}
      Ash.Type.Boolean -> {:ok, :boolean}
      Ash.Type.UtcDatetime -> {:ok, :datetime}
      Ash.Type.UtcDatetimeUsec -> {:ok, :datetime}
      _other -> :error
    end
  end

  @doc """
  The tag an Elixir value encodes under, inferred from its shape. Used by `attenuate/2`,
  which has no declaration to consult.
  """
  @spec infer_tag(term()) :: {:ok, tag()} | :error
  def infer_tag(value) when is_binary(value), do: {:ok, :string}
  def infer_tag(value) when is_boolean(value), do: {:ok, :boolean}
  def infer_tag(value) when is_integer(value), do: {:ok, :integer}
  def infer_tag(%DateTime{}), do: {:ok, :datetime}

  def infer_tag([_ | _] = list) do
    cond do
      Enum.all?(list, &is_binary/1) -> {:ok, :string_list}
      Enum.all?(list, &is_integer/1) -> {:ok, :integer_list}
      true -> :error
    end
  end

  def infer_tag(_value), do: :error

  @doc """
  Encode one caveat. `{:error, reason}` for a name, value or size outside the format.
  """
  @spec encode(binary(), tag(), value()) :: {:ok, binary()} | {:error, atom()}
  def encode(name, tag, value) when is_binary(name) do
    with :ok <- check_name(name),
         {:ok, tag_byte, value_bytes} <- encode_value(tag, value) do
      bytes = <<byte_size(name)::8, name::binary, tag_byte::8, value_bytes::binary>>

      if byte_size(bytes) <= @max_caveat_bytes,
        do: {:ok, bytes},
        else: {:error, :caveat_too_large}
    end
  end

  @doc """
  Decode one caveat into `{name, tag, value}`, strictly. `:error` for anything that is
  not the unique canonical encoding of a caveat.
  """
  @spec decode(binary()) :: {:ok, {binary(), tag(), value()}} | :error
  def decode(<<name_len::8, name::binary-size(name_len), tag_byte::8, rest::binary>> = bytes)
      when byte_size(bytes) <= @max_caveat_bytes do
    with :ok <- check_name(name),
         {:ok, tag, value} <- decode_value(tag_byte, rest),
         {:ok, ^bytes} <- encode(name, tag, value) do
      {:ok, {name, tag, value}}
    else
      _ -> :error
    end
  end

  def decode(_bytes), do: :error

  defp check_name(name) do
    if byte_size(name) in 1..@max_name_bytes and name =~ ~r/\A[a-z][a-z0-9_]*\z/,
      do: :ok,
      else: {:error, :invalid_caveat_name}
  end

  defp encode_value(:string, value) when is_binary(value) do
    with {:ok, bytes} <- encode_string(value), do: {:ok, 0x01, bytes}
  end

  defp encode_value(:integer, value) when is_integer(value) do
    if in_range?(value), do: {:ok, 0x02, <<value::signed-big-64>>}, else: {:error, :out_of_range}
  end

  defp encode_value(:boolean, true), do: {:ok, 0x03, <<1>>}
  defp encode_value(:boolean, false), do: {:ok, 0x03, <<0>>}

  defp encode_value(:datetime, %DateTime{} = value) do
    case DateTime.shift_zone(value, "Etc/UTC") do
      {:ok, utc} ->
        usec = DateTime.to_unix(utc, :microsecond)

        if in_range?(usec),
          do: {:ok, 0x04, <<usec::signed-big-64>>},
          else: {:error, :out_of_range}

      _error ->
        {:error, :invalid_value}
    end
  end

  defp encode_value(:string_list, list) when is_list(list) and length(list) in 1..@max_list do
    list
    |> Enum.reduce_while({:ok, <<length(list)::8>>}, fn
      item, {:ok, acc} when is_binary(item) ->
        case encode_string(item) do
          {:ok, bytes} -> {:cont, {:ok, acc <> bytes}}
          error -> {:halt, error}
        end

      _item, _acc ->
        {:halt, {:error, :invalid_value}}
    end)
    |> case do
      {:ok, bytes} -> {:ok, 0x05, bytes}
      error -> error
    end
  end

  defp encode_value(:integer_list, list) when is_list(list) and length(list) in 1..@max_list do
    if Enum.all?(list, &(is_integer(&1) and in_range?(&1))) do
      {:ok, 0x06,
       IO.iodata_to_binary([<<length(list)::8>> | for(i <- list, do: <<i::signed-big-64>>)])}
    else
      {:error, :invalid_value}
    end
  end

  defp encode_value(_tag, _value), do: {:error, :invalid_value}

  defp encode_string(value) do
    if String.valid?(value) and byte_size(value) <= @max_caveat_bytes,
      do: {:ok, <<byte_size(value)::16, value::binary>>},
      else: {:error, :invalid_value}
  end

  defp in_range?(value), do: value >= @min_int and value <= @max_int

  defp decode_value(0x01, <<len::16, value::binary-size(len)>>), do: {:ok, :string, value}
  defp decode_value(0x02, <<value::signed-big-64>>), do: {:ok, :integer, value}
  defp decode_value(0x03, <<0>>), do: {:ok, :boolean, false}
  defp decode_value(0x03, <<1>>), do: {:ok, :boolean, true}

  defp decode_value(0x04, <<usec::signed-big-64>>) do
    case DateTime.from_unix(usec, :microsecond) do
      {:ok, datetime} -> {:ok, :datetime, datetime}
      _error -> :error
    end
  end

  defp decode_value(0x05, <<count::8, rest::binary>>) when count >= 1 do
    with {:ok, items} <- decode_strings(count, rest, []), do: {:ok, :string_list, items}
  end

  defp decode_value(0x06, <<count::8, rest::binary>>)
       when count >= 1 and byte_size(rest) == count * 8 do
    {:ok, :integer_list, for(<<i::signed-big-64 <- rest>>, do: i)}
  end

  defp decode_value(_tag, _rest), do: :error

  defp decode_strings(0, <<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_strings(count, <<len::16, item::binary-size(len), rest::binary>>, acc),
    do: decode_strings(count - 1, rest, [item | acc])

  defp decode_strings(_count, _rest, _acc), do: :error
end
