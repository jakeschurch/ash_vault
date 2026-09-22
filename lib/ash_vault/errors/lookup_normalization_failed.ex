defmodule AshVault.Errors.LookupNormalizationFailed do
  @moduledoc """
  Raised when a searchable field's `normalize:` strategy did not produce a binary.

  A lookup token is `HMAC-SHA256(key, normalized_plaintext)`, so the normalized value
  has to be bytes. AshVault deliberately does not `to_string/1` whatever it was handed:
  `inspect/1` of a struct is a stable-looking string that would silently become the
  searchable identity of the row, and two structs differing only in a field `inspect`
  truncates would collide.

  The offending value is **described, never reproduced** — it is the plaintext of an
  encrypted field, and this error travels wherever Ash sends errors.
  """

  use Splode.Error, fields: [:resource, :field, :strategy, :value], class: :invalid

  @doc false
  def message(error) do
    """
    The `normalize:` strategy for #{inspect(error.resource)}.#{error.field} \
    (#{error.strategy}) returned #{error.value || "a non-binary value"}, but a lookup \
    token can only be computed from a binary.

    Either give the field a custom `normalize:` MFA that returns a binary, or drop
    `searchable?: true` from it.
    """
  end
end
