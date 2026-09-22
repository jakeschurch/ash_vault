defmodule AshVault.Errors.SerializationFailed do
  @moduledoc """
  Raised when a value could not be dumped to (or cast back from) its embedded
  representation while being encrypted or decrypted.

  Lives in its own file rather than in `AshVault.Errors` because the crypto core owns
  that module; this error belongs to the Ash extension layer.
  """

  use Splode.Error, fields: [:resource, :field, :type, :reason], class: :invalid

  def message(%{resource: resource, field: field, type: type, reason: reason}) do
    """
    Could not serialize #{inspect(resource)}.#{field} (type #{inspect(type)}) for encryption.

    #{inspect(reason)}
    """
  end
end
