defmodule Example.Accounts do
  @moduledoc "The example's Ash domain."

  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource Example.Accounts.Organization
    resource Example.Accounts.User
    resource Example.Accounts.AuthUser
    resource Example.Accounts.Contact
  end
end
