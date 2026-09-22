ExUnit.start(exclude: [:postgres, :openbao])

if :postgres in (ExUnit.configuration() |> Keyword.get(:include, [])) do
  AshVault.Test.Db.setup!()
end
