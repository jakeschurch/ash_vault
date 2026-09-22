# Measures where AES-256-GCM crosses the BEAM's ~1 ms per-NIF budget on this machine,
# which is what the dirty-scheduler threshold in AshVaultRustler.Cipher is set from.
alias AshVaultRustler.Native

key = :crypto.strong_rand_bytes(32)
aad = "ashvault:v1|acme|MyApp.User|ssn"

bench = fn label, fun, iterations ->
  fun.()
  {micros, _} = :timer.tc(fn -> for _ <- 1..iterations, do: fun.() end)
  per_op = micros / iterations
  IO.puts(:io_lib.format("~-34s ~10.3f us/op", [label, per_op]) |> to_string())
  per_op
end

IO.puts("\n== AES-256-GCM encrypt, normal scheduler ==")

for size <- [16, 64, 256, 1_024, 4_096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304] do
  pt = :crypto.strong_rand_bytes(size)
  iterations = max(div(20_000_000, size + 64), 20)
  bench.("rust  #{size} B", fn -> Native.encrypt(key, pt, aad) end, iterations)
end

IO.puts("\n== AES-256-GCM encrypt, dirty CPU scheduler ==")

for size <- [16, 1_024, 65_536, 1_048_576, 4_194_304] do
  pt = :crypto.strong_rand_bytes(size)
  iterations = max(div(20_000_000, size + 64), 20)
  bench.("rust dirty #{size} B", fn -> Native.encrypt_dirty(key, pt, aad) end, iterations)
end

IO.puts("\n== OTP :crypto, for reference ==")

for size <- [16, 1_024, 65_536, 1_048_576] do
  pt = :crypto.strong_rand_bytes(size)
  iterations = max(div(20_000_000, size + 64), 20)

  bench.(
    "otp   #{size} B",
    fn ->
      AshVault.Ciphers.AES.GCM.encrypt(pt, key, aad)
    end,
    iterations
  )
end

IO.puts("\n== Cache fetch (DashMap) vs ETS ==")

{:ok, _} =
  AshVaultRustler.KeyCache.start_link(name: :bench_cache, max_entries: 1024, max_bytes: 1_048_576)

:ok =
  AshVaultRustler.KeyCache.put(
    :bench_cache,
    "acme",
    :current,
    {:key_info, %{version: 1, key: key, created_at: DateTime.utc_now()}},
    60_000,
    0
  )

bench.(
  "rust cache_fetch",
  fn -> AshVaultRustler.KeyCache.fetch(:bench_cache, "acme", :current) end,
  200_000
)

{:ok, _} =
  AshVault.KeyCaches.ETS.start_link(name: :bench_ets, max_entries: 1024, max_bytes: 1_048_576)

:ok =
  AshVault.KeyCaches.ETS.put(
    :bench_ets,
    "acme",
    :current,
    {:key_info, %{version: 1, key: key, created_at: DateTime.utc_now()}},
    60_000,
    0
  )

bench.(
  "ets  fetch",
  fn -> AshVault.KeyCaches.ETS.fetch(:bench_ets, "acme", :current) end,
  200_000
)

bench.(
  "rust evict_scope",
  fn -> AshVaultRustler.KeyCache.evict_scope(:bench_cache, "acme") end,
  50_000
)
