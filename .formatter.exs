spark_locals_without_parens = [
  accepted_key_versions: 1,
  attributes: 1,
  caveat: 2,
  caveat: 3,
  check: 1,
  default_ttl: 1,
  identity: 1,
  macaroon: 1,
  max_ttl: 1,
  macaroon: 2,
  mint_action: 1,
  phase: 1,
  prefix: 1,
  read_action: 1,
  require_authorize_enforcement?: 1,
  revoked_when: 1,
  backfill_from: 1,
  decrypt_by_default: 1,
  destroy: 1,
  encrypt: 1,
  encrypt: 2,
  encrypt_nil?: 1,
  normalize: 1,
  pre_check_with: 1,
  rotate: 1,
  scope: 1,
  scope_owner?: 1,
  searchable?: 1,
  unique?: 1,
  vault: 1
]

# Used by "mix format"
[
  import_deps: [:ash, :spark, :ash_postgres],
  inputs: ["{mix,.formatter}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  locals_without_parens: spark_locals_without_parens,
  export: [locals_without_parens: spark_locals_without_parens]
]
