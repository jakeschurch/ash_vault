spark_locals_without_parens = [
  attributes: 1,
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
