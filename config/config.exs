import Config

config :ash, default_string_length_count: :codepoints

config :ash_vault, ash_domains: []

config :spark,
  formatter: [
    remove_parens?: true,
    "Ash.Resource": [
      section_order: [
        :ash_vault,
        :attributes,
        :relationships,
        :actions,
        :policies,
        :field_policies,
        :calculations,
        :postgres
      ]
    ]
  ]

import_config "#{config_env()}.exs"
