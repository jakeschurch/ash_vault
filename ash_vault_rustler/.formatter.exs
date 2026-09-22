[
  # `test/parent_support/` is deliberately absent. It holds a symlink to the parent's
  # contract suite, and formatting through a symlink would edit the parent's file.
  inputs: [
    "{mix,.formatter}.exs",
    "{config,lib,bench}/**/*.{ex,exs}",
    "test/**/*.exs",
    "test/support/**/*.ex"
  ],
  line_length: 98
]
