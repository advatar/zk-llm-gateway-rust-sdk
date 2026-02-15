# Contributing

Thanks for considering contributing!

## Development

- Rust stable
- Run:
  - `cargo fmt`
  - `cargo clippy --all-targets --all-features`
  - `cargo test --all-features`

## Design goals

- Keep the SDK small and dependency-light
- Favor conservative cryptographic choices
- Make privacy properties explicit and avoid over-claiming
- Keep wire formats versioned

## Pull requests

- Include tests where possible
- Update README if behavior changes
- Avoid breaking changes without bumping version and documenting
