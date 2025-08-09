## Configuration compatibility policy (Go bouncer → Rust bouncer)

- Reference file: `config/go-sample.yaml` is the canonical source for Go bouncer YAML keys and shapes to support for compatibility.
- Transformation point: All Go→Rust YAML normalization must happen in `compat_go_yaml` in `src/config.rs`.
- When adding or changing config keys:
  - First, update `config/go-sample.yaml` to reflect the Go-side schema you want to remain compatible with.
  - Then, update `compat_go_yaml` to map the Go keys to our internal Rust schema.
  - Keep `src/config.rs` serde structs idiomatic; use the transform function for compatibility rather than mixing aliases everywhere.
  - Prefer adding serde aliases only when a field is also used natively in the Rust schema.
- Scope priority: iptables compatibility first (nftables/pf to follow). Avoid adding nftables-only keys until the backend is implemented.
- Defaults: Align defaults with the Go bouncer’s behavior where applicable. Document any intentional deviations in `README.md`.
- Example YAML: `config/cs-firewall-bouncer.yaml.example` should stay consistent with the Rust-native schema. Do not copy Go-specific keys into it; keep them handled by the transform.


