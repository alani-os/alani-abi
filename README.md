# alani-abi

Canonical syscall numbers, repr(C) structs, error codes, handle types, ABI versioning, and feature flags.

| Field | Value |
|---|---|
| Tier | MVK required |
| Owner | ABI owners |
| Aliases | None |
| Architectural dependencies | None |

## Quick start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-features -- -D warnings
```

## Scope

`alani-abi` is the dependency-free root contract shared by kernel, runtime, library, platform, and protocol crates. It provides:

- stable `AlaniStatus` values and Rust-side `AbiError` validation helpers;
- `AbiVersion`, `AbiHeader`, feature bitsets, and `sys_info` discovery records;
- `Handle`, typed handle aliases, `CapabilityHandle`, and capability rights masks;
- `UserBuffer`, `TraceContext`, `InferenceBudget`, syscall frames, returns, and a canonical syscall descriptor table.

The crate is `no_std` when built without the default `std` feature. ABI-facing structures use explicit `#[repr(C)]`, `#[repr(u32)]`, or transparent integer wrappers and avoid heap-owned Rust types at syscall boundaries.

Keep public API changes synchronized with `docs/repositories/alani-abi.md`, Doc 08, Doc 09, Doc 10, Doc 42, and Doc 43 in `alani-spec`.
