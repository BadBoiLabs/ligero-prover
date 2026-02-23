# Bug: Double `bn254fr_alloc` in Rust SDK constructors leaks witness slots

## Summary

`Bn254Fr::from_u32`, `Bn254Fr::from_u64`, and `Bn254Fr::from_c_str` each call
`bn254fr_alloc` twice, orphaning the first allocation.

## Affected file

`sdk/rust/src/bn254fr.rs`

## Root cause

`Bn254Fr::new()` already calls `_bn254fr_alloc` internally. The three constructors
call `Bn254Fr::new()` and then call `_bn254fr_alloc` a second time on the same
`out.data` handle, overwriting the pointer returned by the first call:

```rust
pub fn from_u64(value: u64) -> Self {
    let mut out = Bn254Fr::new();      // alloc #1 — handle stored in out.data
    unsafe {
        _bn254fr_alloc(&mut out.data); // alloc #2 — overwrites handle, #1 is lost
        _bn254fr_set_u64(&mut out.data, value);
    }
    out
}
```

The witness allocated by call #1 is never freed and never enters any constraint.
Its native pointer is simply lost.

## Impact

- One witness slot is leaked per call to `from_u32`, `from_u64`, or `from_c_str`.
- Proof correctness is unaffected: the orphaned witness carries no value and
  participates in no constraint.
- Witness IDs are non-consecutive in debug traces (e.g. IDs 0, 2, 4 are silently
  consumed, while 1, 3, 5 carry the actual values), which is confusing when
  reading constraint traces.

## Fix

Remove the redundant `_bn254fr_alloc` calls from the three constructors, since
`Bn254Fr::new()` already performs the allocation:

```rust
pub fn from_u64(value: u64) -> Self {
    let mut out = Bn254Fr::new();
    unsafe {
        _bn254fr_set_u64(&mut out.data, value);
    }
    out
}
```

The same one-line removal applies to `from_u32` and `from_c_str`.
