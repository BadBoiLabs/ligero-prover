# Constraint Trace Format

`constraint_trace` executes a WASM program and emits one JSON object per line
(JSONL) describing every witness allocation, constraint, and deallocation that
would occur during a Ligero proof.

## Running

```bash
./constraint_trace '{"program":"app.wasm","args":[{"i64":42}]}'
./constraint_trace '{"program":"app.wasm","args":[{"i64":42}],"output":"app.trace"}'
```

## Format

Each line is a self-contained JSON object with a `"type"` field identifying the
event kind.  Witness ID fields (`"id"`, `"a"`, `"b"`, `"out"`) are JSON integers.
Field element values (`"val"`, `"k"`) are JSON strings containing decimal integers
(they may exceed 64-bit range for BN254 field elements).

## Witness lifecycle

Every field element in the proof is a **witness** identified by an integer `id`
assigned sequentially from 0.

```jsonl
{"type":"ACQUIRE","id":0,"val":"42"}
...
{"type":"RELEASE","id":0,"val":"42","status":"linear_ready"}
```

- **ACQUIRE** fires when a witness is created with a known value (input values,
  constants, bit-decomposition bits). Arithmetic output witnesses are created
  implicitly by their constraint event (see below) and do not fire ACQUIRE.
- **RELEASE** fires when the last reference to a witness is dropped — i.e. when
  the WASM stack or local variable holding it goes out of scope. The `status`
  field indicates how the witness was committed:

  | status | meaning |
  |---|---|
  | `linear_ready` | part of a linear constraint row, committed |
  | `quadratic_pending` | waiting — two of the three wires in this quadratic row have not released yet |
  | `quadratic_ready` | last wire in the row — quadratic row is now complete and committed |
  | `not_a_witness` | committed as a constant, not a secret witness |

  Quadratic RELEASE events carry a `"slot"` integer that is the same for all
  three witnesses forming one multiplication triple (`a`, `b`, `out = a*b`).
  This allows grouping without needing to inspect constraint events:

  ```jsonl
  {"type":"RELEASE","id":1,"val":"1","status":"quadratic_pending","slot":7}
  {"type":"RELEASE","id":8,"val":"0","status":"quadratic_pending","slot":7}
  {"type":"RELEASE","id":3,"val":"0","status":"quadratic_ready",  "slot":7}
  ```

  The three witnesses with `"slot":7` form one quadratic row. The row is
  committed when the `quadratic_ready` event fires.

## Constraint events

Constraint events describe the arithmetic relationship between witnesses.
They fire immediately after the output witness is computed, before RELEASE.

### Linear constraints

```jsonl
{"type":"ADD",        "a":0,"b":1,"out":2}           // out = a + b  (mod p)
{"type":"SUB",        "a":0,"b":1,"out":2}           // out = a - b  (mod p)
{"type":"MUL_CONST",  "a":0,"k":"2","out":1}         // out = a * k  (mod p)
{"type":"ADD_CONST",  "a":0,"k":"1","out":1}         // out = a + k  (mod p)
{"type":"SUB_CONST",  "a":0,"k":"1","out":1}         // out = a - k  (mod p)
{"type":"CONST_SUB",  "k":"1","a":0,"out":1}         // out = k - a  (mod p)
{"type":"BITWISE_NOT","a":0,"out":1}                 // out = 1 - a  (a must be 0 or 1)
{"type":"LINEAR",     "out":4,"a":1,"b":3}           // out = a + b  (mod p)  via bn254fr_assert_add
```

### Quadratic constraints

```jsonl
{"type":"MUL",        "a":0,"b":1,"out":2}           // out = a * b  (mod p)
{"type":"BITWISE_AND","a":0,"b":1,"out":2}           // out = a & b  (a,b must be 0 or 1)
{"type":"QUADRATIC",  "out":4,"a":1,"b":3}           // out = a * b  (mod p)  via bn254fr_assert_mul
```

### Structural constraints

```jsonl
{"type":"EQUAL",   "a":0,"b":1}                      // assert a == b
{"type":"CONSTANT","id":0,"val":"42"}                // assert witness 0 == 42
{"type":"BIT",     "id":0}                           // assert witness 0 ∈ {0, 1}
```

## Field values

All field arithmetic is mod the BN254 scalar field prime
(`21888242871839275222246405745257275088548364400416034343698204186575808495617`).
Values are strings containing decimal integers. For large field elements (e.g.
cryptographic hash outputs) these will be long strings.

## Unknown operand IDs (`null`)

When an arithmetic operation is applied to a nested sub-expression rather than a
directly named witness, the operand ID is `null`. This occurs in folded
expressions such as `a + b + c`, where the intermediate `a + b` result may not
have been allocated as a named witness before being consumed.

## Rust

```rust
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum TraceEvent {
    #[serde(rename = "ACQUIRE")]
    Acquire { id: u64, val: String },
    #[serde(rename = "RELEASE")]
    Release { id: u64, val: String, status: CommitStatus, slot: Option<u64> },
    #[serde(rename = "ADD")]
    Add { a: Option<u64>, b: Option<u64>, out: Option<u64> },
    #[serde(rename = "LINEAR")]
    Linear { out: Option<u64>, a: Option<u64>, b: Option<u64> },
    // ...
}
```

## Limitations

- `vbn254fr` (GPU-vectorised batch field operations) is not traced. Programs that
  call `vbn254fr_*` host functions will abort at runtime with a missing-module error.
  All scalar `bn254fr`, `uint256`, WASI, and `env` functions are fully traced.
