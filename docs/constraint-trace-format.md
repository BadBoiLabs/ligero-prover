# Constraint Trace Format

`constraint_trace` executes a WASM program and emits one event per line describing
every witness allocation, constraint, and deallocation that would occur during a
Ligero proof.

## Running

```bash
./constraint_trace '{"program":"app.wasm","args":[{"i64":42}]}'
./constraint_trace '{"program":"app.wasm","args":[{"i64":42}],"output":"app.trace"}'
```

## Witness lifecycle

Every field element in the proof is a **witness** identified by an integer `id`
assigned sequentially from 0.

```
ACQUIRE      id=0  val=42
...
RELEASE      id=0  val=42  status=linear_ready
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
  | `quadratic_pending` | quadratic slot not yet full |
  | `quadratic_ready` | quadratic constraint row complete |
  | `not_a_witness` | committed as a constant, not a secret witness |

## Constraint events

Constraint events describe the arithmetic relationship between witnesses.
They fire immediately after the output witness is computed, before RELEASE.

### Linear constraints

```
ADD          a=0  b=1  out=2       # out = a + b  (mod p)
SUB          a=0  b=1  out=2       # out = a - b  (mod p)
MUL_CONST    a=0  k=2  out=1       # out = a * k  (mod p)
ADD_CONST    a=0  k=1  out=1       # out = a + k  (mod p)
SUB_CONST    a=0  k=1  out=1       # out = a - k  (mod p)
CONST_SUB    k=1  a=0  out=1       # out = k - a  (mod p)
BITWISE_NOT  a=0  out=1            # out = 1 - a  (a must be 0 or 1)
```

### Quadratic constraints

```
MUL          a=0  b=1  out=2       # out = a * b  (mod p)
BITWISE_AND  a=0  b=1  out=2       # out = a & b  (a,b must be 0 or 1)
```

### Structural constraints

```
EQUAL        a=0  b=1              # assert a == b
CONSTANT     id=0  val=42          # assert witness 0 == 42
BIT          id=0                  # assert witness 0 ∈ {0, 1}
```

## Field values

All field arithmetic is mod the BN254 scalar field prime
(`21888242871839275222246405745257275088548364400416034343698204186575808495617`).
Values are printed as decimal integers. For large field elements (e.g. cryptographic
hash outputs) these will be long strings.

## Unknown operand IDs (`?`)

When an arithmetic operation is applied to a nested sub-expression rather than a
directly named witness, the operand ID is shown as `?`. This occurs in folded
expressions such as `a + b + c`, where the intermediate `a + b` result may not
have been allocated as a named witness before being consumed.

## Unconstrained compute events

When a guest program calls `bn254fr_addmod`, `bn254fr_mulmod`, etc. **without** a
corresponding `bn254fr_assert_*` call, the arithmetic is computed but **not constrained**
in the proof. These appear as compute events distinct from the constraint events above.

```
ADDMOD       out=1  x=1  y=3     # out->val = x->val + y->val  (mod p, no constraint)
SUBMOD       out=N  x=N  y=N
MULMOD       out=N  x=N  y=N
DIVMOD       out=N  x=N  y=N
INVMOD       out=N  x=N
NEGMOD       out=N  x=N
POWMOD       out=N  x=N  y=N
IDIV         out=N  x=N  y=N     # integer floor division
IREM         out=N  x=N  y=N     # integer floor remainder
COPY         dst=N  src=N        # dst->val = src->val
```

For in-place operations (e.g. `a.addmod(&b)` in the Rust SDK, where `out == x`),
the RELEASE event for `out` will show the post-operation value. For example:

```
ACQUIRE      id=1   val=9999
ACQUIRE      id=3   val=88888
ADDMOD       out=1  x=1  y=3
RELEASE      id=3   val=88888  status=not_a_witness
RELEASE      id=1   val=98887  status=linear_ready
```

> **Note:** An ADDMOD event means the value was computed but is **not** a ZK constraint.
> To constrain it, the program must separately call `bn254fr_assert_add`, which emits a
> `LINEAR` event.

## Limitations

- `vbn254fr` (GPU-vectorised batch field operations) is not traced. Programs that
  call `vbn254fr_*` host functions will abort at runtime with a missing-module error.
  All scalar `bn254fr`, `uint256`, WASI, and `env` functions are fully traced.
