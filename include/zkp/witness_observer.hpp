/*
 * Copyright (C) 2023-2026 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstddef>
#include <limits>
#include <gmpxx.h>

#include <zkp/backend/lazy_witness.hpp>

namespace ligero::vm::zkp {

// Sentinel: input is an intermediate sub-expression with no single witness ID
inline constexpr size_t unknown_id = std::numeric_limits<size_t>::max();

// Observer interface for the constraint generation process.
//
// Events fire in execution order. Arithmetic events (on_add, on_mul, etc.)
// fire as soon as the output witness is created. on_release fires when the
// witness is garbage-collected by the WASM stack discipline. IDs increase
// monotonically with creation order.
//
// Input IDs may be unknown_id when the operand is a compile-time constant
// folded into a nested expression rather than a live witness.
struct witness_observer {
    virtual ~witness_observer() = default;

    // Fired when a witness with a known initial value is created — covers
    // constants, bit-decomposition outputs, and explicit witness allocations.
    // Arithmetic output witnesses appear only in the constraint events below.
    virtual void on_acquire(size_t id, const mpz_class& val) {}

    // Fired just before a witness is garbage-collected. val is the final
    // wire value. status distinguishes linear / quadratic / non-witness.
    virtual void on_release(size_t id, const mpz_class& val, commit_status status) {}

    // --- Arithmetic constraints -------------------------------------------
    // All field operations are mod p (the BN254 scalar field prime).
    // out = a + b  (mod p)
    virtual void on_add(size_t a, size_t b, size_t out) {}
    // out = a - b  (mod p)
    virtual void on_sub(size_t a, size_t b, size_t out) {}
    // out = a * b  (mod p)  — quadratic constraint
    virtual void on_mul(size_t a, size_t b, size_t out) {}

    // out = a + k  (mod p),  k is a compile-time constant
    virtual void on_add_const(size_t a, const mpz_class& k, size_t out) {}
    // out = a - k  (mod p)
    virtual void on_sub_const(size_t a, const mpz_class& k, size_t out) {}
    // out = k - a  (mod p)
    virtual void on_const_sub(const mpz_class& k, size_t a, size_t out) {}
    // out = a * k  (mod p),  linear constraint (k is constant)
    virtual void on_mul_const(size_t a, const mpz_class& k, size_t out) {}

    // out = 1 - a  (bit NOT; a must be in {0,1})
    virtual void on_bitwise_not(size_t a, size_t out) {}
    // out = a AND b = a * b  (a,b in {0,1})  — quadratic constraint
    virtual void on_bitwise_and(size_t a, size_t b, size_t out) {}

    // --- Structural constraints -------------------------------------------
    // a == b  (equality)
    virtual void on_equal(size_t a, size_t b) {}
    // id is a known public constant with value val
    virtual void on_constant(size_t id, const mpz_class& val) {}
    // id must be in {0, 1}
    virtual void on_bit(size_t id) {}
};

} // namespace ligero::vm::zkp
