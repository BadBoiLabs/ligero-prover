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

#include <zkp/nonbatch_context.hpp>
#include <zkp/finite_field_gmp.hpp>
#include <zkp/witness_observer.hpp>

namespace ligero::vm::zkp {

// Random policy with all checks disabled: no randomness is allocated or used,
// making a single-pass trace execution lightweight.
struct trace_random_policy {
    static constexpr bool pad_encoding_random    = false;
    static constexpr bool enable_code_check      = false;
    static constexpr bool enable_linear_check    = false;
    static constexpr bool enable_quadratic_check = false;
};

// Minimal executor that satisfies nonbatch_context_base without any GPU.
// Only message_size() and padding_size() are required by the base class.
struct null_executor {
    null_executor(size_t message_size, size_t padding_size)
        : msg_(message_size), pad_(padding_size) {}

    size_t message_size() const { return msg_; }
    size_t padding_size() const { return pad_; }

private:
    size_t msg_, pad_;
};

// Lightweight context for a single-pass constraint trace.
// All row callbacks are no-ops; constraint events are delivered to a
// witness_observer registered via set_observer().
template <typename Field = bn254_gmp>
struct trace_context
    : public nonbatch_context_base<Field, null_executor, trace_random_policy>
{
    using Base = nonbatch_context_base<Field, null_executor, trace_random_policy>;
    using typename Base::witness_row_type;

    static constexpr context_role role = context_role::prover;

    explicit trace_context(null_executor& exe)
        : Base(exe) {}

    void set_observer(witness_observer* obs) {
        this->backend().manager().set_observer(obs);
    }

    void linear_callback(witness_row_type) override {}
    void quadratic_callback(witness_row_type, witness_row_type, witness_row_type) override {}
    void mask_callback(mpz_vector&, mpz_vector&, mpz_vector&) override {}
};

}  // namespace ligero::vm::zkp
