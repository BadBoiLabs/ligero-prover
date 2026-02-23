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

// constraint_trace: execute a WASM program and emit a JSONL stream of witness
// lifecycle and constraint events to stdout (or a file).  One JSON object per
// line; every object has a "type" field identifying the event kind.
//
// Usage:
//   constraint_trace '<json-config>'
//
// JSON config fields:
//   program          (string, required) path to .wasm or .wat file
//   args             (array, optional)  program arguments; each element is one of:
//                      {"i64": <number>}
//                      {"str": "<string>"}
//                      {"hex": "0x<hex-bytes>"}
//   private-indices  (array, optional)  1-indexed argument indices treated as private
//   output           (string, optional) path to write events; default is stdout
//
// Note: vbn254fr (GPU-vectorised batch field ops) is not available in trace mode.
// Programs that call vbn254fr_* host functions will abort with a missing-module
// error at runtime.  All scalar bn254fr, uint256, WASI and env functions work.
//
// Event types emitted:
//   ACQUIRE, RELEASE, ADD, SUB, MUL, ADD_CONST, SUB_CONST, CONST_SUB,
//   MUL_CONST, BITWISE_NOT, BITWISE_AND, EQUAL, CONSTANT, BIT,
//   LINEAR, QUADRATIC
//
// Witness ID fields ("id", "a", "b", "out") are JSON integers, or null when the
// operand is an intermediate sub-expression with no allocated witness ID.
// Field element values ("val", "k") are JSON strings (decimal); BN254 values
// may exceed 64-bit range.
//
// RELEASE events for quadratic witnesses include a "slot" integer that groups
// the three witnesses (a, b, out) of each quadratic row: all three releases for
// the same multiplication triple share the same slot value.

#include <filesystem>
#include <fstream>
#include <iostream>
#include <unordered_set>

// Interpreter and runtime — but NOT invoke.hpp (which pulls in vbn254fr.hpp)
#include <cassert>
#include <runtime.hpp>
#include <interpreter.hpp>
#include <params.hpp>
#include <util/timer.hpp>

// Scalar-only host modules (no GPU executor dependency)
#include <host_modules/env.hpp>
#include <host_modules/bn254fr.hpp>
#include <host_modules/uint256.hpp>
#include <host_modules/wasi_preview1.hpp>

#include <zkp/finite_field_gmp.hpp>
#include <zkp/trace_context.hpp>
#include <zkp/witness_observer.hpp>

#include <boost/algorithm/hex.hpp>
#include <wabt/binary-reader-ir.h>
#include <wabt/binary-reader.h>
#include <wabt/error-formatter.h>
#include <wabt/wast-parser.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace ligero;
using namespace ligero::vm;
namespace fs = std::filesystem;

// ---- helpers ----------------------------------------------------------------

// Formats a field element value as a decimal string.
static std::string val_str(const mpz_class& v) {
    return v.get_str(10);
}

static const char* status_str(zkp::commit_status s) {
    using cs = zkp::commit_status;
    switch (s) {
        case cs::not_a_witness:     return "not_a_witness";
        case cs::linear_ready:      return "linear_ready";
        case cs::quadratic_pending: return "quadratic_pending";
        case cs::quadratic_ready:   return "quadratic_ready";
    }
    return "unknown";
}

// ---- observer ---------------------------------------------------------------

// Emits one JSON object per line (JSONL).
//
// Witness ID fields are JSON integers; unknown_id (intermediate sub-expression)
// is emitted as JSON null. Field element values are JSON strings (decimal).
struct jsonl_observer : zkp::witness_observer {
    explicit jsonl_observer(std::ostream& out) : out_(out) {}

    void on_acquire(size_t id, const mpz_class& val) override {
        emit({{"type","ACQUIRE"}, {"id",id}, {"val",val_str(val)}});
    }

    void on_release(size_t id, const mpz_class& val, zkp::commit_status s,
                    size_t slot_id = zkp::unknown_id) override {
        nlohmann::ordered_json j = {{"type","RELEASE"}, {"id",id}, {"val",val_str(val)},
                                    {"status",status_str(s)}};
        if (slot_id != zkp::unknown_id) j["slot"] = slot_id;
        emit(std::move(j));
    }

    void on_add(size_t a, size_t b, size_t out) override {
        emit({{"type","ADD"}, {"a",wid(a)}, {"b",wid(b)}, {"out",wid(out)}});
    }

    void on_sub(size_t a, size_t b, size_t out) override {
        emit({{"type","SUB"}, {"a",wid(a)}, {"b",wid(b)}, {"out",wid(out)}});
    }

    void on_mul(size_t a, size_t b, size_t out) override {
        emit({{"type","MUL"}, {"a",wid(a)}, {"b",wid(b)}, {"out",wid(out)}});
    }

    void on_add_const(size_t a, const mpz_class& k, size_t out) override {
        emit({{"type","ADD_CONST"}, {"a",wid(a)}, {"k",val_str(k)}, {"out",wid(out)}});
    }

    void on_sub_const(size_t a, const mpz_class& k, size_t out) override {
        emit({{"type","SUB_CONST"}, {"a",wid(a)}, {"k",val_str(k)}, {"out",wid(out)}});
    }

    void on_const_sub(const mpz_class& k, size_t a, size_t out) override {
        emit({{"type","CONST_SUB"}, {"k",val_str(k)}, {"a",wid(a)}, {"out",wid(out)}});
    }

    void on_mul_const(size_t a, const mpz_class& k, size_t out) override {
        emit({{"type","MUL_CONST"}, {"a",wid(a)}, {"k",val_str(k)}, {"out",wid(out)}});
    }

    void on_bitwise_not(size_t a, size_t out) override {
        emit({{"type","BITWISE_NOT"}, {"a",wid(a)}, {"out",wid(out)}});
    }

    void on_bitwise_and(size_t a, size_t b, size_t out) override {
        emit({{"type","BITWISE_AND"}, {"a",wid(a)}, {"b",wid(b)}, {"out",wid(out)}});
    }

    void on_equal(size_t a, size_t b) override {
        emit({{"type","EQUAL"}, {"a",wid(a)}, {"b",wid(b)}});
    }

    void on_constant(size_t id, const mpz_class& val) override {
        emit({{"type","CONSTANT"}, {"id",id}, {"val",val_str(val)}});
    }

    void on_bit(size_t id) override {
        emit({{"type","BIT"}, {"id",id}});
    }

    void on_linear(size_t out, size_t a, size_t b) override {
        emit({{"type","LINEAR"}, {"out",wid(out)}, {"a",wid(a)}, {"b",wid(b)}});
    }

    void on_quadratic(size_t out, size_t a, size_t b) override {
        emit({{"type","QUADRATIC"}, {"out",wid(out)}, {"a",wid(a)}, {"b",wid(b)}});
    }

private:
    // Returns a JSON value for a witness ID: integer, or null for unknown_id.
    static nlohmann::ordered_json wid(size_t id) {
        return id == zkp::unknown_id
            ? nlohmann::ordered_json(nullptr)
            : nlohmann::ordered_json(id);
    }

    void emit(nlohmann::ordered_json j) {
        out_ << j.dump() << '\n';
    }

    std::ostream& out_;
};

// ---- trace-specific invoke (omits vbn254fr which requires GPU) ---------------

template <typename Interpreter>
void invoke_trace(module_instance& module,
                  Interpreter& interp,
                  const std::vector<std::vector<u8>>& args,
                  const std::unordered_set<int>& indices)
{
    auto& ctx = interp.context();

    auto dummy = ctx.make_frame();
    dummy->module = &module;
    ctx.set_current_frame(dummy.get());
    ctx.stack_push(std::move(dummy));

    using Context = std::remove_reference_t<decltype(ctx)>;
    ctx.template add_host_module<wasi_preview1_module<Context>>(&ctx, args, indices);
    ctx.template add_host_module<env_module<Context>>(&ctx);
    ctx.template add_host_module<bn254fr_module<Context>>(&ctx);
    ctx.template add_host_module<uint256_module<Context>>(&ctx);
    // vbn254fr_module is intentionally omitted: it requires a GPU executor.

    try {
        auto result = interp.run(call{ module.exports["_start"] });
        if (result.is_exit()) {
            std::cout << "Exit with code " << result.exit_code() << '\n';
        }
    }
    catch (const wasm_trap& e) {
        throw e;
    }

    interp.context().stack_pop();
}

template <typename Context>
void run_trace_program(const wabt::Module& module,
                       Context& ctx,
                       const std::vector<std::vector<u8>>& args,
                       const std::unordered_set<int>& indices)
{
    store_t store;
    wasm_interpreter interp(ctx);
    ctx.store(&store);

    module_instance m = instantiate(store, module, interp);
    ctx.module(&m);

    invoke_trace(m, interp, args, indices);
    ctx.finalize();
}

// ---- main -------------------------------------------------------------------

int main(int argc, const char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: constraint_trace '<json-config>'\n"
                  << "  program (required), args, private-indices, output\n";
        return EXIT_FAILURE;
    }

    json jconfig;
    try {
        jconfig = json::parse(std::string_view(argv[1]));
    }
    catch (const json::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    if (!jconfig.contains("program")) {
        std::cerr << "Error: 'program' key missing from JSON config\n";
        return EXIT_FAILURE;
    }

    fs::path program_name = jconfig["program"].template get<std::string>();

    // Build input arguments (argv[0] is always "Ligero")
    std::vector<std::vector<u8>> input_args;
    {
        const std::string arg0("Ligero");
        input_args.emplace_back((u8*)arg0.c_str(), (u8*)arg0.c_str() + arg0.size() + 1);
    }

    if (jconfig.contains("args")) {
        for (const auto& arg : jconfig["args"]) {
            if (arg.contains("i64")) {
                auto i = arg["i64"].template get<int64_t>();
                input_args.emplace_back((u8*)&i, (u8*)&i + sizeof(int64_t));
            }
            else if (arg.contains("str")) {
                auto str = arg["str"].template get<std::string>();
                input_args.emplace_back((u8*)str.c_str(), (u8*)str.c_str() + str.size() + 1);
            }
            else if (arg.contains("hex")) {
                std::vector<u8> hex_vec;
                auto hex_str = arg["hex"].template get<std::string>();
                if (hex_str.starts_with("0x")) hex_str = hex_str.substr(2);
                if (hex_str.size() % 2 == 1) hex_str.insert(hex_str.begin(), '0');
                boost::algorithm::unhex(hex_str.c_str(), std::back_inserter(hex_vec));
                input_args.emplace_back(std::move(hex_vec));
            }
            else {
                std::cerr << "Error: unknown arg type: " << arg.dump() << '\n';
                return EXIT_FAILURE;
            }
        }
    }

    std::unordered_set<int> indices_set;
    if (jconfig.contains("private-indices")) {
        indices_set = jconfig["private-indices"].template get<std::unordered_set<int>>();
    }

    // Parse the WASM / WAT file
    std::unique_ptr<wabt::Module> wabt_module{ new wabt::Module{} };
    {
        std::vector<uint8_t> program_data;
        wabt::Result read_result = wabt::ReadFile(program_name.c_str(), &program_data);
        if (wabt::Failed(read_result)) {
            std::cerr << "Error: could not read \"" << program_name.c_str() << "\"\n";
            return EXIT_FAILURE;
        }

        wabt::Features wabt_features;
        wabt::Errors   parsing_errors;
        wabt::Result   parsing_result;

        if (program_name.extension() == ".wat" || program_name.extension() == ".wast") {
            std::unique_ptr<wabt::WastLexer> lexer = wabt::WastLexer::CreateBufferLexer(
                program_name.c_str(),
                program_data.data(),
                program_data.size(),
                &parsing_errors);

            wabt::WastParseOptions parse_wast_options(wabt_features);
            parsing_result = wabt::ParseWatModule(lexer.get(),
                                                  &wabt_module,
                                                  &parsing_errors,
                                                  &parse_wast_options);
        }
        else {
            parsing_result = wabt::ReadBinaryIr(program_name.c_str(),
                                                program_data.data(),
                                                program_data.size(),
                                                wabt::ReadBinaryOptions{},
                                                &parsing_errors,
                                                wabt_module.get());
        }

        if (wabt::Failed(parsing_result)) {
            auto err_msg = wabt::FormatErrorsToString(parsing_errors,
                                                      wabt::Location::Type::Binary);
            std::cerr << "WASM parse error: " << err_msg << '\n';
            return EXIT_FAILURE;
        }
    }

    // Open output stream
    std::ostream* out_stream = &std::cout;
    std::ofstream out_file;
    if (jconfig.contains("output")) {
        auto path = jconfig["output"].template get<std::string>();
        out_file.open(path);
        if (!out_file) {
            std::cerr << "Error: could not open output file: " << path << '\n';
            return EXIT_FAILURE;
        }
        out_stream = &out_file;
    }

    // Set up trace context and attach observer
    using field_t = zkp::bn254_gmp;
    zkp::null_executor exe(params::default_packing_size, params::default_row_size);
    zkp::trace_context<field_t> ctx(exe);

    jsonl_observer observer(*out_stream);
    ctx.set_observer(&observer);

    // Execute the program; observer fires for every constraint event
    try {
        run_trace_program(*wabt_module, ctx, input_args, indices_set);
    }
    catch (const wasm_trap& e) {
        std::cerr << "WASM trap: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
