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

//! Edit Distance Example
//!
//! Proves the knowledge that the private string is
//! within the edit distance of 5 characters from the public string.
//!
//! Arguments:
//!     [1]: Input text A (private) (as string)
//!     [2]: Input text B (as string)

use ligetron::*;

fn main() {
    let args = get_args();

    let a: usize = args.get_as_int(1).try_into().unwrap();
    let b: usize = args.get_as_int(2).try_into().unwrap();

    assert_one(a + b == 5);
}
