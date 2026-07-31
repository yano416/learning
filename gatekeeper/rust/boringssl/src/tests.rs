// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests for the BoringSSL-based implementations of crypto traits.
//!
//! Inject the local trait implementation into the into the smoke tests from `gk_tests`.

#[test]
fn test_aes_cmac() {
    gk_tests::test_aes_cmac::<crate::BoringAesCmac>();
}

#[test]
fn test_shared_secret_derive() {
    let aes_cmac = crate::BoringAesCmac;
    gk_tests::test_shared_secret_derive(aes_cmac);
}

#[test]
fn test_rng() {
    let mut rng = crate::Rng;
    gk_tests::test_rng(&mut rng);
}

#[test]
fn test_eq() {
    let comparator = crate::ConstEq;
    gk_tests::test_eq(comparator);
}

#[ignore]
#[test]
fn test_constant_time_eq() {
    let comparator = crate::ConstEq;
    gk_tests::test_constant_time_eq(comparator);
}

#[test]
fn test_hmac() {
    let hmac = crate::HmacSha256;
    gk_tests::test_hmac(hmac);
}
