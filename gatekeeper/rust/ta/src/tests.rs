// Copyright 2025, The Android Open Source Project
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

//! Tests

use crate::{
    handle::PasswordHandle,
    traits::{HmacKey, HmacSha256, OpaqueOr, Rng},
    Error, FailureRecord,
};
use alloc::{vec, vec::Vec};
use gk_wire as wire;
use hal_wire::AsCborValue;
use wire::{MillisecondsSinceEpoch, SecureUserId};

#[test]
fn test_invalid_data() {
    // Cross-check that the hand-encoded invalid CBOR data matches an auto-encoded equivalent.
    let rsp = wire::PerformOpResponse::Err(wire::ApiStatus::GeneralFailure as i32);
    let rsp_data = rsp.into_vec().unwrap();
    assert_eq!(hex::encode(rsp_data), hex::encode(super::invalid_cbor_rsp_data()));
}

#[test]
fn test_failure_record_roundtrip() {
    let tests = [(1, 100, 0), (-1, -100, 5), (i64::MAX, 22593600, 5), (i64::MIN, 22593600, 5)];
    for (sid, ts, count) in tests {
        let want = FailureRecord {
            sid: SecureUserId(sid),
            last_checked_timestamp: MillisecondsSinceEpoch(ts),
            failure_counter: count,
        };
        let data = want.to_vec().unwrap();
        let got = FailureRecord::from_slice(&data).unwrap();
        assert_eq!(got, want, "for input {want:?}");
    }
}

#[test]
fn test_password_handle_roundtrip() {
    let hmac_key = OpaqueOr::Explicit(HmacKey(vec![1, 2, 3]));

    struct Fakery;
    impl HmacSha256 for Fakery {
        fn sign(&self, _key: &OpaqueOr<HmacKey>, _data: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(vec![0xdd; 32])
        }
    }
    impl Rng for Fakery {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(2);
        }
    }

    let want = PasswordHandle::new(
        &hmac_key,
        &Fakery,
        &mut Fakery,
        &wire::Password(vec![1, 2, 3]),
        SecureUserId(43),
    )
    .unwrap();
    let data = want.to_wire().unwrap();
    let got = PasswordHandle::from_wire(&data).unwrap();
    assert_eq!(got, want)
}

#[test]
fn test_retry_timeout() {
    let expected_timeouts_in_minutes = [
        /* 0  */ 0, //
        /* 1  */ 0, //
        /* 2  */ 0, //
        /* 3  */ 0, //
        /* 4  */ 0, //
        /* 5  */ 1, //
        /* 6  */ 5, //
        /* 7  */ 15, //
        /* 8  */ 30, //
        /* 9  */ 90, //
        /* 10 */ 240, // 4 hours
        /* 11 */ 720, // 12 hours
        /* 12 */ 2160, // 36 hours
        /* 13 */ 5760, // 4 days
        /* 14 */ 18720, // 13 days
        /* 15 */ 59040, // 41 days
        /* 16 */ 177120, // 123 days
        /* 17 */ 525600, // 1 year
        /* 18 */ 1576800, // 3 years
        /* 19 */ 4730400, // 9 years
    ];
    for count in 0..20 {
        let want = Ok(expected_timeouts_in_minutes[count as usize] * 60000);
        let record = FailureRecord {
            sid: SecureUserId(1),
            last_checked_timestamp: MillisecondsSinceEpoch(1),
            failure_counter: count,
        };
        let got = record.compute_retry_timeout();
        assert_eq!(got, want, "for count={count}");
    }
    for count in 20..100 {
        let want = Err(Error::RetryTimeout(i32::MAX));
        let record = FailureRecord {
            sid: SecureUserId(1),
            last_checked_timestamp: MillisecondsSinceEpoch(1),
            failure_counter: count,
        };
        let got = record.compute_retry_timeout();
        assert_eq!(got, want, "for count={count}");
    }
}
