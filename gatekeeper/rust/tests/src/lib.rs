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

//! Test methods to confirm basic functionality of trait implementations.

use gk_ta::traits::{
    Aes256Key, AesCmac, ConstTimeEq, FailureRecording, HmacKey, HmacSha256, MonotonicClock,
    OpaqueOr, Rng, SharedSecretDerive,
};
use gk_ta::FailureRecord;
use gk_wire::{AndroidUserId, MillisecondsSinceEpoch, SecureUserId};
use std::time::Duration;

/// Test basic [`Rng`] functionality.
pub fn test_rng<R: Rng>(rng: &mut R) {
    let u1 = rng.next_u64();
    let u2 = rng.next_u64();
    assert_ne!(u1, u2);

    let mut b1 = [0u8; 16];
    let mut b2 = [0u8; 16];
    rng.fill_bytes(&mut b1);
    rng.fill_bytes(&mut b2);
    assert_ne!(b1, b2);

    rng.fill_bytes(&mut b1);
    assert_ne!(b1, b2);
}

/// Test basic [`ConstTimeEq`] functionality. Does not test the key constant-time property though.
pub fn test_eq<E: ConstTimeEq>(comparator: E) {
    let b0 = [];
    let b1 = [0u8, 1u8, 2u8];
    let b2 = [1u8, 1u8, 2u8];
    let b3 = [0u8, 1u8, 3u8];
    let b4 = [0u8, 1u8, 2u8, 3u8];
    let b5 = [42; 4096];
    let mut b6 = [42; 4096];
    b6[4095] = 43;
    assert!(comparator.eq(&b0, &b0));
    assert!(comparator.eq(&b5, &b5));

    assert!(comparator.ne(&b0, &b1));
    assert!(comparator.ne(&b0, &b2));
    assert!(comparator.ne(&b0, &b3));
    assert!(comparator.ne(&b0, &b4));
    assert!(comparator.ne(&b0, &b5));
    assert!(comparator.eq(&b1, &b1));
    assert!(comparator.ne(&b1, &b2));
    assert!(comparator.ne(&b1, &b3));
    assert!(comparator.ne(&b1, &b4));
    assert!(comparator.ne(&b5, &b6));
}

/// Test the constant-time property for [`ConstTimeEq`] functionality.
pub fn test_constant_time_eq<E: ConstTimeEq>(cmp: E) {
    const LEN: usize = 128 * 1024 * 1024;
    let base = vec![42; LEN];
    let same = base.clone();

    // Change a bit in the last byte.
    let mut last = base.clone();
    last[LEN - 1] ^= 0x01;
    // Change a bit in the first byte.
    let mut first = base.clone();
    first[0] ^= 0x01;

    assert!(cmp.eq(&base, &base));
    assert!(cmp.ne(&base, &first));
    assert!(cmp.ne(&base, &last));

    // Benchmark comparisons with first and last bytes holding a difference.
    let same_duration = bench(|| cmp.eq(&base, &same));
    println!("comparing same {LEN}-byte chunk takes {same_duration:?}");
    let first_duration = bench(|| cmp.eq(&base, &first));
    println!("comparing {LEN}-byte chunk with differing first byte takes {first_duration:?}");
    let last_duration = bench(|| cmp.eq(&base, &last));
    println!("comparing {LEN}-byte chunk with differing last byte takes {last_duration:?}");

    check_same("compare-same vs compare-first-byte", &same_duration, &first_duration, 20.0);
    check_same("compare-same vs compare-last-byte", &same_duration, &last_duration, 20.0);
    check_same("compare-first-byte vs compare-last-byte", &first_duration, &last_duration, 20.0);
}

fn check_same(msg: &str, base: &Duration, other: &Duration, max_pct_diff: f64) {
    let delta_nanos = base.as_nanos().abs_diff(other.as_nanos());
    let pct_diff = 100.0 * delta_nanos as f64 / base.as_nanos() as f64;
    assert!(
        pct_diff < max_pct_diff,
        "{msg}: difference {pct_diff}% between {base:?} and {other:?} should be < {max_pct_diff}%"
    );
    println!("{msg}: {pct_diff}% between {base:?} and {other:?} is < {max_pct_diff}%");
}

/// Repeatedly run the given closure and return average iteration time.
fn bench<F>(mut f: F) -> Duration
where
    F: FnMut() -> bool,
{
    const WARMUP_ITERATIONS: u32 = 5;
    let mut duration = Duration::ZERO;
    println!("  warmup for {WARMUP_ITERATIONS}...");
    for _ in 0..WARMUP_ITERATIONS {
        duration += time(&mut f);
    }
    let warmup = duration / WARMUP_ITERATIONS;
    println!("  warmup for {WARMUP_ITERATIONS}...done in {duration:?} average {warmup:?}");

    // Guess at rough number of iterations that fit in the test interval.
    const TEST_INTERVAL: Duration = Duration::from_secs(5);
    let iterations = if warmup > Duration::from_secs(1) {
        3
    } else {
        TEST_INTERVAL.as_nanos() / warmup.as_nanos()
    };
    let iterations = u32::try_from(iterations).unwrap_or(u32::MAX);

    println!("  iterate for {iterations}...");
    let mut duration = Duration::ZERO;
    for _ in 0..iterations {
        duration += time(&mut f);
    }
    let result = duration / iterations;
    println!("  warmup for {iterations}...done in {duration:?} average {result:?}");
    result
}

#[inline]
fn time<F>(f: &mut F) -> Duration
where
    F: FnMut() -> bool,
{
    let start = std::time::Instant::now();
    let _ = f();
    start.elapsed()
}

/// Test basic [`MonotonicClock`] functionality.
pub fn test_clock<C: MonotonicClock>(clock: C) {
    let t1 = clock.now();
    let t2 = clock.now();
    assert!(t2.0 >= t1.0);
    std::thread::sleep(std::time::Duration::from_millis(400));
    let t3 = clock.now();
    assert!(t3.0 > (t1.0 + 200));
}

/// Test basic [`HmacSha256`] functionality.
pub fn test_hmac<H: HmacSha256>(hmac: H) {
    struct TestCase {
        key: &'static [u8],
        data: &'static [u8],
        want: &'static str,
    }

    const HMAC_TESTS: &[TestCase] = &[
        TestCase {
            data: b"Hello",
            key: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            want: "e0ff02553d9a619661026c7aa1ddf59b7b44eac06a9908ff9e19961d481935d4",
        },
        // empty data
        TestCase {
            data: &[],
            key: b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            want: "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d",
        },
        // Test cases from RFC 4231 Section 4.2
        TestCase {
            key: &[0x0b; 20],
            data: b"Hi There",
            want: concat!("b0344c61d8db38535ca8afceaf0bf12b", "881dc200c9833da726e9376c2e32cff7",),
        },
        // Test cases from RFC 4231 Section 4.3
        TestCase {
            key: b"Jefe",
            data: b"what do ya want for nothing?",
            want: concat!("5bdcc146bf60754e6a042426089575c7", "5a003f089d2739839dec58b964ec3843"),
        },
        // Test cases from RFC 4231 Section 4.4
        TestCase {
            key: &[0xaa; 20],
            data: &[0xdd; 50],
            want: concat!("773ea91e36800e46854db8ebd09181a7", "2959098b3ef8c122d9635514ced565fe"),
        },
    ];

    for (i, test) in HMAC_TESTS.iter().enumerate() {
        let key = OpaqueOr::Explicit(HmacKey(test.key.to_vec()));
        let got = hmac.sign(&key, test.data).expect("failed to HMAC for case {i}");
        assert_eq!(hex::encode(&got), test.want, "incorrect mac in case {i}",);
    }
}

/// Test [`FailureRecording`] functionality.
pub fn test_failure_recording<T: FailureRecording>(mut records: T) {
    let record = |sid, ts, count| FailureRecord {
        sid: SecureUserId(sid),
        last_checked_timestamp: MillisecondsSinceEpoch(ts),
        failure_counter: count,
    };

    records.set(AndroidUserId(100), &record(100100, 1, 0)).unwrap();
    records.set(AndroidUserId(200), &record(100200, 100, 0)).unwrap();
    records.set(AndroidUserId(300), &record(100300, 100, 0)).unwrap();

    assert_eq!(records.get(AndroidUserId(100)).unwrap(), Some(record(100100, 1, 0)));
    assert_eq!(records.get(AndroidUserId(200)).unwrap(), Some(record(100200, 100, 0)));
    assert_eq!(records.get(AndroidUserId(300)).unwrap(), Some(record(100300, 100, 0)));

    records.set(AndroidUserId(100), &record(100101, 101, 0)).unwrap();

    assert_eq!(records.get(AndroidUserId(100)).unwrap(), Some(record(100101, 101, 0)));
    assert_eq!(records.get(AndroidUserId(200)).unwrap(), Some(record(100200, 100, 0)));
    assert_eq!(records.get(AndroidUserId(300)).unwrap(), Some(record(100300, 100, 0)));

    assert!(records.clear(AndroidUserId(200)).unwrap());
    assert_eq!(records.get(AndroidUserId(100)).unwrap(), Some(record(100101, 101, 0)));
    assert_eq!(records.get(AndroidUserId(200)).unwrap(), None);
    assert_eq!(records.get(AndroidUserId(300)).unwrap(), Some(record(100300, 100, 0)));

    assert!(!records.clear(AndroidUserId(200)).unwrap());
    assert!(!records.clear(AndroidUserId(200)).unwrap());

    records.clear_all().unwrap();
    assert_eq!(records.get(AndroidUserId(100)).unwrap(), None);
    assert_eq!(records.get(AndroidUserId(200)).unwrap(), None);
    assert_eq!(records.get(AndroidUserId(300)).unwrap(), None);
}

/// Test [`AesCmac`] functionality.
pub fn test_aes_cmac<T: AesCmac>() {
    // Test vectors from NIST 800-38B D.3.
    let key =
        hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
    let key: Aes256Key = key.try_into().unwrap();
    let data = hex::decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710",
    ))
    .unwrap();
    let tests = vec![
        (0, "028962f61b7bf89efc6b551f4667d983"),
        (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
        (40, "aaf3d8f1de5640c232f5b169b9c911e6"),
        (64, "e1992190549f6ed5696a2c056c315410"),
    ];

    for (len, want) in tests {
        let mut op = T::begin(&OpaqueOr::Explicit(key)).unwrap();
        op.update(&data[..len]).unwrap();
        let got = op.finish().unwrap();

        assert_eq!(hex::encode(&got), want, "for message len {len}");
    }
}

/// Test [`SharedSecretDerive`] functionality for an [`AesCmac`] implementation.
pub fn test_shared_secret_derive<T: AesCmac>(aes_cmac: T) {
    // Test data manually generated from Android C++ implementation.
    let key: Aes256Key = [0; 32];
    let label = b"KeymasterSharedMac";
    let v0 = vec![0x00, 0x00, 0x00, 0x00];
    let v1 = vec![0x01, 0x01, 0x01, 0x01];
    let v2 = vec![0x02, 0x02, 0x02, 0x02];
    let v3 = vec![0x03, 0x03, 0x03, 0x03];

    let result =
        aes_cmac.derive(&OpaqueOr::Explicit(key), label, &[&v0, &v1, &v2, &v3], 32).unwrap();
    let OpaqueOr::Explicit(result) = result else { panic!("expected explicit key") };
    assert_eq!(
        hex::encode(result.0.clone()),
        "ac9af88a02241f53d43056a4676c42eef06825755e419e7bd20f4e57487717aa"
    );
}

#[cfg(test)]
mod tests {
    use gk_ta::traits::ConstTimeEq;

    /// Tests for the tests.
    #[test]
    #[should_panic]
    fn test_non_constant_eq() {
        struct NonConstEq;
        impl ConstTimeEq for NonConstEq {
            fn eq(&self, left: &[u8], right: &[u8]) -> bool {
                left == right
            }
        }
        // A naive implementation of `NonConstEq` will fail the test.
        super::test_constant_time_eq(NonConstEq);
    }
}
