# Gatekeeper Rust Reference Implementation

This repository holds a reference implementation of the Android
[Gatekeeper
HAL](https://cs.android.com/android/platform/superproject/main/+/main:hardware/interfaces/gatekeeper/aidl/android/hardware/gatekeeper/IGatekeeper.aidl).

## Repository Structure

The codebase is divided into a number of interdependent crates, as follows.

- `wire/`: The `gk-wire` crate holds the types that are used for communication between the
  userspace HAL service and the trusted application code that runs in the secure world, together
  with code for serializing and deserializing these types as CBOR. This crate is `no_std` but uses
  `alloc`.
- `ta/`: The `gk-ta` crate holds the implementation of the Gatekeeper trusted application (TA),
  which is expected to run within the device's secure environment. This crate is `no_std` but uses
  `alloc`.
- `hal/`: The `gk-hal` crate holds the implementation of the HAL service for Gatekeeper, which is
  expected to run in the Android userspace and respond to Binder method invocations. This crate uses
  `std` (as it runs within Android, not within the more restricted secure environment).
- `boringssl/`: The `gk-boring` crate holds a BoringSSL-based implementation of some of the
  abstractions from `gk-ta`. This crate is `no_std`, but uses `alloc`.
- `tests/`: The `gk-tests` crate holds internal testing code.

| Subdir          | Crate Name     | `std`?           | Description                                           |
|-----------------|----------------|------------------|-------------------------------------------------------|
| **`wire`**      | `gk-wire`      | No               | Types for HAL <-> TA communication                    |
| **`ta`**        | `gk-ta`        | No               | TA implementation                                     |
| **`hal`**       | `gk-hal`       | Yes              | HAL service implementation                            |
| **`boringssl`** | `gk-boringssl` | No               | Boring/OpenSSL-based implementations of crypto traits |
| `tests`         | `gk-tests`     | Yes              | Tests and test infrastructure                         |

## Porting to a Device

To use the Rust reference implementation on an Android device, implementations of various
abstractions must be provided.  This section describes the different areas of functionality that are
required.

### Rust Toolchain and Heap Allocator

Using the reference implementation requires a Rust toolchain that can target the secure environment.
This toolchain (and any associated system libraries) must also support heap allocation (or an
approximation thereof) via the [`alloc` sysroot crate](https://doc.rust-lang.org/alloc/).

If the BoringSSL-based implementation of cryptographic functionality is used (see below), then some
parts of the Rust `std` library must also be provided, in order to support the compilation of the
[`openssl`](https://docs.rs/openssl) wrapper crate.

**Checklist:**

- [ ] Rust toolchain that targets secure environment.
- [ ] Heap allocation support via `alloc`.

### HAL Service

Gatekeeper appears as a HAL service in userspace, and so an executable that registers for and
services the Gatekeeper related HALs must be provided.

The implementation of this service is mostly provided by the `gk-hal` crate, but a driver program
must be provided that:

- Performs start-of-day administration (e.g. logging setup, panic handler setup)
- Creates a communication channel to the Gatekeeper TA.
- Registers for the Gatekeeper HAL services.
- Starts a thread pool to service requests.

The Gatekeeper HAL service (which runs in userspace) must communicate with the Gatekeeper TA (which
runs in the secure environment).  The reference implementation assumes the existence of a reliable,
message-oriented, bi-directional communication channel for this, as encapsulated in the
`gk_hal::SerializedChannel` trait.

This trait has a single method `execute()`, which takes as input a request message (as bytes), and
returns a response message (as bytes) or an error.

**Checklist:**

- [ ] Implementation of HAL service main executable.
- [ ] SELinux policy for the HAL service.
- [ ] init.rc configuration for the HAL service.
- [ ] Implementation of `SerializedChannel` trait, for reliable HAL <-> TA communication.

The <a
href="https://cs.android.com/android/platform/superproject/main/+/main:system/core/trusty/gatekeeper/rust/">Trusty-specific
implementation</a> provides an example of this.

### TA Driver

The `gk-ta` crate provides the majority of the implementation of the Gatekeeper TA, but needs a
driver program that:

- Performs start-of-day administration (e.g. logging setup).
- Creates a `gk_ta::GatekeeperTa` instance.
- Configures the communication channel with the HAL service.
- Provides a mechanism for obtaining the shared HMAC key used for authentication.
- Holds the main loop that:
    - reads request messages from the channel(s)
    - passes request messages to `gk_ta::GatekeeperTa::process()`, receiving a response
    - writes response messages back to the relevant channel.

**Checklist:**

- [ ] Implementation of `main` equivalent for TA, handling scheduling of incoming requests.
- [ ] Implementation of communication channel between HAL service and TA.
- [ ] Implementation of mechanism to retrieve HMAC key (see next section).

The <a
href="https://android.googlesource.com/trusty/app/gatekeeper/+/refs/heads/main/rust/">Trusty-specific
implementation</a> provides an example of this.

### Auth Key Retrieval

Gatekeeper signs its authentication tokens with a per-boot HMAC key, which can be obtained in one of
the following ways:

- The Gatekeeper TA can directly retrieve the auth token key from another component (typically
  KeyMint) in the secure environment.  In this case, the device-specific implementation of the
  `AuthKeyManagement` trait performs signing operations using the retrieved key.
- The Gatekeeper TA can implement the `ISharedSecret` HAL and take part in the negotiation of the
  HMAC key. The common code includes an implementation of the `AuthKeyManagement` trait that handles
  this scenario, but the device must provide implementations of the following traits:
  - [ ] CDKF key derivation operation: `SharedSecretDerive`
  - [ ] Mechanism to retrieve a pre-shared key: `RetrievePresharedKey`

### Device-Specific Abstractions

The Gatekeeper TA requires implementations for low-level primitives to be provided, in the form of
implementations of the various Rust traits held in [`gk_ta::traits`](ta/src/traits.rs).

Note that some of these traits include methods that have default implementations, which means that
an external implementation is not required (but can be provided if desired).

**Checklist:**

- [ ] RNG implementation: `Rng`.
- [ ] Constant time comparison implementation: `ConstTimeEq`.
- [ ] Secure time implementation (monotonic, shared with authenticators): `MonotonicClock`.
- [ ] Implementation of mechanism to retrieve password key: `PasswordKeyRetrieval`
- [ ] Persistent secure storage of failure records: `FailureRecording`
   - [ ] The TA code includes one implementation of the `FailureRecording` trait, based on an
         implementation of a trait for accessing files in a secure filesystem: `SecureFilesystem`

BoringSSL-based implementations are available for some of the above, in the `boringssl/` directory.
