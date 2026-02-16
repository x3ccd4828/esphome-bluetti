# Bluetti Encryption C++ Conversion Plan

## Overview
Convert the Rust encryption library (`bluetti-encryption`) to pure C++ code to eliminate the Rust static library dependency and simplify the build process.

## Current State
- Rust library with C FFI wrapper
- Static library linked via PlatformIO build flags
- Requires Rust toolchain with xtensa-esp32-none-elf target
- Uses crates: aes, cbc, p256, md-5, heapless, rand_core

## Target State
- Pure C++ implementation in `components/bluetti_rust/`
- Uses ESP-IDF's built-in mbedTLS for crypto operations
- No external library dependencies
- Simpler build process

---

## Phase 1: Core Data Structures

### Files to Modify
- `components/bluetti_rust/bluetti_encryption.h` (new)
- `components/bluetti_rust/bluetti_encryption.cpp` (new)

### Tasks
1. Port all constants from Rust:
   - Magic bytes: `[0x2A, 0x2A]`
   - AES block size: 16 bytes
   - Key lengths, offsets, packet sizes
   - Hardcoded keys (LOCAL_AES_KEY, PRIVATE_KEY_L1, PUBLIC_KEY_K2_BYTES)

2. Create `BluettiMessage` class:
   - Parse message type from buffer
   - Verify checksums
   - Extract data payloads
   - Check for KEX magic bytes

3. Create `BluettiEncryption` class with state:
   - unsecure_aes_key[16]
   - unsecure_aes_iv[16]
   - secure_aes_key[32]
   - peer_pubkey (P-256 point)
   - my_secret (ephemeral ECDH key)
   - ready flag

### Dependencies
- ESP-IDF headers
- Standard C++ library

---

## Phase 2: Cryptographic Primitives

### Tasks
1. **MD5 Hashing** (16-byte output)
   - Use mbedTLS `mbedtls_md5_init/update/finish`
   - Create wrapper: `md5_hash_16(input, len)`

2. **AES Encryption** (CBC mode)
   - AES-128 for unsecure phase
   - AES-256 for secure phase
   - Use mbedTLS `mbedtls_aes_crypt_cbc`
   - Handle zero-padding

3. **XOR Operation**
   - Simple 16-byte XOR for key derivation

4. **Checksum**
   - Simple sum of bytes (hexsum function)

### Dependencies
- `mbedtls/md5.h`
- `mbedtls/aes.h`

---

## Phase 3: Key Exchange Protocol

### Tasks
1. **Handle Challenge** (message type 0x01)
   - Extract 4-byte seed
   - Reverse byte order
   - Derive unsecure_iv = md5(reversed_seed)
   - Derive unsecure_key = xor(unsecure_iv, LOCAL_AES_KEY)
   - Build challenge response packet

2. **Verify Peer Signature** (message type 0x04)
   - Extract 64-byte public key + 64-byte signature
   - Load K2 public key (hardcoded)
   - Verify ECDSA signature using mbedTLS
   - Store peer public key

3. **Generate Local Keys**
   - Generate ephemeral P-256 keypair using `esp_fill_random`
   - Sign public key with L1 private key
   - Encrypt response with unsecure key

4. **Handle Pubkey Accepted** (message type 0x06)
   - Perform ECDH: shared_secret = my_secret * peer_pubkey
   - Derive secure_aes_key from shared secret
   - Mark encryption as ready

### Dependencies
- `mbedtls/ecp.h` (P-256 curve)
- `mbedtls/ecdh.h` (key exchange)
- `mbedtls/ecdsa.h` (signing/verification)
- `mbedtls/bignum.h` (big integer math)
- `esp_random.h` (RNG)

---

## Phase 4: Message Operations

### Tasks
1. **Build KEX Packets**
   - Magic bytes + type + length + payload + checksum
   - Handle buffer sizing

2. **Encrypt MODBUS Commands**
   - Generate random 4-byte IV seed
   - IV = md5(seed)
   - Encrypt with secure_aes_key
   - Frame: length_prefix + iv_seed + encrypted_payload

3. **Decrypt Responses**
   - Parse length prefix
   - Extract IV seed or use stored IV
   - Decrypt with appropriate key (secure or unsecure)
   - Handle both encrypted KEX and MODBUS responses

### Buffer Management
- Use fixed-size buffers (512 bytes max)
- Avoid dynamic allocation
- Match Rust heapless::Vec behavior

---

## Phase 5: Integration

### Tasks
1. **Update bluetti_rust.h/cpp**
   - Remove FFI header include
   - Add BluettiEncryption member variable
   - Replace FFI calls with direct method calls

2. **Update __init__.py**
   - Remove library linking code
   - Remove build flags

3. **Remove Files**
   - `link_rust.py`
   - `components/bluetti_rust/lib/libbluetti_encryption.a`
   - `components/bluetti_rust/bluetti_ffi.h`
   - `bluetti-encryption/` directory (optional - can keep for reference)

4. **Update README.md**
   - Remove Rust build instructions
   - Simplify setup steps

---

## Testing Checklist

- [ ] Challenge handling works
- [ ] Peer pubkey verification succeeds
- [ ] Local key generation works
- [ ] Pubkey accepted triggers ready state
- [ ] MODBUS commands encrypt correctly
- [ ] Responses decrypt correctly
- [ ] Full handshake completes successfully
- [ ] Telemetry data parses correctly
- [ ] AC/DC toggle commands work

---

## Migration Benefits

1. **Simpler Build**
   - No Rust toolchain required
   - No cross-compilation for ESP32
   - Single `esphome run` command

2. **Easier Maintenance**
   - One language (C++)
   - Standard ESP-IDF crypto APIs
   - Easier debugging

3. **Smaller Binary**
   - No Rust runtime overhead
   - Only required crypto functions linked

4. **Better Integration**
   - Direct access to ESP32 hardware RNG
   - No FFI boundary overhead
   - Cleaner error handling

---

## Implementation Order

1. Phase 1: Data structures + constants
2. Phase 2: MD5 + AES helpers
3. Phase 3: Challenge handling (test first)
4. Phase 4: ECDH/ECDSA implementation
5. Phase 5: Full handshake + MODBUS encryption
6. Phase 6: Integration + cleanup

**Important:** Test compile after each phase before committing.
