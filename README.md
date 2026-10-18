# Bluetti EL30V2 ESPHome Integration (Rust)

Complete implementation of Bluetti BLE encryption protocol for ESPHome using a Rust static library.
This project enables full monitoring and control of Bluetti EL30V2 (and compatible) devices via Home Assistant.

## 🚀 Features

- **Secure BLE Handshake**: Full implementation of Bluetti's challenge-response + ECDH key exchange.
- **Rust Core**: Crypto logic runs in a high-performance, memory-safe Rust static library (`no_std`).
- **Full Telemetry**:
  - Battery %
  - AC/DC Output Power
  - AC/DC Input Power
  - Time Remaining
  - AC Input Voltage
- **Control**:
  - AC Output Toggle (with "Always On" mode)
  - DC Output Toggle (with "Always On" mode)
  - BLE Connection Control

## 🛠️ Architecture

```
bluetti-el30v2.yaml (ESPHome Config)
    ↓
components/bluetti_rust/ (C++ Wrapper Component)
    ↓
bluetti-encryption/ (Rust Library)
    ↓
components/bluetti_rust/lib/libbluetti_encryption.a
    ↓
ESP-IDF component (CMake add_prebuilt_library)
```

## 📦 Quick Start

### 1. Configure ESPHome

Use ESPHome **2026.9.1 or newer**, a classic ESP32 board, and the ESP-IDF framework.
The precompiled Rust library is included; ordinary firmware builds do not need
Cargo or a Rust toolchain. Other ESP32 variants need their own Rust archive and
are rejected during configuration validation.

Edit `bluetti-el30v2.yaml` and update:

- **WiFi SSID/Password**: `!secret wifi_ssid` / `!secret wifi_password`
- **MAC Address**: Under `ble_client` -> `mac_address`

Native API encryption is enabled with `!secret api_encryption_key`. Generate a
unique 32-byte base64 key with:

```bash
openssl rand -base64 32
```

Add the result to your untracked `secrets.yaml`:

```yaml
api_encryption_key: "PASTE_GENERATED_KEY_HERE"
```

After uploading the firmware, enter that same key when Home Assistant asks for
the ESPHome device's encryption key. When building on another machine, copy
the existing key rather than generating a new one. Keep it in `secrets.yaml`;
the key is private to your device and is not supplied by the GitHub component.
This protects native API traffic between ESPHome and Home Assistant. The Bluetti
Bluetooth encryption handshake is independent.

The configuration downloads the component and its bundled Rust archive from
GitHub:

```yaml
external_components:
  - source: github://x3ccd4828/esphome-bluetti@fix/rust-esphome-build
    components: [bluetti_rust]
    refresh: 0s
```

On another machine, you only need `bluetti-el30v2.yaml`, your own `secrets.yaml`,
ESPHome, and internet access. No local `components/` directory, repository clone,
or Rust toolchain is needed. Use this branch until the fix is merged into `main`;
the current `@main` source still contains the older build integration.

`DC Always On` is enabled by default. Set the `dc_always_on` global's
`initial_value` to `"false"` to prevent automatic DC output activation.

### 2. Compile and update over Wi-Fi

```bash
esphome run bluetti-el30v2.yaml --device <ESP32_IP_ADDRESS>
```

For Podman users, the Makefile mounts the project and a persistent build cache,
and enables host networking for OTA:

```bash
make compile IMAGE=docker.io/esphome/esphome:2026.9.1
make run IMAGE=docker.io/esphome/esphome:2026.9.1 DEVICE=<ESP32_IP_ADDRESS>
```

`IMAGE` defaults to `docker.io/esphome/esphome:latest`. To pick up a newly
released image, run `podman pull docker.io/esphome/esphome:latest` before building.
`make logs DEVICE=<ESP32_IP_ADDRESS>` opens network logs. Use the same image
version for compilation, uploading, and logs.

For an initial USB flash with Podman:

```bash
podman run --rm -it --device=/dev/ttyUSB0 --group-add keep-groups \
  --security-opt label=disable -v "$PWD:/config" \
  docker.io/esphome/esphome:2026.9.1 \
  run bluetti-el30v2.yaml --device /dev/ttyUSB0
```

After ESPHome downloads the GitHub source, the Rust archive is registered with
`esp32.add_idf_component` from ESPHome's downloaded component cache. Its CMake
file imports and links the archive using
ESP-IDF's supported `add_prebuilt_library` API. It does not use a PlatformIO
registry lookup, linker flags tied to generated paths, or scripts that patch
ESPHome's generated build files. ESPHome's default native ESP-IDF toolchain is
used; selecting the deprecated PlatformIO toolchain is unnecessary.

### Compatibility checks

GitHub Actions compiles the full configuration on pushes and pull requests
against ESPHome `2026.9.1`, `latest`, and `dev`. A weekly schedule also runs once
the workflow is on the repository's default branch. CI builds from a separate
configuration directory containing only the YAML and test Wi-Fi credentials,
and downloads the component from the exact GitHub commit being checked.
Development-version failures are advisory. Future releases can still change APIs or toolchain ABI;
these builds detect compatibility regressions rather than guarantee support
for every future release. Compilation does not verify the live BLE handshake
or output controls, which require an ESP32 and a Bluetti device.

### Rebuilding the Rust library

Only needed when changing the Rust code. In a checkout of
[`bluetti-encryption`](https://github.com/x3ccd4828/bluetti-encryption), with an
ESP Rust toolchain supporting `xtensa-esp32-none-elf`, run:

```bash
cargo +esp rustc \
  -Z build-std=core,alloc \
  --release \
  --features c_ffi \
  --target xtensa-esp32-none-elf \
  --lib \
  --crate-type staticlib
```

Replace `components/bluetti_rust/lib/libbluetti_encryption.a` in this project
with `target/xtensa-esp32-none-elf/release/libbluetti_encryption.a` from that
build. Commit and push the updated archive to the Git ref used by
`external_components`, then recompile ESPHome.

## 📊 Home Assistant Entities

### Sensors

- **Battery**: State of charge (%)
- **DC Output Power**: Watts
- **AC Output Power**: Watts
- **DC Input Power**: Watts
- **AC Input Power**: Watts
- **Time Remaining**: Minutes
- **AC Input Voltage**: Volts
- **Encryption State**: 3 = Ready, 0 = Not Ready

### Controls

- **AC Output**: Switch to toggle AC power.
- **DC Output**: Switch to toggle DC power.
- **BLE Client**: Diagnostic switch to enable/disable BLE connection.

### Configuration

- **AC Always On**: When enabled, forces AC output ON if battery > 3%.
- **DC Always On**: When enabled, forces DC output ON if battery > 3%.

## 🔐 How It Works (The 7-Step Flow)

1. **BLE Scan**: ESP32 scans for the device.
2. **Connect**: Establishes GATT connection.
3. **Subscribe**: Listens to notification char `0xFF01`.
4. **Handshake**:
   - **4a. Receive CHALLENGE**: Extracts seed, derives unsecure key.
   - **4b. Send CHALLENGE_ACCEPTED**: Writes response to `0xFF02`.
   - **4c. Receive PEER_PUBKEY**: Decrypts peer's ECDH public key.
   - **4d. Send MY_PUBKEY**: Generates ephemeral keypair, signs it, encrypts and sends.
   - **4e. Receive PUBKEY_ACCEPTED**: Confirms handshake.
   - **4f. Shared Secret**: Computes ECDH secret -> derives `secure_aes_key`.
5. **Send Commands**: Encrypts Modbus RTU frames with AES-256-CBC + random IV.
6. **Receive Responses**: Decrypts responses using the secure key.
7. **Parse Data**: Extracts register values (SOC, Power, etc.).

## ⚠️ Troubleshooting

- **"Encryption not ready"**: Wait ~5-10s after boot for handshake.
- **"MODBUS poll timeout"**: Check BLE signal strength (RSSI).
- **"Could not find the package with 'bluetti_encryption' requirements"**: An older component is being loaded. Use the GitHub source above, or another published Git ref containing the ESP-IDF component integration.
- **"Linker error"**: Confirm the Rust archive was built for `xtensa-esp32-none-elf` with `c_ffi`. Toolchain ABI changes may require rebuilding it.

## 📝 License

This project combines ESPHome (GPL) and custom Rust components.
Based on reverse-engineered protocol details. Use at your own risk.
