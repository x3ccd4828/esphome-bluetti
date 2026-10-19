# Bluetti EL30V2 ESPHome Integration (C++)

Implementation of Bluetti BLE encryption for ESPHome using native C++ on ESP32 and Raspberry Pi Pico W.
This project enables full monitoring and control of Bluetti EL30V2 (and compatible) devices via Home Assistant.

## 🚀 Features

- **Secure BLE Handshake**: Full implementation of Bluetti's challenge-response + ECDH key exchange.
- **Native C++ Core**: ESP32 uses ESP-IDF mbedTLS; Pico W uses the framework's BearSSL library.
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
bluetti-el30v2-esp32.yaml / bluetti-el30v2-picow.yaml (ESPHome Config)
    ↓
components/bluetti/ (shared protocol and controls)
    ├── ESP32: ESPHome BLE client + ESP-IDF mbedTLS
    └── Pico W: ESPHome BTstack connection backend + BearSSL
```

## 📦 Quick Start

### 1. Configure ESPHome

Use ESPHome **2026.9.1 or newer**. The ESP32 configuration uses the ESP-IDF
framework; see the Pico W configuration below for Raspberry Pi boards. The
`bluetti` component uses C++ and has no Rust library or toolchain dependency.

Edit `bluetti-el30v2-esp32.yaml` and update:

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

The configuration downloads the C++ component from GitHub:

```yaml
external_components:
  - source: github://x3ccd4828/esphome-bluetti@main
    components: [bluetti]
    refresh: 0s
```

For configurations using the earlier C++ branch, change
`components: [bluetti_rust]` to `components: [bluetti]` and the top-level
`bluetti_rust:` key to `bluetti:`. Keep the component's existing `id` and
`ble_client_id` values. The component files, C++ class, namespace, and log tag
are now named `bluetti`.

On another machine, you only need `bluetti-el30v2-esp32.yaml`, your own `secrets.yaml`,
ESPHome, and internet access. No local `components/` directory, repository clone,
or Rust toolchain is needed. The component builds directly against ESP-IDF's
crypto library supplied by its framework.

`DC Always On` is enabled by default. Set the `dc_always_on` global's
`initial_value` to `"false"` to prevent automatic DC output activation.

The logger keeps general runtime messages at `DEBUG`, and enables `VERBOSE`
only for the `sensor`, `text_sensor`, `binary_sensor`, and `switch` tags so
readings and state changes appear on UART. ESPHome 2026.4 moved these state
messages from `DEBUG` to `VERBOSE`. The global `level: VERBOSE` compiles those
messages into the firmware; `initial_level: DEBUG` and the per-tag overrides
control which ones are printed. Change your own YAML and reflash to apply this
logger setup; downloading the external component alone does not change it.

### 2. Compile and update over Wi-Fi

```bash
esphome run bluetti-el30v2-esp32.yaml --device <ESP32_IP_ADDRESS>
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
  run bluetti-el30v2-esp32.yaml --device /dev/ttyUSB0
```

On ESP32, the component enables mbedTLS through ESPHome's ESP-IDF helpers, including
the MD5 primitive required by Bluetti's protocol. It builds with ESPHome's
default native ESP-IDF toolchain without a static Rust archive or a script
that patches generated build files.

### Raspberry Pi Pico W

Use [bluetti-el30v2-picow.yaml](bluetti-el30v2-picow.yaml). It has the same
telemetry, controls, API encryption, and Always On behavior as the ESP32
configuration, with a separate device name. It uses the built-in RP2 BTstack
connection backend and BearSSL; no additional crypto dependency is downloaded.
The original ESP32 YAML and Bluetooth backend continue to work.

Copy this YAML into a device entry in ESPHome Device Builder. When replacing
an existing Pico W configuration, retain its current `esphome.name`, Wi-Fi,
API encryption key, and OTA credentials so it remains reachable and Home
Assistant keeps its identity. Set the Bluetti MAC address under `bluetti:`.
Both example configurations load the component from `@main`.

The platform-specific portion is:

```yaml
rp2:
  board: rpipicow

rp2040_ble:

bluetti:
  id: bluetti_el30v2_picow
  mac_address: "A8:46:74:31:18:12"
  address_type: public
```

Use `address_type: random` only for a Bluetti advertising a random BLE address.
The Pico connects directly to that address, discovers the service and actual
notification descriptor, and reconnects automatically. Its BLE Client switch
enables/disables this connection. A BLE tracker or Bluetooth proxy is not
required. During testing, turn off the existing ESP32's BLE Client switch so
the two boards do not compete for the same Bluetti connection.

Choose **Install → Wirelessly** for a Pico already running ESPHome. For an
initial installation, download the UF2 through Device Builder, hold BOOTSEL
while connecting the Pico to USB, and copy the UF2 onto the `RPI-RP2` drive.
Live BLE operation on the Pico requires hardware testing; compilation and
simulated transport tests do not establish radio compatibility.

### Compatibility checks

GitHub Actions compiles the full configuration on pushes and pull requests
for both ESP32 and Pico W against ESPHome `2026.9.1`, `latest`, and `dev`. A weekly schedule also runs once
the workflow is on the repository's default branch. CI builds from a separate
configuration directory containing only the YAML and test Wi-Fi credentials,
and downloads the component from the exact GitHub commit being checked.
Development-version failures are advisory. Future releases can still change APIs or toolchain ABI;
these builds detect compatibility regressions rather than guarantee support
for every future release. Compilation does not verify the live BLE handshake
or output controls, which require an ESP32 and a Bluetti device.

Host regression tests exercise both crypto implementations, the signed handshake,
protocol vectors, buffer bounds, telemetry, queued AC/DC commands, retries,
and disconnect handling. Pico-specific tests cover asynchronous GATT writes,
notification subscription, cancellation, reconnection, and OTA pauses. With CMake, a C++17
compiler, and mbedTLS 3.x and BearSSL development packages installed:

```bash
cmake -S tests -B /tmp/bluetti-tests -DCMAKE_BUILD_TYPE=Debug
cmake --build /tmp/bluetti-tests
ctest --test-dir /tmp/bluetti-tests --output-on-failure
```

AddressSanitizer and UndefinedBehaviorSanitizer are enabled by default. The
tests substitute a test signing key in a build-directory copy of the encryption
source; firmware retains the original Bluetti trust anchor. BLE is simulated,
so hardware testing remains necessary.


## 📊 Home Assistant Entities

### Sensors

- **Battery**: State of charge (%)
- **DC Output Power**: Watts
- **AC Output Power**: Watts
- **DC Input Power**: Watts
- **AC Input Power**: Watts
- **Time Remaining**: Estimated runtime in hours:minutes
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
- **"Could not find the package with 'bluetti_encryption' requirements"**: An older Rust component is being loaded. Use the GitHub source above to select the C++ implementation.
- **"Linker/crypto build error"**: Confirm you use ESPHome 2026.9.1 or newer with ESP-IDF, then clean and rebuild.

## 📝 License

This project combines ESPHome (GPL) and custom C++ components.
Based on reverse-engineered protocol details. Use at your own risk.
