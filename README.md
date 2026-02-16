# Bluetti EL30V2 ESPHome Integration

Complete implementation of Bluetti BLE encryption protocol for ESPHome using a native C++ component.
This project enables full monitoring and control of Bluetti EL30V2 (and compatible) devices via Home Assistant.

## 🚀 Features

- **Secure BLE Handshake**: Full implementation of Bluetti's challenge-response + ECDH key exchange.
- **Native C++ Core**: Crypto logic runs inside the ESPHome component using mbedTLS.
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
components/bluetti_rust/ (ESPHome C++ component)
    ↓
mbedTLS (ESP-IDF crypto primitives)
```

## 📦 Quick Start

### 1. Configure ESPHome

Edit `bluetti-el30v2.yaml` and update:

- **WiFi SSID/Password**: `!secret wifi_ssid` / `!secret wifi_password`
- **MAC Address**: Under `ble_client` -> `mac_address`

### 2. Compile and Flash

```bash
esphome run bluetti-el30v2.yaml
```

The component is self-contained and builds directly with ESPHome.

### 3. Flash a prebuilt factory binary with espflash

If you already have a compiled `firmware.factory.bin`, you can write it directly:

```bash
espflash write-bin --monitor --chip esp32 --baud 400000 0x0 <PATH_TO_BUILD_OUTPUT>/firmware.factory.bin
```

Example placeholder path:

```bash
espflash write-bin --monitor --chip esp32 --baud 400000 0x0 <WORKSPACE>/.esphome/build/bluetti-el30v2/.pioenvs/bluetti-el30v2/firmware.factory.bin
```

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
- **"Linker/crypto build error"**: ensure ESP-IDF mbedTLS options are enabled in `bluetti-el30v2.yaml` and rebuild from clean.

## 📝 License

This project combines ESPHome (GPL) and custom C++ components.
Based on reverse-engineered protocol details. Use at your own risk.
