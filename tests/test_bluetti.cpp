#include "bluetti.h"
#include "bluetti_crypto.h"
#include "fixtures.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <mbedtls/aes.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha256.h>
#include <random>
#include <vector>

using Bytes = std::vector<uint8_t>;
using esphome::bluetti::BluettiEncryption;
static std::mt19937 rng(42);
static int64_t now_us = 1000000;
static std::vector<Bytes> writes;
static bool fail_write = false;
static bool fail_random = false;

void esp_fill_random(void *output, size_t len) {
    auto *bytes = static_cast<uint8_t *>(output);
    for (size_t i = 0; i < len; ++i)
        bytes[i] = static_cast<uint8_t>(rng());
}
static int random_bytes(void *, unsigned char *output, size_t len) {
    esp_fill_random(output, len);
    return 0;
}
namespace esphome {
uint32_t millis() { return now_us / 1000; }
bool random_bytes(uint8_t *data, size_t len) {
    if (fail_random)
        return false;
    esp_fill_random(data, len);
    return true;
}
} // namespace esphome
int esp_ble_gattc_register_for_notify(int, uint8_t *, uint16_t) { return 0; }
int esp_ble_gattc_write_char_descr(int, uint16_t, uint16_t, uint16_t, uint8_t *,
                                   int, int) {
    return 0;
}
int esp_ble_gattc_write_char(int, uint16_t, uint16_t, uint16_t len,
                             uint8_t *data, int, int) {
    if (fail_write)
        return -1;
    writes.emplace_back(data, data + len);
    return 0;
}

static Bytes hex(const char *text) {
    Bytes bytes;
    while (*text) {
        unsigned value;
        assert(std::sscanf(text, "%2x", &value) == 1);
        bytes.push_back(value);
        text += 2;
    }
    return bytes;
}

// Independent peer framing: this also checks the length prefix and padding.
static Bytes frame(const Bytes &plain, const Bytes &key, bool secure) {
    const size_t header = secure ? 6 : 2;
    Bytes result(header + (plain.size() + 15) / 16 * 16, 0);
    result[0] = plain.size() >> 8;
    result[1] = plain.size();
    std::array<uint8_t, 16> iv{};
    if (secure) {
        std::copy_n(hex("10203040").begin(), 4, result.begin() + 2);
        assert(mbedtls_md5(result.data() + 2, 4, iv.data()) == 0);
    } else {
        auto initial_iv = hex(fixtures::UNSECURE_IV);
        std::copy(initial_iv.begin(), initial_iv.end(), iv.begin());
    }
    std::copy(plain.begin(), plain.end(), result.begin() + header);
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    assert(mbedtls_aes_setkey_enc(&aes, key.data(), key.size() * 8) == 0);
    assert(mbedtls_aes_crypt_cbc(
               &aes, MBEDTLS_AES_ENCRYPT, result.size() - header, iv.data(),
               result.data() + header, result.data() + header) == 0);
    mbedtls_aes_free(&aes);
    return result;
}

static Bytes unframe(const Bytes &packet, const Bytes &key, bool secure) {
    const size_t header = secure ? 6 : 2;
    assert(packet.size() > header && (packet.size() - header) % 16 == 0);
    size_t size = (packet[0] << 8) | packet[1];
    assert(size <= packet.size() - header);
    Bytes result(packet.size() - header);
    std::array<uint8_t, 16> iv{};
    if (secure)
        assert(mbedtls_md5(packet.data() + 2, 4, iv.data()) == 0);
    else {
        auto initial_iv = hex(fixtures::UNSECURE_IV);
        std::copy(initial_iv.begin(), initial_iv.end(), iv.begin());
    }
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    assert(mbedtls_aes_setkey_dec(&aes, key.data(), key.size() * 8) == 0);
    assert(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, result.size(),
                                 iv.data(), packet.data() + header,
                                 result.data()) == 0);
    mbedtls_aes_free(&aes);
    assert(std::all_of(result.begin() + size, result.end(),
                       [](uint8_t value) { return value == 0; }));
    result.resize(size);
    return result;
}

// Verify the firmware's L1 signature, then independently compute the peer's
// ECDH secret as 2 * local public key (the fixture peer's private scalar is 2).
static Bytes check_local_key(const Bytes &packet) {
    assert(packet.size() == 134 && packet[0] == 0x2a && packet[1] == 0x2a &&
           packet[2] == 5 && packet[3] == 128);
    unsigned checksum = 0;
    for (size_t i = 2; i < packet.size() - 2; ++i)
        checksum += packet[i];
    assert((checksum & 0xffff) == unsigned((packet[132] << 8) | packet[133]));
    Bytes hash_input(packet.begin() + 4, packet.begin() + 68);
    auto iv = hex(fixtures::UNSECURE_IV);
    hash_input.insert(hash_input.end(), iv.begin(), iv.end());
    uint8_t digest[32];
    assert(mbedtls_sha256(hash_input.data(), hash_input.size(), digest, 0) ==
           0);
    mbedtls_ecp_group group;
    mbedtls_ecp_point trusted, local, shared;
    mbedtls_mpi r, s, scalar;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&trusted);
    mbedtls_ecp_point_init(&local);
    mbedtls_ecp_point_init(&shared);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&scalar);
    assert(mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0);
    auto trusted_bytes = hex(fixtures::LOCAL_SIGNING_PUBLIC_KEY);
    assert(mbedtls_ecp_point_read_binary(&group, &trusted, trusted_bytes.data(),
                                         trusted_bytes.size()) == 0);
    assert(mbedtls_mpi_read_binary(&r, packet.data() + 68, 32) == 0);
    assert(mbedtls_mpi_read_binary(&s, packet.data() + 100, 32) == 0);
    assert(mbedtls_ecdsa_verify(&group, digest, sizeof(digest), &trusted, &r,
                                &s) == 0);
    Bytes public_bytes(65, 4);
    std::copy_n(packet.begin() + 4, 64, public_bytes.begin() + 1);
    assert(mbedtls_ecp_point_read_binary(&group, &local, public_bytes.data(),
                                         public_bytes.size()) == 0);
    assert(mbedtls_mpi_lset(&scalar, 2) == 0);
    assert(mbedtls_ecp_mul(&group, &shared, &scalar, &local, random_bytes,
                           nullptr) == 0);
    size_t size = public_bytes.size();
    assert(mbedtls_ecp_point_write_binary(
               &group, &shared, MBEDTLS_ECP_PF_UNCOMPRESSED, &size,
               public_bytes.data(), public_bytes.size()) == 0);
    mbedtls_mpi_free(&scalar);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&shared);
    mbedtls_ecp_point_free(&local);
    mbedtls_ecp_point_free(&trusted);
    mbedtls_ecp_group_free(&group);
    return Bytes(public_bytes.begin() + 1, public_bytes.begin() + 33);
}

static void test_crypto() {
    BluettiEncryption crypto;
    std::array<uint8_t, 512> buffer{};
    size_t size = buffer.size();
    auto challenge = hex(fixtures::CHALLENGE);
    assert(!crypto.encrypt_modbus_command(challenge.data(), challenge.size(),
                                          buffer.data(), &size));
    assert(!crypto.handle_challenge(challenge.data(), 3, buffer.data(), &size));
    assert(crypto.handle_challenge(challenge.data(), challenge.size(),
                                   buffer.data(), &size));
    assert(Bytes(buffer.begin(), buffer.begin() + size) ==
           hex(fixtures::CHALLENGE_RESPONSE));
    for (auto fixture :
         {std::pair{fixtures::ACCEPTED_PACKET, fixtures::ENCRYPTED_ACCEPTED},
          std::pair{fixtures::ALIGNED_PLAINTEXT,
                    fixtures::ENCRYPTED_ALIGNED}}) {
        auto plain = hex(fixture.first), encrypted = hex(fixture.second);
        size = buffer.size();
        std::copy(plain.begin(), plain.end(), buffer.begin());
        assert(crypto.encrypt_unsecure_kex(buffer.data(), plain.size(),
                                           buffer.data(), &size));
        assert(Bytes(buffer.begin(), buffer.begin() + size) == encrypted);
        size_t output_size = buffer.size();
        assert(crypto.decrypt_response(buffer.data(), size, buffer.data(),
                                       &output_size));
        assert(Bytes(buffer.begin(), buffer.begin() + output_size) == plain);
    }
    // Every padding boundary, exact capacities, overlapping buffers, canaries.
    for (size_t len = 1; len <= 300; ++len) {
        Bytes plain(len, static_cast<uint8_t>(len));
        auto encrypted = frame(plain, hex(fixtures::UNSECURE_KEY), false);
        buffer.fill(0xa5);
        size = encrypted.size() - 1;
        assert(!crypto.encrypt_unsecure_kex(plain.data(), len, buffer.data(),
                                            &size));
        assert(buffer.front() == 0xa5 && buffer.back() == 0xa5);
        size = encrypted.size();
        assert(crypto.encrypt_unsecure_kex(plain.data(), len, buffer.data(),
                                           &size));
        assert(Bytes(buffer.begin(), buffer.begin() + size) == encrypted);
        assert(buffer[size] == 0xa5);
        size = buffer.size();
        assert(!crypto.decrypt_response(encrypted.data(), encrypted.size() - 1,
                                        buffer.data(), &size));
        encrypted[0] = encrypted[1] = 0xff;
        assert(!crypto.decrypt_response(encrypted.data(), encrypted.size(),
                                        buffer.data(), &size));
    }
    auto peer = hex(fixtures::PEER_PACKET);
    peer[80] ^= 1;
    size = buffer.size();
    assert(
        !crypto.handle_peer_pubkey(peer.data() + 4, 128, buffer.data(), &size));
    peer[80] ^= 1;
    std::copy(peer.begin(), peer.end(), buffer.begin());
    assert(crypto.handle_peer_pubkey(buffer.data() + 4, 128, buffer.data(),
                                     &size));
    auto shared = check_local_key(Bytes(buffer.begin(), buffer.begin() + size));
    uint8_t accepted = 1;
    assert(!crypto.handle_pubkey_accepted(&accepted, 1));
    accepted = 0;
    assert(crypto.handle_pubkey_accepted(&accepted, 1));
    assert(crypto.is_ready_for_commands());
    auto plain = hex("0103006600016415");
    size = buffer.size();
    assert(crypto.encrypt_modbus_command(plain.data(), plain.size(),
                                         buffer.data(), &size));
    assert(unframe(Bytes(buffer.begin(), buffer.begin() + size), shared,
                   true) == plain);
    auto response = frame(plain, shared, true);
    size = buffer.size();
    assert(crypto.decrypt_response(response.data(), response.size(),
                                   buffer.data(), &size));
    assert(Bytes(buffer.begin(), buffer.begin() + size) == plain);
    fail_random = true;
    size = buffer.size();
    assert(!crypto.encrypt_modbus_command(plain.data(), plain.size(),
                                          buffer.data(), &size));
    fail_random = false;
    crypto.reset();
    assert(!crypto.is_ready_for_commands());
    assert(!crypto.decrypt_response(response.data(), response.size(),
                                    buffer.data(), &size));
    fail_random = true;
    assert(!crypto.precompute_ephemeral_keypair());
    fail_random = false;
    // Reject an off-curve peer point on both crypto implementations.
    uint8_t invalid_point[64]{}, private_key[32]{}, secret[32]{};
    private_key[31] = 2;
    assert(!esphome::bluetti::crypto::shared_secret(private_key, invalid_point,
                                                    secret));
}

static Bytes with_crc(Bytes bytes) {
    unsigned crc = 0xffff;
    for (auto byte : bytes) {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc & 1) ? (crc >> 1) ^ 0xa001 : crc >> 1;
    }
    bytes.push_back(crc & 0xff);
    bytes.push_back(crc >> 8);
    return bytes;
}

class TestBluetti : public esphome::bluetti::Bluetti {
  public:
    using Bluetti::poll_next_register;
    using Bluetti::process_notification;
    void receive(const Bytes &packet) {
        process_notification(packet.data(), packet.size());
    }
};

#ifndef USE_RP2
static void test_controller() {
    TestBluetti device;
    esphome::ble_client::BLEClient ble;
    device.set_ble_client_parent(&ble);
    device.setup();
    esp_ble_gattc_cb_param_t param{};
    device.gattc_event_handler(ESP_GATTC_SEARCH_CMPL_EVT, 1, &param);
    device.receive(hex("2a2a010401020304000f"));
    assert(writes.back() == hex(fixtures::CHALLENGE_RESPONSE));
    auto peer =
        frame(hex(fixtures::PEER_PACKET), hex(fixtures::UNSECURE_KEY), false);
    device.receive(peer);
    const auto cached = writes.back();
    assert(cached.size() == BluettiEncryption::PUBKEY_RESPONSE_SIZE);
    auto shared =
        check_local_key(unframe(cached, hex(fixtures::UNSECURE_KEY), false));
    device.receive(peer);
    assert(writes.back() == cached);
    device.receive(hex(fixtures::ENCRYPTED_ACCEPTED));
    assert(device.is_ready());
    device.poll_next_register();
    assert(unframe(writes.back(), shared, true) ==
           with_crc(hex("010300660001")));
    auto count = writes.size();
    assert(device.set_ac_output(true) && device.set_dc_output(true));
    assert(writes.size() == count);
    auto response = with_crc(hex("0103020064"));
    response.back() ^= 1;
    device.receive(frame(response, shared, true));
    assert(std::isnan(device.battery_soc()));
    response.back() ^= 1;
    device.receive(frame(response, shared, true));
    assert(device.battery_soc() == 100);
    // A read must preserve both queued commands; failed sends must retry.
    fail_write = true;
    device.poll_next_register();
    assert(writes.size() == count);
    fail_write = false;
    device.poll_next_register();
    assert(unframe(writes.back(), shared, true) ==
           with_crc(hex("010607db0001")));
    device.poll_next_register();
    assert(unframe(writes.back(), shared, true) ==
           with_crc(hex("010607dc0001")));
    device.receive(frame(with_crc(hex("010607db0001")), shared, true));
    device.receive(frame(with_crc(hex("010607dc0001")), shared, true));
    assert(device.ac_output_enabled() && device.dc_output_enabled());
    assert(!device.set_ac_output(false)); // Debounced.
    now_us += 2000000;
    device.poll_next_register(); // Read time remaining.
    assert(device.set_ac_output(false));
    count = writes.size();
    now_us += 3000000;
    device.poll_next_register(); // Timeout preserves the queued write.
    device.poll_next_register();
    assert(writes.size() == count + 1);
    assert(unframe(writes.back(), shared, true) ==
           with_crc(hex("010607db0000")));
    device.gattc_event_handler(ESP_GATTC_DISCONNECT_EVT, 1, &param);
    assert(!device.is_ready() && std::isnan(device.battery_soc()));
    assert(!device.ac_output_enabled() && !device.dc_output_enabled());
}
#else
static void test_controller() {
    TestBluetti device;
    esphome::bluetooth_connection::RP2GattClient ble;
    ble.listener = &device;
    device.set_backend(&ble);
    device.set_mac_address(0xa84674311812ULL);
    device.set_address_type(0);
    device.setup();
    now_us = 6000000;
    device.loop();
    assert(ble.connects == 1 && ble.address == 0xa84674311812ULL);
    assert(ble.address_type == 0 && !device.is_connected());
    device.on_connection_state(true, 256, 0);
    assert(ble.discoveries == 1);
    device.on_service_discovery_done(0);
    assert(ble.services_released && ble.descriptor_handle == 14);

    // Bluetti can notify before the CCCD write's completion. The challenge
    // response must remain queued until BTstack can accept another write.
    auto challenge = hex("2a2a010401020304000f");
    device.on_notify_data(10, challenge.data(), challenge.size());
    assert(ble.writes.empty());
    ble.complete(14);
    assert(device.is_connected());
    assert(ble.writes.back() == hex(fixtures::CHALLENGE_RESPONSE));

    // The peer key arrives while the challenge response is still in flight.
    auto peer =
        frame(hex(fixtures::PEER_PACKET), hex(fixtures::UNSECURE_KEY), false);
    device.on_notify_data(10, peer.data(), peer.size());
    assert(ble.writes.size() == 1);
    ble.complete();
    auto cached = ble.writes.back();
    auto shared =
        check_local_key(unframe(cached, hex(fixtures::UNSECURE_KEY), false));
    ble.complete();
    device.on_notify_data(10, peer.data(), peer.size());
    assert(ble.writes.back() == cached);
    ble.complete();
    auto accepted = hex(fixtures::ENCRYPTED_ACCEPTED);
    device.on_notify_data(10, accepted.data(), accepted.size());
    assert(device.is_ready());
    device.poll_next_register();
    assert(unframe(ble.writes.back(), shared, true) ==
           with_crc(hex("010300660001")));
    assert(device.set_ac_output(true) && device.set_dc_output(true));
    // Telemetry may also precede the GATT write acknowledgement.
    device.receive(frame(with_crc(hex("0103020064")), shared, true));
    assert(device.battery_soc() == 100);
    device.poll_next_register();
    device.poll_next_register();
    auto count = ble.writes.size();
    ble.complete();
    assert(ble.writes.size() == count + 1);
    assert(unframe(ble.writes.back(), shared, true) ==
           with_crc(hex("010607db0001")));
    ble.complete();
    assert(unframe(ble.writes.back(), shared, true) ==
           with_crc(hex("010607dc0001")));
    ble.complete();
    device.receive(frame(with_crc(hex("010607db0001")), shared, true));
    device.receive(frame(with_crc(hex("010607dc0001")), shared, true));
    assert(device.ac_output_enabled() && device.dc_output_enabled());

    // Synchronous busy rejection must keep the encrypted packet for retry.
    ble.write_error = 1;
    count = ble.writes.size();
    device.poll_next_register();
    assert(ble.writes.size() == count);
    ble.write_error = 0;
    device.loop();
    assert(ble.writes.size() == count + 1);
    // An asynchronous ATT failure tears down and clears stale state.
    ble.complete(20, 5);
    assert(ble.disconnects == 1 && !device.is_connected() &&
           !device.is_ready());
    device.on_connection_state(false, 0, 5);
    assert(std::isnan(device.battery_soc()));
    now_us += 6000000;
    device.loop();
    assert(ble.connects == 2);
    device.set_enabled(false); // Cancel a connect still in progress.
    assert(!device.is_enabled() && ble.disconnects == 2);
    device.on_connection_state(false, 0, 0);
    now_us += 6000000;
    device.loop();
    assert(ble.connects == 2);
    device.set_enabled(true);
    device.loop();
    assert(ble.connects == 3);
    device.on_connection_state(true, 256, 0);
    // A device missing a real CCCD must fail instead of guessing a handle.
    ble.descriptors[0].uuid.value = 0x2901;
    device.on_service_discovery_done(0);
    assert(ble.disconnects == 3);
    device.on_connection_state(false, 0, 0);
    now_us += 6000000;
    device.loop();
    now_us += 31000000;
    device.loop(); // Missing connect/handshake completion times out.
    assert(ble.disconnects == 4);
    device.on_connection_state(false, 0, 0);
    device.on_ota_global_state(esphome::ota::OTA_STARTED, 0, 0, nullptr);
    device.on_connection_state(false, 0, 0);
    now_us += 10000000;
    auto connect_count = ble.connects;
    device.loop();
    assert(ble.connects == connect_count);
    device.on_ota_global_state(esphome::ota::OTA_ABORT, 0, 0, nullptr);
    now_us += 6000000;
    device.loop();
    assert(ble.connects == connect_count + 1);
}
#endif

int main() {
    test_crypto();
    test_controller();
    std::puts("Encryption vectors, handshake, bounds, queued writes and "
              "reconnect tests passed");
}
