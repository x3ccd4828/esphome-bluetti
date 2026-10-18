#pragma once

// Protocol vectors generated independently with Python cryptography/OpenSSL.
namespace fixtures {
inline constexpr const char *CHALLENGE = "01020304";
inline constexpr const char *CHALLENGE_RESPONSE = "2a2a020430bba9ca0264";
inline constexpr const char *UNSECURE_KEY = "82a36edee5d1ea51402a4953773f3448";
inline constexpr const char *UNSECURE_IV = "c73cabeb6558aba030bba9ca49dcdd75";
inline constexpr const char *ACCEPTED_PACKET = "2a2a0601000007";
inline constexpr const char *ENCRYPTED_ACCEPTED =
    "0007b8bcc96f3b449cf0adadec3dbe22383b";
inline constexpr const char *ALIGNED_PLAINTEXT =
    "000102030405060708090a0b0c0d0e0f";
inline constexpr const char *ENCRYPTED_ALIGNED =
    "00108b946135a0df983563dae7d712923f59";
inline constexpr const char *PEER_PACKET =
    "2a2a04807cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807"
    "775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d18879bd152664"
    "942d063d58b0a409dd1e79b7fab884b59f72a9de27ba2ae0ed4158e75922149efb0d31a60c"
    "22b81ce61a314a6733172510aab26a26342d06fe84399d";
inline constexpr const char *LOCAL_SIGNING_PUBLIC_KEY =
    "043f29e1b8b29d8422bbb0e0f09000cf2ee2931da13cdac8129f8c09deac07f519b5ac5509"
    "ca3f3f59b234b7777a231ae595ca5aa1745fd7a62bc4d02037117dd1";
} // namespace fixtures
