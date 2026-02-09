#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BluettiContext BluettiContext;

typedef int32_t (*BluettiRandomCallback)(void *user_data, uint8_t *output,
                                         size_t output_len);

enum {
    BLUETTI_FFI_OK = 0,
    BLUETTI_FFI_ERR_NULL_POINTER = -1,
    BLUETTI_FFI_ERR_INVALID_INPUT = -2,
    BLUETTI_FFI_ERR_BUFFER_TOO_SMALL = -3,
    BLUETTI_FFI_ERR_OPERATION_FAILED = -4,
    BLUETTI_FFI_ERR_RNG_NOT_CONFIGURED = -5,
    BLUETTI_FFI_ERR_RNG_FAILED = -6,
};

BluettiContext *bluetti_init(void);
void bluetti_free(BluettiContext *ctx);

int32_t bluetti_set_random_callback(BluettiContext *ctx,
                                    BluettiRandomCallback callback,
                                    void *user_data);

int32_t bluetti_handle_challenge(BluettiContext *ctx, const uint8_t *data,
                                 size_t len, uint8_t *out_buf, size_t *out_len);

int32_t bluetti_handle_peer_pubkey(BluettiContext *ctx, const uint8_t *data,
                                   size_t len, uint8_t *out_buf,
                                   size_t *out_len);

int32_t bluetti_handle_pubkey_accepted(BluettiContext *ctx, const uint8_t *data,
                                       size_t len);

int32_t bluetti_encrypt_command(BluettiContext *ctx, const uint8_t *data,
                                size_t len, uint8_t *out_buf, size_t *out_len);

int32_t bluetti_decrypt_response(BluettiContext *ctx, const uint8_t *data,
                                 size_t len, uint8_t *out_buf, size_t *out_len);

bool bluetti_is_ready(const BluettiContext *ctx);

#ifdef __cplusplus
}
#endif
