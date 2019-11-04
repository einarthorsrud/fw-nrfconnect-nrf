/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

/** @file
 * @brief Secure Services Crypto header.
 */

#ifndef SECURE_SERVICES_CRYPTO_H__
#define SECURE_SERVICES_CRYPTO_H__

#include <stddef.h>
#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ERROR_INPUT_SIZE 2300 /** Error code for wrong input length. */

#define SPM_SHA1_MAX_UPDATE_LEN 512 /** Maximum SHA-1 input buffer size. */
#define SPM_AES_MAX_UPDATE_LEN 512 /** Maximum AES input buffer size. */

/**
 * Initialize the internal SHA-1 context by calling mbedtls_sha1_init().
 */
void spm_sha1_init();

/**
 * Start SHA-1 calculation by calling mbedtls_sha1_starts_ret() with the internal 
 * context.
 * 
 * @return Return value from mbedtls_sha1_starts_ret().
 */
int spm_sha1_starts();

/**
 * Provide input data to SHA-1 algorithem.
 * 
 * @details This function copies data to an internal buffer since CC310 can only
 *          use data in secure region. Then calls mbedtls_sha1_update_ret().
 *          Can be called an arbitrary number of times.
 * 
 * @param input Pointer to input buffer.
 * @param ilen  Input buffer length. Must not exceed SPM_SHA1_MAX_UPDATE_LEN.
 * @return -ERROR_INPUT_SIZE or return value from mbedtls_sha1_update_ret()
 */
int spm_sha1_update(const unsigned char *input, size_t ilen);

/**
 * Finis SHA-1 calculation and copy the result to the provided buffer.
 * 
 * @detail This function calls mbedtls_sha1_finish_ret() and copies the result
 *         to the provided buffer.
 * 
 * @param output Pointer to buffer that will be populated with the SHA1 hash.
 * @return Return the return value from mbedtls_sha1_finish_ret()
 */
int spm_sha1_finish(unsigned char output[20]);

/**
 * Clear the SHA-1 context
 */
void spm_sha1_free();

/**
 * Structure type for holding paramters for spm_aes_crypt_cbc().
 * 
 * @details This is needed because non-secure callable functions are limited
 *          to 4 paramters (cannot pass parameters on stack).
 */
typedef struct {
	int mode /* MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT */;
	size_t length; /* Length of input puffer. Maximum value is SPM_AES_MAX_UPDATE_LEN. Must be a multippl of the block size (16) */
	unsigned char *iv; /* 16 byte initialization vector for AES 128 */
	const unsigned char *input; /* Pointer to input buffer */
	unsigned char *output; /* Pointer to output buffer. Must be at least as large as the input buffer. */
} spm_mbedtls_aes_crypt_cbc_params;

/**
 * Initialize the internal AES context by calling mbedtls_aes_init().
 */
void spm_aes_init();

/**
 * Clear the internal AES context by calling spm_aes_free().
 */
void spm_aes_free();

/**
 * Set the internal encryption key buffer and call mbedtls_aes_setkey_enc().
 * 
 * @param key 128 bit (16 byte) AES key
 * @param keybits Must be 128 (exists to stay as close to mbed TLS API) as possible.
 * @return -ERROR_INPUT_SIZE or return value from mbedtls_aes_setkey_enc().
 */
int spm_aes_setkey_enc(const unsigned char *key, unsigned int keybits);

/**
 * Set the internal decryption key buffer and call mbedtls_aes_setkey_dec().
 * 
 * @param key 128 bit (16 byte) AES key
 * @param keybits Must be 128 (exists to stay as close to mbed TLS API) as possible.
 * @return -ERROR_INPUT_SIZE or return value from mbedtls_aes_setkey_dec().
 */
int spm_aes_setkey_dec(const unsigned char *key, unsigned int keybits);

/**
 * Encrypt or decrypt data. Data is copied to and from internal buffers.
 * 
 * Can be called multiplle times to generate a continius tream of encrypted data.
 * 
 * @note The only supported block size is 128 bit.
 * 
 * @param params Instance of spm_mbedtls_aes_crypt_cbc_params holding pointers
 *               to input and output buffer, initialization vector and mode.
 * @return int 
 */
int spm_aes_crypt_cbc(spm_mbedtls_aes_crypt_cbc_params *params);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* SECURE_SERVICES_CRYPTO_H__ */
