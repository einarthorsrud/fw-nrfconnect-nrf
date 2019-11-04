/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <zephyr.h>
#include <errno.h>
#include <cortex_m/tz.h>
#include <secure_services.h>
#include <string.h>
#include <secure_services_crypto.h>

#ifdef CONFIG_SPM_SERVICE_CC310_CRYPTO

#ifdef MBEDTLS_CONFIG_FILE
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif /* MBEDTLS_CONFIG_FILE */

#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha1.h>
#include <mbedtls/aes.h>

#define AES_BLOCK_SIZE 16 /* Only support AES 128 */

static mbedtls_sha1_context m_sha1_context;
static unsigned char m_sha1_intput[SPM_SHA1_MAX_UPDATE_LEN];
static unsigned char m_sha1_output[20];

static mbedtls_aes_context m_aes_context;
static unsigned char m_aes_key_dec[AES_BLOCK_SIZE];
static unsigned char m_aes_key_enc[AES_BLOCK_SIZE];
static unsigned char m_aes_iv[AES_BLOCK_SIZE];
static unsigned char m_aes_input[SPM_AES_MAX_UPDATE_LEN];
static unsigned char m_aes_output[SPM_AES_MAX_UPDATE_LEN];

__TZ_NONSECURE_ENTRY_FUNC
void spm_sha1_init()
{
	mbedtls_sha1_init(&m_sha1_context);
}

__TZ_NONSECURE_ENTRY_FUNC
int spm_sha1_starts()
{
	return mbedtls_sha1_starts_ret(&m_sha1_context);
}

__TZ_NONSECURE_ENTRY_FUNC
int spm_sha1_update(const unsigned char *input, size_t ilen)
{
	int ret;

	if (ilen > SPM_SHA1_MAX_UPDATE_LEN) {
		return ERROR_INPUT_SIZE;
	}

	memcpy(m_sha1_intput, input, ilen);

	ret = mbedtls_sha1_update_ret(&m_sha1_context, m_sha1_intput, ilen);

	return ret;
}

__TZ_NONSECURE_ENTRY_FUNC
int spm_sha1_finish(unsigned char output[20])
{
	int ret;

	ret = mbedtls_sha1_finish_ret(&m_sha1_context, m_sha1_output);
	if (ret != 0) {
		return ret;
	}

	memcpy(output, m_sha1_output, 20);

	return ret;
}

__TZ_NONSECURE_ENTRY_FUNC
void spm_sha1_free()
{
	mbedtls_sha1_free(&m_sha1_context);
}

__TZ_NONSECURE_ENTRY_FUNC
void spm_aes_init()
{
	mbedtls_aes_init(&m_aes_context);
}

__TZ_NONSECURE_ENTRY_FUNC
void spm_aes_free()
{
	mbedtls_aes_free(&m_aes_context);
}

__TZ_NONSECURE_ENTRY_FUNC
int spm_aes_setkey_enc(const unsigned char *key, unsigned int keybits)
{
	if (keybits != 128) {
		return ERROR_INPUT_SIZE;
	}

	memcpy(m_aes_key_enc, key, keybits / 8);

	return mbedtls_aes_setkey_enc(&m_aes_context, m_aes_key_enc, keybits);
}

__TZ_NONSECURE_ENTRY_FUNC
int spm_aes_setkey_dec(const unsigned char *key, unsigned int keybits)
{
	if (keybits != 128) {
		return ERROR_INPUT_SIZE;
	}

	memcpy(m_aes_key_dec, key, keybits / 8);

	return mbedtls_aes_setkey_dec(&m_aes_context, m_aes_key_dec, keybits);
}

__TZ_NONSECURE_ENTRY_FUNC
int spm_aes_crypt_cbc(spm_mbedtls_aes_crypt_cbc_params *params)
{
	int ret;

	if ((params->length > SPM_AES_MAX_UPDATE_LEN) ||
	    (params->length % AES_BLOCK_SIZE != 0)) {
		return ERROR_INPUT_SIZE;
	}

	memcpy(m_aes_input, params->input, params->length);
	memcpy(m_aes_iv, params->iv, AES_BLOCK_SIZE);

	ret = mbedtls_aes_crypt_cbc(&m_aes_context, params->mode,
				    params->length, m_aes_iv, m_aes_input,
				    m_aes_output);

	memcpy(params->output, m_aes_output, params->length);

	return ret;
}

#endif /* CONFIG_SPM_SERVICE_CC310_CRYPTO */
