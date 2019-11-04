/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <string.h>
#include <secure_services_crypto.h>
#include <device.h>
#include <mbedtls/aes.h>
#include <stdio.h>
#include "shared.h"

#define AES_DATA_LENGTH 2048 /* Arbitrary number divisible by 16 */

static const unsigned char m_plain_text[AES_DATA_LENGTH] = "Secret data";
static const unsigned char m_key[16] = "Nordic Semi";
static const unsigned char m_iv[16] = "IV..."; // Would typically be random
static unsigned char m_encrypted[AES_DATA_LENGTH] = { 0 };
static unsigned char m_decrypted[AES_DATA_LENGTH] = { 0 };

/**
 * Demonstrate AES CBC encryption using CC310 via the SPM (secure services).
 **/
int aes_cbc_example_hw(u32_t *execution_time_ns)
{
	int ret;
	u32_t start_time;
	u32_t stop_time;
	static unsigned char iv[16];
	spm_mbedtls_aes_crypt_cbc_params crypt_params;

	memset(m_decrypted, 0, sizeof(m_decrypted));
	memcpy(iv, m_iv, sizeof(iv));

	/* Capture initial time stamp before starting the work */
	start_time = k_cycle_get_32();

	/* Perform AES CBC encryption of the data set */
	spm_aes_init();
	ret = spm_aes_setkey_enc(m_key, 128);
	if (ret != 0) {
		printf("ERROR: spm_aes_setkey_enc returned: %i\n", ret);
		goto end;
	}

	crypt_params.mode = MBEDTLS_AES_ENCRYPT;
	crypt_params.iv = iv;

	for (unsigned int bytes_done = 0; bytes_done < AES_DATA_LENGTH;
	     bytes_done = bytes_done + SPM_AES_MAX_UPDATE_LEN) {
		if (sizeof(m_plain_text) - bytes_done <
		    SPM_AES_MAX_UPDATE_LEN) {
			crypt_params.length = sizeof(m_plain_text) - bytes_done;
		} else {
			crypt_params.length = SPM_AES_MAX_UPDATE_LEN;
		}

		crypt_params.input = &m_plain_text[bytes_done];
		crypt_params.output = &m_encrypted[bytes_done];

		ret = spm_aes_crypt_cbc(&crypt_params);
		if (ret != 0) {
			printf("ERROR: spm_aes_crypt_cbc returned: %i\n", ret);
			goto end;
		}
	}

	spm_aes_free();

	/* Perform AES CBC decryption of the data set */
	spm_aes_init();
	memcpy(iv, m_iv, sizeof(iv));
	ret = spm_aes_setkey_dec(m_key, 128);
	if (ret != 0) {
		printf("ERROR: spm_aes_setkey_dec returned: %i\n", ret);
		goto end;
	}

	crypt_params.mode = MBEDTLS_AES_DECRYPT;
	crypt_params.iv = iv;

	for (unsigned int bytes_done = 0; bytes_done < AES_DATA_LENGTH;
	     bytes_done = bytes_done + SPM_AES_MAX_UPDATE_LEN) {
		if (sizeof(m_encrypted) - bytes_done < SPM_AES_MAX_UPDATE_LEN) {
			crypt_params.length = sizeof(m_encrypted) - bytes_done;
		} else {
			crypt_params.length = SPM_AES_MAX_UPDATE_LEN;
		}

		crypt_params.input = &m_encrypted[bytes_done];
		crypt_params.output = &m_decrypted[bytes_done];

		ret = spm_aes_crypt_cbc(&crypt_params);

		if (ret != 0) {
			printf("ERROR: spm_aes_crypt_cbc returned: %i\n", ret);
			goto end;
		}
	}

	if (0 != memcmp(m_plain_text, m_decrypted, AES_DATA_LENGTH)) {
		printf("ERROR: Decrypted data is not equal to original.\n");
		printf("Plain text: ");
		print_hex_number(m_plain_text, sizeof(m_plain_text));
		printf("HW Encrypted: ");
		print_hex_number(m_encrypted, sizeof(m_encrypted));
		printf("HW Decrypted: ");
		print_hex_number(m_decrypted, sizeof(m_decrypted));
		ret = -1;
	}

end:
	spm_aes_free();

	/* Compute execution time */
	stop_time = k_cycle_get_32();
	*execution_time_ns = SYS_CLOCK_HW_CYCLES_TO_NS(stop_time - start_time);

	return ret;
}

/**
 * Corresponds to aes_cbc_example_sw, but uses mbed TLS in SW. Used for comparison.
 **/
int aes_cbc_example_sw(u32_t *execution_time_ns)
{
	int ret;
	u32_t start_time;
	u32_t stop_time;
	mbedtls_aes_context aes_context = { 0 };
	static unsigned char iv[16];

	memset(m_decrypted, 0, sizeof(m_decrypted));
	memcpy(iv, m_iv, sizeof(iv));

	/* Capture initial time stamp before starting the work */
	start_time = k_cycle_get_32();

	/* Perform AES CBC encryption of the data set */
	mbedtls_aes_init(&aes_context);

	ret = mbedtls_aes_setkey_enc(&aes_context, m_key, 128);
	if (ret != 0) {
		printf("ERROR: mbedtls_aes_setkey_enc returned: %i\n", ret);
		goto end;
	}

	ret = mbedtls_aes_crypt_cbc(&aes_context, MBEDTLS_AES_ENCRYPT,
				    sizeof(m_plain_text), iv, m_plain_text,
				    m_encrypted);
	if (ret != 0) {
		printf("ERROR: mbedtls_aes_crypt_cbc returned: %i\n", ret);
		goto end;
	}

	mbedtls_aes_free(&aes_context);

	/* Perform AES CBC decryption of the data set */
	memset(&aes_context, 0, sizeof(aes_context));
	memcpy(iv, m_iv, sizeof(iv));

	mbedtls_aes_init(&aes_context);
	ret = mbedtls_aes_setkey_dec(&aes_context, m_key, 128);
	if (ret != 0) {
		printf("ERROR: mbedtls_aes_setkey_dec returned: %i\n", ret);
		goto end;
	}

	ret = mbedtls_aes_crypt_cbc(&aes_context, MBEDTLS_AES_DECRYPT,
				    sizeof(m_plain_text), iv, m_encrypted,
				    m_decrypted);
	if (ret != 0) {
		printf("ERROR: mbedtls_aes_crypt_cbc returned: %i\n", ret);
		goto end;
	}

	if (0 != memcmp(m_plain_text, m_decrypted, AES_DATA_LENGTH)) {
		printf("ERROR: Decrypted data is not equal to original.\n");
		printf("Plain text: ");
		print_hex_number(m_plain_text, sizeof(m_plain_text));
		printf("SW Encrypted: ");
		print_hex_number(m_encrypted, sizeof(m_encrypted));
		printf("SW Decrypted: ");
		print_hex_number(m_decrypted, sizeof(m_decrypted));
		ret = -1;
	}

end:
	mbedtls_aes_free(&aes_context);

	/* Compute execution time */
	stop_time = k_cycle_get_32();
	*execution_time_ns = SYS_CLOCK_HW_CYCLES_TO_NS(stop_time - start_time);

	return ret;
}

/**
 * Executes two simple AES examples encrypting and decrypting a data set, one
 * using the CC310 HW implementation and one using the mbed TLS SW. Prints the
 * execution time and ratio.
 * 
 * Note that the time comparison is very rough as it times everyting including
 * buffer comparison etc., but it gives a ballpark number for performance
 * comparison. Also note that the diference between the HW and SW numbers
 * increase as the length of the data increases.
 **/
void aes_cbc_example(void)
{
	int ret_hw;
	int ret_sw;
	u32_t execution_time_hw_ns;
	u32_t execution_time_sw_ns;

	printf("\n*** Demonstrate AES CBC encrypting and decrypting %u byte ***\n",
	       AES_DATA_LENGTH);

	ret_hw = aes_cbc_example_hw(&execution_time_hw_ns);
	if (ret_hw == 0) {
		printf("CC310 HW AES example succeeded. Execution time: %.2f ms\n",
		       (double)execution_time_hw_ns / 1000);
	} else {
		printf("ERROR: CC310 HW AES example returned %i\n", ret_hw);
	}

	ret_sw = aes_cbc_example_sw(&execution_time_sw_ns);
	if (ret_sw == 0) {
		printf("Mbed TLS SW AES example succeeded. Execution time: %.2f ms\n",
		       (double)execution_time_sw_ns / 1000);
	} else {
		printf("ERROR: Mbed TLS SW AES example returned %i\n", ret_sw);
	}

	if (ret_hw == 0 && ret_sw == 0) {
		printf("SW was %.1f times slower than HW\n",
		       (double)execution_time_sw_ns /
			       (double)execution_time_hw_ns);
	}
}
