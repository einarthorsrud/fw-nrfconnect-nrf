/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <string.h>
#include <secure_services_crypto.h>
#include <device.h>
#include <mbedtls/sha1.h>
#include <stdio.h>
#include "shared.h"

#define SHA1_DATA_LENGTH 512 /* Only change when also updating m_expected. */

static unsigned char m_input[SHA1_DATA_LENGTH] = { 0 }; /* All zero input. */

/* Expected SHA-1 hash of 512 all zero bytes. */
static unsigned char m_expected[] = { 0x5c, 0x3e, 0xb8, 0x00, 0x66, 0x42, 0x00,
				      0x02, 0xbc, 0x3d, 0xcc, 0x7c, 0xa4, 0xab,
				      0x6e, 0xfa, 0xd7, 0xed, 0x4a, 0xe5 };
static unsigned char m_output[20];

int sha1_example_hw(u32_t *execution_time_ns)
{
	int ret;
	u32_t start_time;
	u32_t stop_time;

	memset(m_output, 0, sizeof(m_output));

	/* Capture initial time stamp before starting the work */
	start_time = k_cycle_get_32();

	spm_sha1_init();

	ret = spm_sha1_starts();
	if (ret != 0) {
		printf("ERROR: spm_sha1_starts returned: %i\n", ret);
		goto end;
	}

	ret = spm_sha1_update(m_input, sizeof(m_input));
	if (ret != 0) {
		printf("ERROR: spm_sha1_update returned: %i\n", ret);
		goto end;
	}

	ret = spm_sha1_finish(m_output);
	if (ret != 0) {
		printf("ERROR: spm_sha1_finish returned: %i\n", ret);
		goto end;
	}

	if (0 != memcmp(m_expected, m_output, sizeof(m_expected))) {
		printf("ERROR: Actual SHA-1 is not equal to expected: ");
		print_hex_number(m_output, sizeof(m_output));
	}

end:
	spm_sha1_free();

	/* Compute execution time */
	stop_time = k_cycle_get_32();
	*execution_time_ns = SYS_CLOCK_HW_CYCLES_TO_NS(stop_time - start_time);

	return ret;
}

int sha1_example_sw(u32_t *execution_time_ns)
{
	int ret;
	u32_t start_time;
	u32_t stop_time;
	mbedtls_sha1_context sha1_context;

	memset(m_output, 0, sizeof(m_output));

	/* Capture initial time stamp before starting the work */
	start_time = k_cycle_get_32();

	mbedtls_sha1_init(&sha1_context);

	ret = mbedtls_sha1_starts_ret(&sha1_context);
	if (ret != 0) {
		printf("ERROR: mbedtls_sha1_starts_ret returned: %i\n", ret);
		goto end;
	}

	ret = mbedtls_sha1_update_ret(&sha1_context, m_input, sizeof(m_input));
	if (ret != 0) {
		printf("ERROR: mbedtls_sha1_update_ret returned: %i\n", ret);
		goto end;
	}

	ret = mbedtls_sha1_finish_ret(&sha1_context, m_output);
	if (ret != 0) {
		printf("ERROR: mbedtls_sha1_finish_ret returned: %i\n", ret);
		goto end;
	}

	if (0 != memcmp(m_expected, m_output, sizeof(m_expected))) {
		printf("ERROR: Actual SHA-1 is not equal to expected: ");
		print_hex_number(m_output, sizeof(m_output));
	}

end:
	mbedtls_sha1_free(&sha1_context);

	/* Compute execution time */
	stop_time = k_cycle_get_32();
	*execution_time_ns = SYS_CLOCK_HW_CYCLES_TO_NS(stop_time - start_time);

	return ret;
}

/**
 * Executes two simple SHA-1 examples where the SHA-1 hash of a know input is
 * calculated. One using the CC310 HW implementation and one using the mbed TLS
 * SW. Prints the execution time and ratio.
 * 
 * Note that the time comparison is very rough as it times everyting including
 * buffer comparison etc., but it gives a ballpark number for performance
 * comparison. Also note that the diference between the HW and SW numbers
 * increase as the length of the data increases.
 **/
void sha1_example(void)
{
	int ret_hw;
	int ret_sw;
	u32_t execution_time_hw_ns;
	u32_t execution_time_sw_ns;

	printf("\n*** Demonstrate SHA-1 hashing of %u bytes ***\n",
	       SHA1_DATA_LENGTH);

	ret_hw = sha1_example_hw(&execution_time_hw_ns);
	if (ret_hw == 0) {
		printf("CC310 HW SHA-1 example succeeded. Execution time: %.2f ms\n",
		       (double)execution_time_hw_ns / 1000);
	} else {
		printf("ERROR: CC310 HW SHA-1 example returned %i\n", ret_hw);
	}

	ret_sw = sha1_example_sw(&execution_time_sw_ns);
	if (ret_sw == 0) {
		printf("Mbed TLS SW SHA-1 example succeeded. Execution time: %.2f ms\n",
		       (double)execution_time_sw_ns / 1000);
	} else {
		printf("ERROR: Mbed TLS SW SHA-1 example returned %i\n",
		       ret_sw);
	}

	if (ret_hw == 0 && ret_sw == 0) {
		printf("SW was %.1f times slower than HW\n",
		       (double)execution_time_sw_ns /
			       (double)execution_time_hw_ns);
	}
}
