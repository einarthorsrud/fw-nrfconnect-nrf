/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <secure_services.h>

void sha1_example(void);
void aes_cbc_example(void);

void main(void)
{
	printk("\nRuning crypto examples...\n");

	sha1_example();
	aes_cbc_example();

	printk("\nCrypto examples completed...\n");
}
