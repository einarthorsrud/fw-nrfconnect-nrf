/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */

#include <zephyr.h>
#include <misc/printk.h>
#include <string.h>
#include <secure_services_crypto.h>
#include <device.h>
#include <drivers/gpio.h>
#include <mbedtls/aes.h>

void print_hex_number(u8_t const *const num, size_t len)
{
	printk("0x");
	for (int i = 0; i < len; i++) {
		printk("%02x", num[i]);
	}
	printk("\n");
}
