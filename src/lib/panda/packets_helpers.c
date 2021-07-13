// SPDX-License-Identifier: BSD-2-Clause-FreeBSD
/*
 * Copyright (c) 2020, 2021 SiPanda Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <linux/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "panda/packets_helpers.h"

struct panda_packets_list *panda_packets_build_list(char *files[],
						    unsigned int num_files,
						    unsigned int max_packets)
{
	struct panda_packets_list *packets;
	unsigned int num_packets = 0;
	struct panda_pcap_file *pf;
	__u8 packet[1500];
	ssize_t len;
	size_t plen;
	void *p;
	int i;

	packets = malloc(sizeof(*packets) +
			 max_packets * sizeof(struct panda_packet_info));
	if (!packets) {
		fprintf(stderr, "Malloc failed\n");
		exit(-1);
	}

	for (i = 0; i < num_files && num_packets < max_packets; i++) {
		pf = panda_pcap_init(files[i]);
		if (!pf) {
			fprintf(stderr, "PANDA pcap init failed for %s\n",
				files[i]);
			exit(-1);
		}

		while (num_packets < max_packets &&
		       (len = panda_pcap_readpkt(pf, packet, sizeof(packet),
						 &plen)) >= 0) {
			p = malloc(len);
			if (!p) {
				fprintf(stderr, "Malloc failed\n");
				exit(-1);
			}

			memcpy(p, packet, len);
			packets->packets[num_packets].data = p;
			packets->packets[num_packets].len = len;

			num_packets++;
		}
	}

	packets->num_packets = num_packets;

	return packets;
}
