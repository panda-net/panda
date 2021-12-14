/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020,2021 SiPanda Inc.
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

#include "panda/parser_metadata.h"

/* Common function to run the parser. Note that struct metadata is defined
 * in the C file that includes this header file (the structure will be
 * different for different use cases
 */
void run_parser(const void *arg, const void *pktbuf, size_t pktbuflen)
{
	const struct panda_parser *parser = arg;
	struct {
		struct panda_metadata panda_metadata; /* Must be first */
		struct metadata metadata;
	} pmetadata;
	struct metadata *metadata = &pmetadata.metadata;

	memset(&pmetadata, 0, sizeof(pmetadata));

	panda_parse(parser, pktbuf, pktbuflen,
		    &pmetadata.panda_metadata, 0, 0);

	/* Print IP addresses and ports in the metadata */
	switch (metadata->addr_type) {
	case PANDA_ADDR_TYPE_IPV4: {
		char sbuf[INET_ADDRSTRLEN];
		char dbuf[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &metadata->addrs.v4.saddr,
			  sbuf, sizeof(sbuf));
		inet_ntop(AF_INET, &metadata->addrs.v4.daddr,
			  dbuf, sizeof(dbuf));

		printf("IPv4: %s:%u->%s:%u\n", sbuf,
		       ntohs(metadata->port_pair.sport), dbuf,
		       ntohs(metadata->port_pair.dport));

		break;
	}
	case PANDA_ADDR_TYPE_IPV6: {
		char sbuf[INET6_ADDRSTRLEN];
		char dbuf[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, &metadata->addrs.v6.saddr,
			  sbuf, sizeof(sbuf));
		inet_ntop(AF_INET6, &metadata->addrs.v6.daddr,
			  dbuf, sizeof(dbuf));

		printf("IPv6: %s:%u->%s:%u\n", sbuf,
		       ntohs(metadata->port_pair.sport), dbuf,
		       ntohs(metadata->port_pair.dport));

		break;
	}
	default:
		fprintf(stderr, "Unknown addr type %u\n",
			metadata->addr_type);
	}

	/* If data is present for TCP timestamp option then print */
	if (metadata->tcp_options.timestamp.value ||
	    metadata->tcp_options.timestamp.echo) {
		printf("\tTCP timestamps value: %u, echo %u\n",
		       metadata->tcp_options.timestamp.value,
		       metadata->tcp_options.timestamp.echo);
	}

	/* Compute and print hash over addresses and port numbers */
	printf("\tHash %08x\n",
	       PANDA_COMMON_COMPUTE_HASH(metadata, HASH_START_FIELD));
}
