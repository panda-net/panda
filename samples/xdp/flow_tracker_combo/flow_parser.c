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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "panda/pcap.h"

#define ARGS "O"

#include "panda/parser.h"
#include "panda/parser_metadata.h"

/* Common function to run the parser. */

void run_parser(const struct panda_parser *parser, struct panda_pcap_file *pf)
{
	struct {
		struct panda_metadata panda_metadata; /* Must be first */
		struct panda_metadata_all metadata;
	} pmetadata;
	struct panda_metadata_all *metadata = &pmetadata.metadata;
	__u8 packet[1500];
	ssize_t len;
	size_t plen;

	while ((len = panda_pcap_readpkt(pf, packet, sizeof(packet),
					 &plen)) >= 0) {
		memset(&pmetadata, 0, sizeof(pmetadata));

		panda_parse(parser, packet, len,
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
	}
}

void *usage(char *prog)
{
	fprintf(stderr, "%s [-O] <pcap_file>\n", prog);
	exit(-1);
}

PANDA_PARSER_EXT_DECL(panda_parser_simple_tuple);
PANDA_PARSER_EXT_DECL(panda_parser_simple_tuple_opt);

int main(int argc, char *argv[])
{
	struct panda_pcap_file *pf;
	bool opt_parser = false;
	int c;

	while ((c = getopt(argc, argv, ARGS)) != -1) {
		switch (c) {
		case 'O':
			opt_parser = true;
			break;
		default:
			usage(argv[0]);
		}
	}
	if (optind != argc - 1)
		usage(argv[0]);

	pf = panda_pcap_init(argv[optind]);
	if (!pf) {
		fprintf(stderr, "PANDA pcap init failed\n");

		exit(-1);
	}

	run_parser(opt_parser ? panda_parser_simple_tuple_opt :
		   panda_parser_simple_tuple, pf);
}
