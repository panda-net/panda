/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD */

#ifndef __PANDA_PROTO_IGMP_H__
#define __PANDA_PROTO_IGMP_H__

/* PANDA protocol node for IGMP */

#include <linux/igmp.h>

#include "panda/parser.h"

#endif /* __PANDA_PROTO_IGMP_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* panda_parse_igmp protocol node
 *
 * Parse IGMP header
 */
static struct panda_proto_node panda_parse_igmp __unused() = {
	.name = "IGMP",
	.min_len = sizeof(struct igmphdr),
};

#endif /* PANDA_DEFINE_PARSE_NODE */
