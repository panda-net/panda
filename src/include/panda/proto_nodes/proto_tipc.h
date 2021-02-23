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

#ifndef __PANDA_PROTO_TIPC_H__
#define __PANDA_PROTO_TIPC_H__

/* TIPC node definitions */

#include <linux/ppp_defs.h>

#include "panda/parser.h"

/* LINK_PROTOCOL + MSG_IS_KEEPALIVE */
#define TIPC_KEEPALIVE_MSG_MASK		0x0e080000

struct tipc_basic_hdr {
	__be32 w[4];
};

#endif /* __PANDA_PROTO_TIPC_H__ */

#ifdef PANDA_DEFINE_PARSE_NODE

/* panda_parse_tipc protocol node
 *
 * Parse TIPC header
 */
static const struct panda_proto_node panda_parse_tipc __unused() = {
	.name = "TIPC",
	.min_len = sizeof(struct tipc_basic_hdr),
};

#endif /* PANDA_DEFINE_PARSE_NODE */
