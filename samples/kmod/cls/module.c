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

#include <linux/string.h>
#include <linux/skbuff.h>

#include "kernel/cls_panda.h"

#include "panda/parser.h"
#include "panda/parser_metadata.h"
#include "panda/tc_tmpl.h"

PANDA_PARSER_KMOD_EXTERN(panda_parser_big_ether);

/* Meta data structure for just one frame */
struct panda_parser_big_metadata_one {
	struct panda_metadata panda_data;
	struct panda_metadata_all frame;
};

static int do_parse(struct sk_buff *skb)
{
	int err;
	struct panda_parser_big_metadata_one mdata;

	memset(&mdata, 0, sizeof(mdata));

	err = skb_linearize(skb);
	if (err < 0)
		return err;

	BUG_ON(skb->data_len);

	err = panda_parse(PANDA_PARSER_KMOD_NAME(panda_parser_big_ether),
			  skb->data, skb->len, &mdata.panda_data, 0, 1);
	if (err != PANDA_STOP_OKAY)
		return -1;

	return 0;
}

PANDA_TC_MAKE_PARSER_PROGRAM("big", do_parse);
