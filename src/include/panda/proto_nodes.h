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

/* Include for all defined proto nodes */

#include "panda/proto_nodes/proto_ether.h"
#include "panda/proto_nodes/proto_pppoe.h"
#include "panda/proto_nodes/proto_ipv4.h"
#include "panda/proto_nodes/proto_ipv6.h"
#include "panda/proto_nodes/proto_ports.h"
#include "panda/proto_nodes/proto_tcp.h"
#include "panda/proto_nodes/proto_ip.h"
#include "panda/proto_nodes/proto_ipv6_eh.h"
#include "panda/proto_nodes/proto_ipv4ip.h"
#include "panda/proto_nodes/proto_ipv6ip.h"
#include "panda/proto_nodes/proto_gre.h"
#include "panda/proto_nodes/proto_vlan.h"
#include "panda/proto_nodes/proto_icmp.h"
#include "panda/proto_nodes/proto_ppp.h"
#include "panda/proto_nodes/proto_mpls.h"
#include "panda/proto_nodes/proto_arp_rarp.h"
#include "panda/proto_nodes/proto_tipc.h"
#include "panda/proto_nodes/proto_batman.h"
#include "panda/proto_nodes/proto_igmp.h"
#include "panda/proto_nodes/proto_fcoe.h"
