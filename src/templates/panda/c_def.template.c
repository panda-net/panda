#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "panda/parser.h"
#include "panda/proto_nodes_def.h"
#include "@!filename!@"

static inline __attribute__((always_inline)) int check_pkt_len(const void* hdr,
		const struct panda_proto_node *pnode, size_t len, ssize_t* hlen)
{
	*hlen = pnode->min_len;

	/* Protocol node length checks */
	if (len < *hlen)
		return PANDA_STOP_LENGTH;

	if (pnode->ops.len) {
		*hlen = pnode->ops.len(hdr);
		if (len < *hlen)
			return PANDA_STOP_LENGTH;
		if (*hlen < pnode->min_len)
			return *hlen < 0 ? *hlen : PANDA_STOP_LENGTH;
	} else {
		*hlen = pnode->min_len;
	}

	return PANDA_OKAY;
}

static inline __attribute__((always_inline)) int panda_encap_layer(
		struct panda_metadata *metadata, unsigned max_encaps,
		void **frame, unsigned *frame_num)
{
	/* New encapsulation layer. Check against number of encap layers
	 * allowed and also if we need a new metadata frame.
	 */
	if (++metadata->encaps > max_encaps)
		return PANDA_STOP_ENCAP_DEPTH;

	if (metadata->max_frame_num > *frame_num) {
		*frame += metadata->frame_size;
		*frame_num = (*frame_num) + 1;
	}

	return PANDA_OKAY;
}

<!--(for node in graph)-->
@!generate_protocol_parse_function_decl(name=node)!@
<!--(end)-->
<!--(for node in graph)-->
@!generate_protocol_parse_function(name=node)!@
<!--(end)-->
<!--(for parser_name,root_name,parser_add,parser_ext in roots)-->
@!generate_entry_parse_function(parser_name=parser_name,root_name=root_name,parser_add=parser_add,parser_ext=parser_ext)!@
<!--(end)-->
