/* SPDX-License-Identifier: BSD-3-Clause */
/* Mbuf release entry points. */

#include <rte_mbuf.h>

#include "shim.h"

void spdk_sys_rte_pktmbuf_free(struct rte_mbuf *m) { rte_pktmbuf_free(m); }
void spdk_sys_rte_pktmbuf_free_seg(struct rte_mbuf *m) { rte_pktmbuf_free_seg(m); }
