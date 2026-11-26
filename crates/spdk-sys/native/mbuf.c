/* SPDX-License-Identifier: BSD-3-Clause */
/* Mbuf allocation, reference count, IOVA, offload and checksum entry points. */

#include <rte_ip4.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "shim.h"

struct rte_mbuf *spdk_sys_rte_pktmbuf_alloc(struct rte_mempool *mp) { return rte_pktmbuf_alloc(mp); }

int spdk_sys_rte_pktmbuf_alloc_bulk(struct rte_mempool *mp, struct rte_mbuf **mbufs, unsigned count)
{
	return rte_pktmbuf_alloc_bulk(mp, mbufs, count);
}

uint16_t spdk_sys_rte_mbuf_refcnt_read(const struct rte_mbuf *m) { return rte_mbuf_refcnt_read(m); }

uint16_t spdk_sys_rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t value)
{
	return rte_mbuf_refcnt_update(m, value);
}

int spdk_sys_rte_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail)
{
	return rte_pktmbuf_chain(head, tail);
}

void *spdk_sys_rte_mempool_get_priv(struct rte_mempool *mp) { return rte_mempool_get_priv(mp); }
uint64_t spdk_sys_rte_mbuf_data_iova(const struct rte_mbuf *m) { return rte_mbuf_data_iova(m); }

uint64_t spdk_sys_rte_mbuf_data_iova_default(const struct rte_mbuf *m)
{
	return rte_mbuf_data_iova_default(m);
}

void *spdk_sys_rte_pktmbuf_mtod(const struct rte_mbuf *m) { return rte_pktmbuf_mtod(m, void *); }

void spdk_sys_rte_mbuf_set_tx_offload(struct rte_mbuf *m, uint64_t l2_len, uint64_t l3_len,
				      uint64_t l4_len)
{
	m->tx_offload = rte_mbuf_tx_offload(l2_len, l3_len, l4_len, 0, 0, 0, 0);
}

uint16_t spdk_sys_rte_ipv4_cksum(const struct rte_ipv4_hdr *ipv4_hdr) { return rte_ipv4_cksum(ipv4_hdr); }

uint16_t spdk_sys_rte_ipv4_phdr_cksum(const struct rte_ipv4_hdr *ipv4_hdr, uint64_t ol_flags)
{
	return rte_ipv4_phdr_cksum(ipv4_hdr, ol_flags);
}

uint16_t spdk_sys_rte_ipv4_udptcp_cksum(const struct rte_ipv4_hdr *ipv4_hdr, const void *l4_hdr)
{
	return rte_ipv4_udptcp_cksum(ipv4_hdr, l4_hdr);
}
