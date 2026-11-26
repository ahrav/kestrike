/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * C entry points for native operations that SPDK and DPDK define as macros
 * or static inline functions, plus the post-initialization registry query
 * and the layout table the Rust layout tests compare against. Shim sources
 * compile against installed headers with pkg-config flags; the build checks
 * those headers and flags against recorded binding-generation inputs.
 */
#ifndef SPDK_SYS_SHIM_H
#define SPDK_SYS_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct rte_mbuf;
struct rte_mempool;
struct rte_ipv4_hdr;

/* The calling thread's DPDK error number, its reset, and lcore identity. */
int spdk_sys_rte_errno(void);
void spdk_sys_rte_errno_clear(void);
unsigned spdk_sys_rte_lcore_id(void);

/* Whether the linked DPDK library reports the version its headers declare. */
bool spdk_sys_rte_library_matches_headers(void);

/* Port bursts and transmit preparation. */
uint16_t spdk_sys_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id,
				   struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t spdk_sys_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id,
				   struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t spdk_sys_rte_eth_tx_prepare(uint16_t port_id, uint16_t queue_id,
				     struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

/* Mbuf allocation, release and reference counts. */
struct rte_mbuf *spdk_sys_rte_pktmbuf_alloc(struct rte_mempool *mp);
int spdk_sys_rte_pktmbuf_alloc_bulk(struct rte_mempool *mp, struct rte_mbuf **mbufs,
				    unsigned count);
void spdk_sys_rte_pktmbuf_free(struct rte_mbuf *m);
void spdk_sys_rte_pktmbuf_free_seg(struct rte_mbuf *m);
uint16_t spdk_sys_rte_mbuf_refcnt_read(const struct rte_mbuf *m);
uint16_t spdk_sys_rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t value);
int spdk_sys_rte_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail);
void *spdk_sys_rte_mempool_get_priv(struct rte_mempool *mp);

/* IOVA helpers. */
uint64_t spdk_sys_rte_mbuf_data_iova(const struct rte_mbuf *m);
uint64_t spdk_sys_rte_mbuf_data_iova_default(const struct rte_mbuf *m);
void *spdk_sys_rte_pktmbuf_mtod(const struct rte_mbuf *m);

/* Transmit offload fields, which the mbuf stores in bitfields. */
void spdk_sys_rte_mbuf_set_tx_offload(struct rte_mbuf *m, uint64_t l2_len, uint64_t l3_len,
				      uint64_t l4_len);

/* Checksum preparation. */
uint16_t spdk_sys_rte_ipv4_cksum(const struct rte_ipv4_hdr *ipv4_hdr);
uint16_t spdk_sys_rte_ipv4_phdr_cksum(const struct rte_ipv4_hdr *ipv4_hdr, uint64_t ol_flags);
uint16_t spdk_sys_rte_ipv4_udptcp_cksum(const struct rte_ipv4_hdr *ipv4_hdr, const void *l4_hdr);

/* Bit masks of the controller configuration enable and status ready fields. */
uint32_t spdk_sys_nvme_cc_en_mask(void);
uint32_t spdk_sys_nvme_csts_rdy_mask(void);

/*
 * Which retained components the live registries hold. Constructors fill
 * the registries before main; callers query after environment
 * initialization, the state the environment's drivers run in.
 */
struct spdk_sys_registry {
	bool nvme_pcie_transport;
	bool pci_bus;
	bool ena_pmd;
	bool ring_mempool;
};
void spdk_sys_registry_query(struct spdk_sys_registry *out);

/*
 * One entry of the layout table: the C compiler's size and alignment of an
 * exposed structure, or the offset of one of its fields (align is zero for
 * a field entry).
 */
struct spdk_sys_layout {
	const char *type_name;
	const char *field_name;
	size_t size;
	size_t align;
	size_t offset;
};
const struct spdk_sys_layout *spdk_sys_layout_table(size_t *count);

#endif
