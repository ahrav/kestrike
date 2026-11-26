/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <string.h>

#include <rte_bus.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip4.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_version.h>
#include <spdk/env.h>
#include <spdk/nvme.h>

#include "shim.h"

int spdk_sys_rte_errno(void) { return rte_errno; }
void spdk_sys_rte_errno_clear(void) { rte_errno = 0; }
unsigned spdk_sys_rte_lcore_id(void) { return rte_lcore_id(); }
bool spdk_sys_rte_library_matches_headers(void)
{
	char header[32];

	/* The pinned headers declare an empty release suffix. */
	snprintf(header, sizeof(header), "%s %d.%02d.%d", RTE_VER_PREFIX, RTE_VER_YEAR, RTE_VER_MONTH,
		 RTE_VER_MINOR);
	return strncmp(rte_version(), header, sizeof(header)) == 0;
}

uint16_t spdk_sys_rte_eth_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts,
				   uint16_t nb_pkts)
{
	return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t spdk_sys_rte_eth_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts,
				   uint16_t nb_pkts)
{
	return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

uint16_t spdk_sys_rte_eth_tx_prepare(uint16_t port_id, uint16_t queue_id,
				     struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	return rte_eth_tx_prepare(port_id, queue_id, tx_pkts, nb_pkts);
}

uint32_t spdk_sys_nvme_cc_en_mask(void)
{
	union spdk_nvme_cc_register cc = {.raw = 0};
	cc.bits.en = 1;
	return cc.raw;
}

uint32_t spdk_sys_nvme_csts_rdy_mask(void)
{
	union spdk_nvme_csts_register csts = {.raw = 0};
	csts.bits.rdy = 1;
	return csts.raw;
}

#include "layout.inc"

const struct spdk_sys_layout *spdk_sys_layout_table(size_t *count)
{
	*count = sizeof(spdk_sys_layouts) / sizeof(spdk_sys_layouts[0]);
	return spdk_sys_layouts;
}
