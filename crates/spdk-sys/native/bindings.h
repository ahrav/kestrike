/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * The native headers the generated bindings cover. Every file here comes
 * from the pinned SPDK install and its bundled DPDK; shim.h adds the C
 * entry points for the operations those headers define as macros or
 * static inline functions.
 */
#include <spdk/env.h>
#include <spdk/nvme.h>
#include <spdk/nvme_spec.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_memory.h>
#include <rte_vfio.h>
#include <rte_bus.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_ip4.h>
#include <rte_udp.h>
#include <rte_timer.h>
#include <rte_version.h>

#include "shim.h"
