/* SPDX-License-Identifier: BSD-3-Clause */
/* The post-initialization registry query and its view of the PCI bus object. */

#include <string.h>

#include <bus_driver.h>
#include <bus_pci_driver.h>
#include <rte_bus.h>
#include <rte_mempool.h>
#include <spdk/nvme.h>

#include "shim.h"

/*
 * The PCI bus object DPDK exports as rte_pci_bus: the generic bus followed
 * by its device and driver lists. The bus driver keeps this definition
 * private, so the build script reads the exported symbol's size from the
 * installed archive and this assertion refuses a definition that differs.
 * The registry query also checks that the generic prefix is the bus DPDK
 * finds by name before it reads either list.
 */
struct spdk_sys_pci_bus {
	struct rte_bus bus;
	RTE_TAILQ_HEAD(, rte_pci_device) device_list;
	RTE_TAILQ_HEAD(, rte_pci_driver) driver_list;
};
_Static_assert(sizeof(struct spdk_sys_pci_bus) == SPDK_SYS_PCI_BUS_SIZE,
	       "rte_pci_bus layout differs from the installed bus driver");
extern struct spdk_sys_pci_bus rte_pci_bus;

static bool pci_driver_registered(const char *name)
{
	const struct rte_pci_driver *driver;

	if (rte_bus_find_by_name("pci") != &rte_pci_bus.bus) {
		return false;
	}
	RTE_TAILQ_FOREACH(driver, &rte_pci_bus.driver_list, next) {
		if (driver->driver.name != NULL && strcmp(driver->driver.name, name) == 0) {
			return true;
		}
	}
	return false;
}

static bool mempool_ops_registered(const char *name)
{
	uint32_t i;

	for (i = 0; i < rte_mempool_ops_table.num_ops; i++) {
		if (strcmp(rte_mempool_ops_table.ops[i].name, name) == 0) {
			return true;
		}
	}
	return false;
}

void spdk_sys_registry_query(struct spdk_sys_registry *out)
{
	out->nvme_pcie_transport = spdk_nvme_transport_available_by_name(SPDK_NVME_TRANSPORT_NAME_PCIE);
	out->pci_bus = rte_bus_find_by_name("pci") != NULL;
	out->ena_pmd = pci_driver_registered("net_ena");
	out->ring_mempool = mempool_ops_registered("ring_sp_sc") && mempool_ops_registered("ring_mp_mc");
}
