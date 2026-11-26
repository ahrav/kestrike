/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * The registry tests' probe. It initializes the environment with the
 * in-process registry tests' options under its own process name, prints the
 * registry query's four answers as 0/1 digits and exits with status 2 when
 * initialization fails.
 */

#include <stdio.h>

#include <spdk/env.h>

#include "shim.h"

int main(void)
{
	struct spdk_env_opts opts = {.opts_size = sizeof(opts)};
	struct spdk_sys_registry r;

	spdk_env_opts_init(&opts);
	opts.name = "spdk-sys-probe";
	opts.no_pci = true;
	opts.no_huge = true;
	opts.mem_size = 64;
	opts.shm_id = -1;
	if (spdk_env_init(&opts) != 0) {
		return 2;
	}
	spdk_sys_registry_query(&r);
	printf("%d%d%d%d\n", r.nvme_pcie_transport, r.pci_bus, r.ena_pmd, r.ring_mempool);
	return 0;
}
