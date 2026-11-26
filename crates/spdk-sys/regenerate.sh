#!/usr/bin/env bash
# Regenerates the bindings, layout.inc and layout_table.rs for the host's
# install of the pinned SPDK release. The three files go to
# src/generated/outputs/<digest>, named by native/output-digest.sh, and
# src/generated/installs/<target>-<core>[-asan] records the install: its
# target line (target, sanitizer and compile flags), the digest of its
# headers and the output its headers generate. <core> is the -mcpu or
# -march value of the install's compile flags, and -asan marks an install
# built with --enable-asan, whose libdpdk links -lasan. Installs whose headers
# generate the same files share one output; an existing output of the same
# name with other contents fails the run, and an output no record names is
# removed.
# Usage: crates/spdk-sys/regenerate.sh
# Requires bindgen-cli 0.73.2, clang 15.0.7 (libclang) and rustfmt 1.10.0, and
# reads the install through SPDK_PKG_CONFIG_PATH (default
# /usr/local/lib/pkgconfig). To check that the checked-in files are current:
#   crates/spdk-sys/regenerate.sh && git diff --exit-code -- crates/spdk-sys
# Each output's bindings record the generator digest of this script and of the
# native files listed in native/generator-digest.sh. After a change to any of
# them, run this script on a host of each install in src/generated/installs.
set -euo pipefail
cd "$(dirname "$0")"

require() {
  [[ $2 == "$3"* ]] || { echo "regenerate.sh: needs $1 $3, found: $2" >&2; exit 1; }
}
require bindgen "$(bindgen --version)" "bindgen 0.73.2"
require clang "$(clang --version | head -1)" "clang version 15.0.7 (AWS 15.0.7-3.amzn2023.0.4)"
require rustfmt "$(rustfmt --version)" "rustfmt 1.10.0"

pc_path=${SPDK_PKG_CONFIG_PATH:-/usr/local/lib/pkgconfig}
export PKG_CONFIG_PATH=$pc_path PKG_CONFIG_LIBDIR=$pc_path
target=$(uname -m)-unknown-linux-gnu
read -r -a cflags <<<"$(pkg-config --cflags libdpdk spdk_nvme spdk_env_dpdk)"
core=$(printf '%s\n' "${cflags[@]}" | sed -n 's/^-m\(cpu\|arch\)=//p' | head -n 1)
[[ -n $core ]] || { echo "regenerate.sh: the install's flags name no -mcpu or -march core" >&2; exit 1; }
includedir=$(pkg-config --variable=includedir libdpdk)
[[ ${cflags[0]} == "-I$includedir" ]] \
  || { echo "regenerate.sh: the install's flags open with ${cflags[0]}, not its include root -I$includedir" >&2; exit 1; }
# The -lasan rule native/select.rs (sanitizer) reads an ASan install by.
libs=$(pkg-config --static --libs libdpdk)
sanitizer=
[[ " $libs " != *" -lasan "* ]] || sanitizer=address
install=src/generated/installs/$target-$core${sanitizer:+-asan}
target_line="Target: $target.${sanitizer:+ Sanitizer: $sanitizer.} Flags: ${cflags[*]} -Inative"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
out=$work/out
pp=$work/pp
mkdir "$out" "$pp"
# The core flag tunes code generation for the build host, and this clang
# predates some cores an install can name (neoverse-v2 among them), so bindgen
# parses the headers without it; the layout tests compare every bound
# structure with the shim, which compiles with the install's full flags.
parse_flags=()
for flag in "${cflags[@]}"; do
  case "$flag" in -mcpu=* | -march=*) ;; *) parse_flags+=("$flag") ;; esac
done
# The preprocessed header already holds the forced includes' definitions, so the stages that read
# it use reduced_flags.
reduced_flags=()
skip_include=
for flag in "${parse_flags[@]}"; do
  if [[ -n $skip_include ]]; then
    skip_include=
    continue
  fi
  case "$flag" in
    -include) skip_include=1 ;;
    *) reduced_flags+=("$flag") ;;
  esac
done
source_args=(--target="$target" "${parse_flags[@]}" -Inative)
reduced_args=(--target="$target" "${reduced_flags[@]}" -Inative)
digest=$(native/header-digest.sh "$includedir" "${cflags[@]}")
generator=$(native/generator-digest.sh)

functions='spdk_env_opts_init|spdk_env_init|spdk_env_fini|spdk_mem_register|spdk_mem_unregister|spdk_vtophys'
functions+='|spdk_pci_addr_parse|spdk_pci_addr_fmt|spdk_pci_device_get_addr|spdk_pci_device_get_vendor_id|spdk_pci_device_get_device_id'
functions+='|spdk_nvme_transport_id_parse|spdk_nvme_transport_available_by_name|spdk_nvme_connect|spdk_nvme_detach'
functions+='|spdk_nvme_ctrlr_(get_default_ctrlr_opts|get_data|get_first_active_ns|get_next_active_ns|get_ns|get_num_ns'
functions+='|get_max_xfer_size|get_default_io_qpair_opts|alloc_io_qpair|free_io_qpair|process_admin_completions'
functions+='|register_timeout_callback|disconnect|get_regs_cc|get_regs_csts|is_failed|get_pci_device|get_transport_id|cmd_get_log_page|cmd_get_feature)'
functions+='|spdk_nvme_qpair_process_completions|spdk_nvme_ns_cmd_read|spdk_nvme_ns_cmd_write'
functions+='|spdk_nvme_ns_cmd_reservation_(register|report|acquire)'
functions+='|spdk_nvme_qpair_add_cmd_error_injection|spdk_nvme_qpair_remove_cmd_error_injection'
functions+='|spdk_nvme_ns_(get_id|get_data|get_sector_size|get_extended_sector_size|get_num_sectors|get_size'
functions+='|get_md_size|get_pi_type|get_max_io_xfer_size|get_optimal_io_boundary|get_flags|is_active)'
functions+='|rte_eal_iova_mode|rte_eal_has_hugepages|rte_socket_id|rte_strerror|rte_version|rte_bus_find_by_name'
functions+='|rte_extmem_register|rte_extmem_unregister|rte_vfio_container_dma_map|rte_vfio_container_dma_unmap'
functions+='|rte_vfio_noiommu_is_enabled|rte_vfio_is_enabled|rte_mem_virt2iova|rte_mem_virt2phy|rte_mem_virt2memseg|rte_mem_virt2memseg_list|rte_memseg_list_walk'
functions+='|rte_eth_dev_(info_get|configure|start|stop|close|reset|set_mtu|get_mtu|adjust_nb_rx_tx_desc'
functions+='|get_port_by_name|count_avail|callback_register|callback_unregister|is_valid_port|socket_id)'
functions+='|rte_eth_rx_queue_setup|rte_eth_tx_queue_setup|rte_eth_macaddr_get|rte_eth_tx_done_cleanup'
functions+='|rte_eth_stats_get|rte_eth_xstats_get_names|rte_eth_xstats_get|rte_eth_xstats_get_by_id|rte_eth_xstats_get_id_by_name|rte_eth_link_get_nowait'
functions+='|rte_eth_dev_get_name_by_port|rte_openlog_stream|rte_log_get_stream'
functions+='|rte_mempool_(create_empty|set_ops_byname|register_ops|populate_iova|populate_virt|populate_default|free'
functions+='|obj_iter|mem_iter|avail_count|in_use_count|calc_obj_size)'
functions+='|rte_pktmbuf_pool_init|rte_pktmbuf_init|rte_timer_subsystem_init|rte_timer_subsystem_finalize|rte_timer_manage'
functions+='|spdk_sys_.*'
opaque='spdk_nvme_cmd|spdk_pci_device|rte_device|rte_bus|rte_memzone|rte_fbarray|rte_mempool_cache'
types='spdk_nvme_cpl|spdk_nvme_transport_id|spdk_nvme_ctrlr_opts|spdk_nvme_io_qpair_opts|spdk_nvme_ctrlr_data'
types+='|spdk_nvme_ns_data|spdk_nvme_cmd_cb|spdk_nvme_timeout_cb|spdk_nvme_probe_cb|spdk_env_opts|spdk_pci_addr'
types+='|rte_mbuf|rte_mempool|rte_mempool_ops|rte_pktmbuf_pool_private|rte_eth_conf|rte_eth_dev_info|rte_eth_rxconf'
types+='|rte_eth_txconf|rte_eth_desc_lim|rte_eth_stats|rte_eth_xstat|rte_eth_xstat_name|rte_ether_hdr|rte_ipv4_hdr'
types+='|rte_udp_hdr|rte_iova_mode|rte_eth_event_type|rte_eth_link|spdk_sys_registry|spdk_sys_layout'
enums='spdk_nvme_reservation_(type|register_action|register_cptpl|acquire_action)'
enums+='|spdk_nvme_status_code_type|spdk_nvme_generic_command_status_code'
types+="|spdk_nvme_registered_ctrlr_extended_data|spdk_nvme_reservation_status_extended_data|$enums"
vars='RTE_ETH_(RX|TX)_OFFLOAD_.*|RTE_MBUF_F_(RX|TX)_.*|RTE_PTYPE_(L2|L3|L4|TUNNEL)_.*|RTE_ETHER_.*'
vars+='|RTE_MEMPOOL_F_.*|RTE_MEMPOOL_OPS_NAMESIZE|RTE_PKTMBUF_HEADROOM|RTE_MBUF_DEFAULT_.*|RTE_MAX_LCORE'
vars+='|RTE_ETH_MQ_.*|RTE_BAD_IOVA|RTE_MAX_MEMSEG_LISTS|RTE_VFIO_DEFAULT_CONTAINER_FD|SPDK_NVME_TRANSPORT_NAME_PCIE|SPDK_ENV_.*'

# bindgen reads a preprocessed header that keeps only the macro definitions the allowlist reaches,
# which bounds its macro fallback work. -dD keeps every #define and #undef in preprocessing order;
# line markers preserve system-header status.
vars_re="^($vars)$"
clang -E -dD -x c "${source_args[@]}" native/bindings.h -o "$pp/all.h"
python3 native/macro_closure.py "$pp/all.h" "$pp/bindings.h" "$vars_re" \
  clang -E -P -w -x c "${reduced_args[@]}" -
# The kept definitions are live while bindgen preprocesses declarations the first pass already
# expanded, so both headers must preprocess to the same declarations.
cmp -s <(clang -E -P -fminimize-whitespace -x c "${source_args[@]}" native/bindings.h) \
       <(clang -E -P -fminimize-whitespace -w -x c "${reduced_args[@]}" "$pp/bindings.h") \
  || { echo "regenerate.sh: the reduced header preprocesses to other declarations than native/bindings.h" >&2; exit 1; }

bindgen "$pp/bindings.h" \
  --output "$out/bindings.rs" \
  --rust-edition 2024 --rust-target 1.85 \
  --use-core --no-doc-comments --sort-semantically --merge-extern-blocks \
  --with-derive-default --clang-macro-fallback --clang-macro-fallback-build-dir "$pp" \
  --allowlist-function "^($functions)$" \
  --allowlist-type "^($types)$" \
  --allowlist-var "$vars_re" \
  --constified-enum "^($enums)$" \
  --opaque-type "^($opaque)$" \
  --raw-line '// Generated by crates/spdk-sys/regenerate.sh; edit the script, not this file.' \
  --raw-line '//' \
  --raw-line '// SPDX-License-Identifier: BSD-3-Clause. Derived from the SPDK and DPDK headers listed below,' \
  --raw-line '// Copyright (C) Intel Corporation and the SPDK and DPDK contributors.' \
  --raw-line '//' \
  --raw-line '// SPDK v25.05.1, commit 44b23be7c35469bc0aba4b942c08c935125e2315.' \
  --raw-line '// Bundled DPDK 25.03.0, commit cf36799c473a686fa14fde9af97f917a2125d3d5.' \
  --raw-line '// Headers: native/bindings.h (spdk/env.h spdk/nvme.h spdk/nvme_spec.h rte_eal.h rte_errno.h' \
  --raw-line '// rte_lcore.h rte_memory.h rte_vfio.h rte_bus.h rte_ethdev.h rte_mbuf.h rte_mempool.h rte_ether.h' \
  --raw-line '// rte_ip4.h rte_udp.h rte_timer.h rte_version.h) and native/shim.h.' \
  --raw-line "// Generator digest: $generator" \
  --raw-line "// bindgen $(bindgen --version | cut -d' ' -f2), $(clang --version | head -1), $(rustfmt --version)." \
  -- "${reduced_args[@]}"

python3 native/layout_table.py "$out/bindings.rs" "$out/layout.inc" "$out/layout_table.rs" "^($enums)$"
rustfmt --edition 2024 "$out/layout_table.rs"

output=$(native/output-digest.sh "$out")
mkdir -p src/generated/outputs src/generated/installs
if [[ -d src/generated/outputs/$output ]]; then
  diff -r "$out" "src/generated/outputs/$output" >/dev/null \
    || { echo "regenerate.sh: src/generated/outputs/$output differs from the files it is named for" >&2; exit 1; }
else
  cp -r "$out" "src/generated/outputs/$output"
fi
printf '%s\nHeader digest: %s\nOutput: %s\n' "$target_line" "$digest" "$output" >"$install"
for dir in src/generated/outputs/*/; do
  dir=${dir%/}
  grep -qxF "Output: ${dir##*/}" src/generated/installs/* || rm -r "$dir"
done
