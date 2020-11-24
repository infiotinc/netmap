/*
 * Copyright (C) 2020 Semihalf
 * Author: Lukasz Bartosik <lukasz.bartosik@semihalf.com>
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

#if defined(linux)

#include "bsd_glue.h"

#else

#error Unsupported platform

#endif /* unsupported */

/*
 * common headers
 */
#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>

#ifdef WITH_DSA

#include <dev/netmap/netmap_dsa.h>

static struct netmap_dsa_adapter *dsa_na_tbl[DSA_MAX_PORTS];

static int
netmap_dsa_sync(struct netmap_kring *kring, int flags)
{
	nm_prerr("Error operation not supported");
	return ENOTSUPP;
}

static int
netmap_dsa_reg_port_net(struct netmap_adapter *cpu_na,
                        struct netmap_dsa_adapter *dsa_na)
{
	struct netmap_dsa_slave_port_net *slave;

	if (!cpu_na->dsa_cpu)
		return EINVAL;

	slave = &cpu_na->dsa_cpu->slaves_net[dsa_na->port_num];
	if (slave->is_registered)
		return EBUSY;

	netmap_set_all_rings(cpu_na, NM_KR_LOCKED);
	slave->is_registered = true;
	cpu_na->dsa_cpu->reg_num_net++;
	netmap_set_all_rings(cpu_na, 0);

	if (netmap_debug & NM_DEBUG_DSA)
		nm_prerr("DSA slave port net '%s' registered to '%s', "
		         "port num = %d, tag type = %d, num of registered "
		         "ports = %d",
		         dsa_na->up.name, cpu_na->name, dsa_na->port_num,
		         dsa_na->tag_type, cpu_na->dsa_cpu->reg_num_net);
	return 0;
}

static int
netmap_dsa_unreg_port_net(struct netmap_adapter *cpu_na,
                          struct netmap_dsa_adapter *dsa_na)
{
	struct netmap_dsa_slave_port_net *slave;

	if (!cpu_na->dsa_cpu)
		return EINVAL;

	slave = &cpu_na->dsa_cpu->slaves_net[dsa_na->port_num];
	if (!slave->is_registered)
		return EINVAL;

	netmap_set_all_rings(cpu_na, NM_KR_LOCKED);
	slave->is_registered = false;
	cpu_na->dsa_cpu->reg_num_net--;
	netmap_set_all_rings(cpu_na, 0);

	if (netmap_debug & NM_DEBUG_DSA) {
		nm_prerr("DSA slave port net '%s' deregistered from '%s, "
		         "num of registered ports = %d",
		         dsa_na->up.name, cpu_na->name,
		         cpu_na->dsa_cpu->reg_num_net);
	}

	return 0;
}

static int
netmap_dsa_reg_port_host(struct netmap_adapter *cpu_na,
                         struct netmap_dsa_adapter *dsa_na,
                         struct netmap_kring *host_kring)
{
	struct netmap_dsa_slave_port_host *slave;

	if (!cpu_na->dsa_cpu)
		return EINVAL;

	slave = &cpu_na->dsa_cpu->slaves_host[dsa_na->port_num];
	if (slave->is_registered)
		return EBUSY;

	mbq_lock(&host_kring->rx_queue);
	slave->is_registered = true;
	cpu_na->dsa_cpu->reg_num_host++;
	mbq_unlock(&host_kring->rx_queue);

	if (netmap_debug & NM_DEBUG_DSA)
		nm_prerr("DSA slave port host '%s' registered to '%s', "
		         "port num = %d, tag type = %d, num of registered "
		         "ports = %d",
		         dsa_na->up.name, cpu_na->name, dsa_na->port_num,
		         dsa_na->tag_type, cpu_na->dsa_cpu->reg_num_host);
	return 0;
}

static int
netmap_dsa_unreg_port_host(struct netmap_adapter *cpu_na,
                           struct netmap_dsa_adapter *dsa_na,
                           struct netmap_kring *host_kring)
{
	struct netmap_dsa_slave_port_host *slave;

	if (!cpu_na->dsa_cpu)
		return EINVAL;

	slave = &cpu_na->dsa_cpu->slaves_host[dsa_na->port_num];
	if (!slave->is_registered)
		return EINVAL;

	mbq_lock(&host_kring->rx_queue);
	slave->is_registered = false;
	cpu_na->dsa_cpu->reg_num_host--;
	mbq_unlock(&host_kring->rx_queue);

	if (netmap_debug & NM_DEBUG_DSA) {
		nm_prerr("DSA slave port host '%s' deregistered from '%s, "
		         "num of registered ports = %d",
		         dsa_na->up.name, cpu_na->name,
		         cpu_na->dsa_cpu->reg_num_host);
	}

	return 0;
}

static int
handle_bind_mode(struct netmap_dsa_adapter *dsa_na, u8 *net, u8 *host)
{
	*net = 0;
	*host = 0;
	switch (dsa_na->bind_mode) {
	case NR_REG_ALL_NIC:
		*net = 1;
		break;

	case NR_REG_SW:
		*host = 1;
		break;

	case NR_REG_NIC_SW:
		*net = 1;
		*host = 1;
		break;

	default:
		nm_prerr("Invalid bind mode %d", dsa_na->bind_mode);
		return EINVAL;
	}

	return 0;
}

static int
netmap_dsa_reg_port(struct netmap_adapter *cpu_na,
                    struct netmap_dsa_adapter *dsa_na,
                    struct netmap_kring *host_kring)
{
	u8 net, host;
	int ret;

	ret = handle_bind_mode(dsa_na, &net, &host);
	if (ret)
		return ret;

	if (net) {
		ret = netmap_dsa_reg_port_net(cpu_na, dsa_na);
		if (ret)
			return ret;
	}

	if (host) {
		ret = netmap_dsa_reg_port_host(cpu_na, dsa_na, host_kring);
		if (ret)
			goto error;
	}

	return 0;
error:
	netmap_dsa_unreg_port_net(cpu_na, dsa_na);
	return ret;
}

static int
netmap_dsa_unreg_port(struct netmap_adapter *cpu_na,
                      struct netmap_dsa_adapter *dsa_na,
                      struct netmap_kring *host_kring)
{
	u8 net, host;
	int ret;

	ret = handle_bind_mode(dsa_na, &net, &host);
	if (ret)
		return ret;

	if (net) {
		ret = netmap_dsa_unreg_port_net(cpu_na, dsa_na);
		if (ret)
			return ret;
	}

	if (host) {
		ret = netmap_dsa_unreg_port_host(cpu_na, dsa_na, host_kring);
		if (ret)
			return ret;
	}

	return 0;
}

static int
netmap_dsa_reg(struct netmap_adapter *na, int onoff)
{
	struct netmap_dsa_adapter *dsa_na = (struct netmap_dsa_adapter *)na;
	struct netmap_adapter *cpu_na = dsa_na->cpu_na;
	struct netmap_dsa_cpu_port *dsa_cpu;
	struct netmap_kring *host_kring;
	int ret;

	if (na->active_fds)
		return 0;

	if (netmap_debug & NM_DEBUG_DSA)
		nm_prerr("onoff = %d", onoff);

	/* We lock on rx_queue from cpu port's host_kring to synchronize
	 * netmap_transmit */
	host_kring = NMR(cpu_na, NR_RX)[nma_get_nrings(na, NR_RX) + 1];
	dsa_cpu = cpu_na->dsa_cpu;
	if (onoff) {
		if (!dsa_cpu) {
			/*
			 * Allocate memory on first DSA slave port
			 * registration
			 */
			dsa_cpu = nm_os_malloc(sizeof(*cpu_na->dsa_cpu));
			if (!dsa_cpu)
				return ENOMEM;
			/*
			 * Lock setting of cpu_na->dsa_cpu pointer because it
			 * is used to indicate whether DSA mode is enabled
			 * in netmap_transmit
			 */
			mbq_lock(&host_kring->rx_queue);
			cpu_na->dsa_cpu = dsa_cpu;
			mbq_unlock(&host_kring->rx_queue);
		}

		ret = netmap_dsa_reg_port(cpu_na, dsa_na, host_kring);
		if (ret)
			return ret;

		dsa_na_tbl[dsa_na->port_num] = dsa_na;
		na->na_flags |= NAF_NETMAP_ON;
		if (netmap_debug & NM_DEBUG_DSA)
			nm_prerr("Enabled netmap mode for DSA "
			         "interface '%s'",
			         na->name);
	} else {
		ret = netmap_dsa_unreg_port(cpu_na, dsa_na, host_kring);
		if (ret)
			return ret;

		if (!dsa_cpu->reg_num_net && !dsa_cpu->reg_num_host) {

			/*
			 * Lock setting of cpu_na->dsa_cpu pointer because it
			 * is used to indicate whether DSA mode is enabled
			 * in netmap_transmit
			 */
			mbq_lock(&host_kring->rx_queue);
			cpu_na->dsa_cpu = NULL;
			mbq_unlock(&host_kring->rx_queue);

			nm_os_free(cpu_na->dsa_cpu);
		}

		dsa_na_tbl[dsa_na->port_num] = NULL;
		na->na_flags &= ~NAF_NETMAP_ON;
		if (netmap_debug & NM_DEBUG_DSA)
			nm_prerr("Disabled netmap mode for DSA "
			         "interface '%s'",
			         na->name);
	}

	return 0;
}

static int
netmap_dsa_krings_create(struct netmap_adapter *na)
{
	struct netmap_dsa_adapter *dsa_na = (struct netmap_dsa_adapter *)na;
	int ret;

	if (netmap_debug & NM_DEBUG_DSA)
		nm_prerr("Creating krings");

	ret = netmap_krings_create(na, 0);
	if (ret)
		return ret;

	if (dsa_na->bind_mode == NR_REG_ALL_NIC ||
	    dsa_na->bind_mode == NR_REG_NIC_SW)
		na->rx_rings[DSA_RX_SYNC_RING]->nr_kflags |= NKR_NEEDRING;

	return 0;
}

static void
netmap_dsa_krings_delete(struct netmap_adapter *na)
{
	if (netmap_debug & NM_DEBUG_DSA)
		nm_prerr("Deleting krings");

	netmap_krings_delete(na);
}

int
netmap_get_dsa_na(struct nmreq_header *hdr, struct netmap_adapter **na,
                  struct netmap_mem_d *nmd, int create)
{
	struct nmreq_register *req =
	        (struct nmreq_register *)(uintptr_t)hdr->nr_body;
	struct netmap_dsa_adapter *dsa_na;
	struct netmap_adapter *cpu_na;
	struct ifnet *ifp;
	int ret;

	if (strncmp(hdr->nr_name, DSA_IF_PREFIX, strlen(DSA_IF_PREFIX)))
		return 0;

	/* Find DSA cpu port */
	ifp = ifunit_ref(req->cpu_port_name);
	if (!ifp)
		return ENXIO;

	if (!NM_NA_VALID(ifp)) {
		nm_prerr("DSA cpu port '%s' is not native netmap interface",
		         req->cpu_port_name);
		return ENXIO;
	}

	cpu_na = NA(ifp);
	if (cpu_na == NULL)
		return ENXIO;

	/* Find DSA lan port */
	ifp = ifunit_ref(hdr->nr_name + strlen(DSA_IF_PREFIX));
	if (!ifp) {
		nm_prerr("DSA slave port '%s' not found",
		         hdr->nr_name + strlen(DSA_IF_PREFIX));
		return ENXIO;
	}

	if (dsa_na_tbl[req->port_num] &&
	    dsa_na_tbl[req->port_num]->bind_mode == req->nr_mode) {
		*na = &dsa_na_tbl[req->port_num]->up;
		netmap_adapter_get(*na);
		nm_prinf("Reusing DSA interface '%s'", (*na)->name);
		return 0;
	}

	dsa_na = nm_os_malloc(sizeof(*dsa_na));
	if (dsa_na == NULL)
		return ENOMEM;

	snprintf(dsa_na->up.name, sizeof(dsa_na->up.name), "%s", hdr->nr_name);
	dsa_na->up.nm_txsync = netmap_dsa_sync;
	dsa_na->up.nm_rxsync = netmap_dsa_sync;
	dsa_na->up.nm_register = netmap_dsa_reg;
	dsa_na->up.nm_krings_create = netmap_dsa_krings_create;
	dsa_na->up.nm_krings_delete = netmap_dsa_krings_delete;

	dsa_na->up.num_tx_rings = DSA_TX_RINGS_NUM;
	dsa_na->up.num_rx_rings = DSA_RX_RINGS_NUM;
	dsa_na->up.num_rx_sync_rings = DSA_RX_SYNC_RINGS_NUM;
	dsa_na->up.num_tx_desc = cpu_na->num_tx_desc;
	dsa_na->up.num_rx_desc = cpu_na->num_rx_desc;

	dsa_na->up.ifp = ifp;
	dsa_na->up.na_flags = NAF_HOST_RINGS;
	dsa_na->port_num = req->port_num;
	dsa_na->tag_type = req->tag_type;
	dsa_na->bind_mode = req->nr_mode;
	dsa_na->cpu_na = cpu_na;

	/* Validate tag */
	switch (dsa_na->tag_type) {
	case TAG_DSA_TYPE:
	case TAG_EDSA_TYPE:
		break;
	default:
		nm_prerr("Unsupported tag type %d", dsa_na->tag_type);
		ret = EINVAL;
		goto free_dsa_na;
	};

	if (netmap_debug & NM_DEBUG_DSA) {
		nm_prerr("DSA cpu port '%s' rx/tx rings = %d/%d,"
		         " rx/tx descs = %d/%d",
		         req->cpu_port_name, cpu_na->num_rx_rings,
		         cpu_na->num_tx_rings, cpu_na->num_rx_desc,
		         cpu_na->num_tx_desc);

		nm_prerr("DSA slave port '%s' rx/tx rings = %d/%d,"
		         " rx/tx descs = %d/%d",
		         dsa_na->up.name, dsa_na->up.num_rx_rings,
		         dsa_na->up.num_tx_rings, dsa_na->up.num_rx_desc,
		         dsa_na->up.num_tx_desc);
	}

	ret = netmap_attach_common(&dsa_na->up);
	if (ret)
		goto free_dsa_na;
	*na = &dsa_na->up;
	netmap_adapter_get(*na);

	nm_prinf("Created DSA interface '%s'", dsa_na->up.name);
	return 0;

free_dsa_na:
	nm_os_free(dsa_na);
	return ret;
}

#endif /* WITH_DSA */
