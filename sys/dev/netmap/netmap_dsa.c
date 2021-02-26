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
#include <dev/netmap/netmap_mem2.h>

#ifdef WITH_DSA

#include <dev/netmap/netmap_dsa.h>

static struct netmap_dsa_adapter *dsa_na_tbl[DSA_MAX_PORTS];

static int
netmap_dsa_sync(struct netmap_kring *kring, int flags)
{
	nm_prerr("Error operation not supported");
	return ENOTSUPP;
}

static void
netmap_dsa_print_port_stats_host(struct netmap_adapter *dsa_na,
                                 struct netmap_dsa_slave_port_host *slave)
{
	nm_prerr("DSA port host '%s' statistics", dsa_na->name);
	nm_prerr("drop_rx_no_space : %llu", slave->stats.drop_rx_no_space);
	nm_prerr("rcv_pkts : %llu", slave->stats.rcv_pkts);
}

static void
netmap_dsa_print_stats_host(struct netmap_dsa_cpu_port *dsa_cpu)
{
	nm_prerr("DSA port independent host statistics");
	nm_prerr("drop_inv_tag : %llu\n", dsa_cpu->stats_host.drop_rx_inv_tag);
	nm_prerr("drop_inv_port : %llu", dsa_cpu->stats_host.drop_rx_inv_port);
	nm_prerr("drop_not_reg : %llu", dsa_cpu->stats_host.drop_rx_not_reg);
}

static void
netmap_dsa_print_port_stats_net(struct netmap_adapter *dsa_na,
                                struct netmap_dsa_slave_port_net *slave)
{
	nm_prerr("DSA port net '%s' statistics", dsa_na->name);
	nm_prerr("drop_rx_full : %llu", slave->stats.drop_rx_full);
	nm_prerr("drop_rx_sync_full : %llu", slave->stats.drop_rx_sync_full);
	nm_prerr("event_rx_full : %llu", slave->stats.event_rx_no_space);
	nm_prerr("rcv_pkts : %llu", slave->stats.rcv_pkts);
	nm_prerr("drop_tx_no_headroom : %llu",
	         slave->stats.drop_tx_no_headroom);
	nm_prerr("sent_pkts : %llu", slave->stats.sent_pkts);
}

static void
netmap_dsa_print_stats_net(struct netmap_dsa_cpu_port *dsa_cpu)
{
	nm_prerr("DSA port independent net statistics");
	nm_prerr("drop_inv_tag : %llu\n", dsa_cpu->stats_net.drop_rx_inv_tag);
	nm_prerr("drop_inv_port : %llu", dsa_cpu->stats_net.drop_rx_inv_port);
	nm_prerr("drop_not_reg : %llu", dsa_cpu->stats_net.drop_rx_not_reg);
}

static int
netmap_dsa_reserve_tx_cpu_kring(struct netmap_adapter *cpu_na, u8 *is_excl_tx)
{
	int i;

	*is_excl_tx = 1;
	for (i = 0; i < (cpu_na->num_tx_rings - 1) && i < DSA_MAX_PORTS; i++)
		if (!cpu_na->dsa_cpu->is_tx_kring_used[i]) {
			cpu_na->dsa_cpu->is_tx_kring_used[i] = true;
			break;
		}

	if (i == cpu_na->num_tx_rings - 1) {
		/*
		 * When there are less cpu tx krings than DSA slave ports then
		 * the last cpu tx kring is shared between DSA slave ports
		 */
		i = cpu_na->num_tx_rings - 1;
		*is_excl_tx = 0;
	}

	return i;
}

static void
netmap_dsa_update_kring_offset(struct netmap_kring *kring, int offset)
{
	int i;

	for (i = 0; i < kring->nkr_num_slots; i++) {
		struct netmap_slot *slot = &kring->ring->slot[i];
		slot->data_offs += offset;
		slot->len -= offset;
	}
}

static int
netmap_dsa_reg_port_net(struct netmap_adapter *cpu_na,
                        struct netmap_dsa_adapter *dsa_na)
{
	struct netmap_dsa_slave_port_net *slave;
	u8 idx, is_excl_tx;

	if (!cpu_na->dsa_cpu)
		return EINVAL;

	slave = &cpu_na->dsa_cpu->slaves_net[dsa_na->port_num];
	if (slave->is_registered)
		return EBUSY;

	netmap_set_all_rings(cpu_na, NM_KR_LOCKED);
	slave->rx_kring = dsa_na->up.rx_rings[DSA_RX_RING];
	slave->rx_sync_kring = dsa_na->up.rx_rings[DSA_RX_SYNC_RING];
	slave->rx_si = &dsa_na->up.rx_rings[DSA_RX_SYNC_RING]->si;

	idx = netmap_dsa_reserve_tx_cpu_kring(cpu_na, &is_excl_tx);
	slave->tx_kring = dsa_na->up.tx_rings[DSA_TX_RING];
	slave->tx_cpu_kring = cpu_na->tx_rings[idx];
	netmap_dsa_update_kring_offset(slave->tx_kring,
	                               sizeof(struct edsa_tag));
	if (is_excl_tx)
		slave->tx_cpu_kring_lock = NULL;
	else
		slave->tx_cpu_kring_lock = &cpu_na->tx_rings[idx]->q_lock.sl;
	dsa_na->tx_cpu_kring_idx = idx;

	slave->is_registered = true;
	cpu_na->dsa_cpu->reg_num_net++;
	netmap_set_all_rings(cpu_na, 0);

	if (netmap_debug & NM_DEBUG_DSA)
		nm_prerr("DSA slave port net '%s' registered to '%s', "
		         "port num = %d, tag type = %d, tx cpu kring index %d "
		         "mode %d, num of registered ports = %d",
		         dsa_na->up.name, cpu_na->name, dsa_na->port_num,
		         dsa_na->tag_type, dsa_na->tx_cpu_kring_idx, is_excl_tx,
		         cpu_na->dsa_cpu->reg_num_net);
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
	if (netmap_debug & NM_DEBUG_DSA_STATS) {
		netmap_dsa_print_port_stats_net(&dsa_na->up, slave);
		memset(&slave->stats, 0,
		       sizeof(struct netmap_dsa_slave_net_stats));
	}

	cpu_na->dsa_cpu->is_tx_kring_used[dsa_na->tx_cpu_kring_idx] = false;
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
	slave->host_kring = dsa_na->up.rx_rings[DSA_RX_HOST_RING];
	slave->rx_si = &dsa_na->up.rx_rings[DSA_RX_HOST_RING]->si;
	slave->port_name = dsa_na->up.name;
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
	if (netmap_debug & NM_DEBUG_DSA_STATS) {
		netmap_dsa_print_port_stats_host(&dsa_na->up, slave);
		memset(&slave->stats, 0,
		       sizeof(struct netmap_dsa_slave_host_stats));
	}
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
	enum txrx t;
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

			spin_lock_init(&dsa_cpu->dsa_rx_poll_lock);

			/* Copy params for poll on DSA cpu port */
			for_rx_tx(t)
			{
				dsa_cpu->np_si[t] = cpu_na->nm_priv->np_si[t];
				dsa_cpu->np_qfirst[t] =
				        cpu_na->nm_priv->np_qfirst[t];
				dsa_cpu->np_qlast[t] =
				        cpu_na->nm_priv->np_qlast[t];
			}
			dsa_cpu->tag_type = dsa_na->tag_type;
			dsa_cpu->np_txpoll = cpu_na->nm_priv->np_txpoll;
			dsa_cpu->np_sync_flags = cpu_na->nm_priv->np_sync_flags;
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
			if (netmap_debug & NM_DEBUG_DSA_STATS) {
				netmap_dsa_print_stats_net(dsa_cpu);
				netmap_dsa_print_stats_host(dsa_cpu);
			}

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
netmap_dsa_rx_sync(struct netmap_kring *kring, int flags)
{
	struct netmap_dsa_adapter *dsa_na =
	        (struct netmap_dsa_adapter *)kring->na;
	struct netmap_dsa_slave_port_net *slave =
	        &dsa_na->cpu_na->dsa_cpu->slaves_net[dsa_na->port_num];
	struct netmap_kring *to_kring = slave->rx_kring;
	struct netmap_ring *from_ring = slave->rx_sync_kring->ring;
	struct netmap_ring *to_ring = to_kring->ring;
	spinlock_t *lock = &slave->rx_sync_kring->q_lock.sl;
	struct netmap_slot *from_slot, *to_slot;
	u32 i, n, m, head, tail;

	spin_lock(lock);

	head = from_ring->head;
	tail = to_ring->tail;

	n = nm_rxring_pkts_avail(from_ring);
	m = nm_rxring_slots_avail(to_ring);
	if (m < n) {
		if (netmap_debug & NM_DEBUG_DSA)
			nm_prerr("Num of slots avail in rx kring %d is less "
			         "than number of pkts in rx sync kring %d "
			         "for port %d",
			         m, n, dsa_na->port_num);

		slave->stats.event_rx_no_space++;
		n = m;
	}

	for (i = 0; i < n; i++) {
		from_slot = &from_ring->slot[head];
		to_slot = &to_ring->slot[tail];

		/* Move buffers between krings */
		netmap_dsa_move_buffers(to_slot, from_slot);

		head = nm_ring_next(from_ring, head);
		tail = nm_ring_next(to_ring, tail);
	}

	if (n) {
		from_ring->head = from_ring->cur = head;
		to_ring->tail = tail;

		to_kring->nr_hwtail = to_ring->tail;
		to_kring->nr_hwcur = to_kring->rhead;

		slave->stats.rcv_pkts += n;
	}

	spin_unlock(lock);
	return 0;
}

static int
netmap_dsa_tx_sync(struct netmap_kring *kring, int flags)
{
	struct netmap_dsa_adapter *dsa_na =
	        (struct netmap_dsa_adapter *)kring->na;
	struct netmap_dsa_cpu_port *dsa_cpu = dsa_na->cpu_na->dsa_cpu;
	struct netmap_dsa_slave_port_net *slave =
	        &dsa_cpu->slaves_net[dsa_na->port_num];
	struct netmap_adapter *cpu_na = dsa_na->cpu_na;
	struct netmap_ring *to_ring = slave->tx_cpu_kring->ring;
	struct netmap_kring *from_kring = slave->tx_kring;
	struct netmap_ring *from_ring = from_kring->ring;
	struct netmap_slot *from_slot, *to_slot;
	u32 i, n, m, head, tail;
	u8 *buf, *tag;

	tag = dsa_na->tag_type == TAG_EDSA_TYPE ? (u8 *)&dsa_na->tag
	                                        : (u8 *)&dsa_na->tag.dtag;

	/* Lock access to tx cpu kring if we share it with other threads */
	if (slave->tx_cpu_kring_lock)
		spin_lock(slave->tx_cpu_kring_lock);

	head = to_ring->head;
	tail = from_ring->tail;

	n = nm_txring_pkts_avail(from_ring);
	m = nm_txring_slots_avail(to_ring);
	if (m < n)
		n = m;

	for (i = 0; i < n; i++) {
		to_slot = &to_ring->slot[head];
		tail = nm_ring_next(from_ring, tail);
		from_slot = &from_ring->slot[tail];

		netmap_dsa_move_buffers(to_slot, from_slot);
		if (dsa_na->tag_len <= to_slot->data_offs) {
			buf = NMB(cpu_na, to_slot) + to_slot->data_offs;
			netmap_dsa_add_tag(buf, to_slot, tag, dsa_na->tag_len);
		} else {
			nm_prerr("Error packet headroom %d is less than "
			         "required for tag %d. Packet will be dropped",
			         to_slot->data_offs, dsa_na->tag_len);

			slave->stats.drop_tx_no_headroom++;
		}

		head = nm_ring_next(to_ring, head);
	}

	if (n) {
		to_ring->head = to_ring->cur = head;
		from_ring->tail = tail;

		from_kring->nr_hwtail = from_ring->tail;
		from_kring->nr_hwcur = from_kring->rhead;

		slave->stats.sent_pkts += n;
	}

	if (slave->tx_cpu_kring_lock)
		spin_unlock(slave->tx_cpu_kring_lock);

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

	dsa_na->up.rx_rings[DSA_RX_RING]->nm_sync = netmap_dsa_rx_sync;
	dsa_na->up.rx_rings[DSA_RX_HOST_RING]->nm_sync =
	        netmap_dsa_rxsync_from_host;
	dsa_na->up.tx_rings[DSA_TX_RING]->nm_sync = netmap_dsa_tx_sync;

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
netmap_dsa_dispatch_rcv_pkts(struct netmap_kring *from_kring,
                             struct netmap_adapter *cpu_na,
                             uint16_t poll_port_num)
{
	struct netmap_dsa_slave_port_net *slaves = cpu_na->dsa_cpu->slaves_net;
	struct netmap_dsa_stats *stats = &cpu_na->dsa_cpu->stats_net;
	struct netmap_ring *from_ring = from_kring->ring;
	struct netmap_slot *from_slot, *to_slot;
	struct netmap_kring *to_kring;
	struct netmap_ring *to_ring;
	u32 i, n, head, ret = 0;
	u8 tag_type, tag_len;
	union dsa_tag *tag;
	spinlock_t *lock;
	u8 src_port_num;
	u8 *buf;

	tag_type = cpu_na->dsa_cpu->tag_type;
	head = from_ring->head;
	n = nm_rxring_pkts_avail(from_ring);
	for (i = 0; i < n; i++) {
		from_slot = &from_ring->slot[head];

		buf = NMB(cpu_na, from_slot) + from_slot->data_offs;
		tag = netmap_dsa_get_tag(buf, tag_type, &tag_len);
		if (!tag) {
			stats->drop_rx_inv_tag++;
			goto next_slot;
		}

		if (tag->s.mode != DSA_FORWARD_MODE) {
			if (netmap_debug & NM_DEBUG_DSA)
				nm_prerr("Only forward frames are accepted, "
				         "received frame in mode %d",
				         tag->s.mode);

			stats->drop_rx_inv_tag++;
			goto next_slot;
		}

		src_port_num = tag->s.port;
		if (src_port_num >= DSA_MAX_PORTS) {
			if (netmap_debug & NM_DEBUG_DSA)
				nm_prerr("Port number of received net frame "
				         "%d exceeds maximum supported ports "
				         "%d",
				         src_port_num, DSA_MAX_PORTS);

			stats->drop_rx_inv_port++;
			goto next_slot;
		}

		if (!slaves[src_port_num].is_registered) {
			if (netmap_debug & NM_DEBUG_DSA)
				nm_prerr("Received net packet for not "
				         "registered slave port %d",
				         src_port_num);

			stats->drop_rx_not_reg++;
			goto next_slot;
		}

		/*
		 * If source port of received packet is equal to poll_port_num
		 * then we can move received packet directly to rx kring
		 * because we are in the context of the thread which called
		 * poll, otherwise we need to move packet to rx_sync kring
		 * because a tread might be processing packets from its
		 * rx kring. In this case we also have to sync on rx sync kring
		 * because owning thread might try to read packets from its
		 * rx sync kring.
		 */
		if (src_port_num == poll_port_num) {
			to_kring = slaves[src_port_num].rx_kring;
			lock = NULL;
		} else {
			to_kring = slaves[src_port_num].rx_sync_kring;
			lock = &to_kring->q_lock.sl;
		}

		if (lock && !slaves[src_port_num].is_rx_locked) {
			/*
			 * Lock rx sync kring only if it wasn't already
			 * locked during processing of current kring
			 */
			spin_lock(lock);
			slaves[src_port_num].is_rx_locked = true;
		}

		to_ring = to_kring->ring;
		if (!nm_rxring_slots_avail(to_ring)) {
			if (netmap_debug & NM_DEBUG_DSA)
				nm_prerr("No available slots in destination "
				         "ring for net port %d, poll_port_num "
				         "%d",
				         tag->s.port, poll_port_num);
			if (lock) {
				/*
				 * There is no space in destination kring
				 * therefore unlock it to allow owning thread
				 * to read packets
				 */
				spin_unlock(lock);

				slaves[src_port_num].is_rx_locked = false;
				slaves[src_port_num].stats.drop_rx_sync_full++;
			} else
				slaves[src_port_num].stats.drop_rx_full++;

			goto next_slot;
		}

		/* Move buffers between krings */
		to_slot = &to_ring->slot[to_ring->tail];
		netmap_dsa_move_buffers(to_slot, from_slot);
		to_ring->tail = nm_ring_next(to_ring, to_ring->tail);
		to_kring->rtail = to_kring->nr_hwtail = to_ring->tail;
		to_kring->nr_hwcur = to_kring->rhead;

		/*
		 * The function does the following:
		 * - moves Eth MAC addresses up by tag_len bytes,
		 * - moves tag before Eth frame,
		 * - increases data offset in slot by tag_len bytes
		 * - decreases data length in slot by tag_len bytes.
		 */
		netmap_dsa_move_tag_buf(to_slot, buf, tag, tag_len);

		if (src_port_num == poll_port_num)
			/*
			 * We return true only if there was at least one packet
			 * dispatched to the thread in which context poll call
			 * is being run
			 */
			ret = 1;

		/*
		 * Increase number of received packets only
		 * in case if we moved packet to rx kring
		 */
		if (!lock)
			slaves[src_port_num].stats.rcv_pkts++;
	next_slot:
		head = nm_ring_next(from_ring, head);
	}

	from_ring->head = from_ring->cur = head;

	/* Unlock locked krings and notify listeners */
	for (i = 0; i < DSA_MAX_PORTS; i++)
		if (slaves[i].is_rx_locked) {
			spin_unlock(&slaves[i].rx_sync_kring->q_lock.sl);
			slaves[i].is_rx_locked = false;
			nm_os_selwakeup(slaves[i].rx_si);
		}

	return ret;
}

int
netmap_dsa_enqueue_host_pkt(struct netmap_adapter *cpu_na, struct mbuf *m)
{
	struct netmap_dsa_slave_port_host *slaves =
	        cpu_na->dsa_cpu->slaves_host;
	struct netmap_dsa_stats *stats = &cpu_na->dsa_cpu->stats_host;
	u8 busy, tag_type, tag_len;
	struct netmap_kring *kring;
	union dsa_tag *tag;
	u8 src_port_num;
	struct mbq *q;
	int ret = 0;

	tag_type = cpu_na->dsa_cpu->tag_type;
	tag = netmap_dsa_get_tag(m->data, tag_type, &tag_len);
	if (!tag)
		goto exit;

	if (tag->s.mode != DSA_FROM_CPU_MODE) {
		if (netmap_debug & NM_DEBUG_DSA)
			nm_prerr("Only from cpu frames are accepted, "
			         "received frame in mode %d",
			         tag->s.mode);

		stats->drop_rx_inv_tag++;
		goto exit;
	}

	src_port_num = tag->s.port;
	if (src_port_num >= DSA_MAX_PORTS) {
		if (netmap_debug & NM_DEBUG_DSA)
			nm_prerr("Port number of received host frame %d "
			         "exceeds maximum supported ports %d",
			         src_port_num, DSA_MAX_PORTS);

		stats->drop_rx_inv_port++;
		goto exit;
	}

	if (!slaves[src_port_num].is_registered) {
		if (netmap_debug & NM_DEBUG_DSA)
			nm_prerr("Received host packet for not registered "
			         "slave port %d",
			         src_port_num);

		stats->drop_rx_not_reg++;
		goto exit;
	}

	kring = slaves[src_port_num].host_kring;
	q = &kring->rx_queue;

	mbq_lock(q);
	busy = kring->nr_hwtail - kring->nr_hwcur;
	if (busy < 0)
		busy += kring->nkr_num_slots;
	if (busy + mbq_len(q) >= kring->nkr_num_slots - 1) {
		nm_prlim(2, "%s full hwcur %d hwtail %d qlen %d",
		         slaves[src_port_num].port_name, kring->nr_hwcur,
		         kring->nr_hwtail, mbq_len(q));
		slaves[src_port_num].stats.drop_rx_no_space++;
	} else {
		netmap_dsa_move_tag_skbuf(m, tag, tag_len);
		mbq_enqueue(q, m);
		slaves[src_port_num].stats.rcv_pkts++;
		ret = 1;
	}
	mbq_unlock(q);

	if (ret)
		nm_os_selwakeup(&kring->si);
exit:
	return ret;
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
	dsa_na->up.nm_poll = netmap_dsa_poll;
	dsa_na->up.nm_ioctl_rxtx_sync = netmap_ioctl_dsa_rxtx_sync;
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
		dsa_na->tag_len = DSA_TAG_LEN;
		break;
	case TAG_EDSA_TYPE:
		dsa_na->tag_len = EDSA_TAG_LEN;
		break;
	default:
		nm_prerr("Unsupported tag type %d", dsa_na->tag_type);
		ret = EINVAL;
		goto free_dsa_na;
	};

	/* Build tag */
	dsa_na->tag.dsa_ether_type = ETH_P_EDSA;
	dsa_na->tag.dtag.s.mode = DSA_FROM_CPU_MODE;
	dsa_na->tag.dtag.s.tagged = req->tagged;
	dsa_na->tag.dtag.s.port = req->port_num;
	dsa_na->tag.dtag.s.vlan_prio = req->vlan_prio;
	dsa_na->tag.dtag.s.vlan_id = req->vlan_id;
	dsa_na->tag.dtag.u32 = htonl(dsa_na->tag.dtag.u32);

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
