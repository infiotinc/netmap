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

#ifndef _NET_NETMAP_DSA_H__
#define _NET_NETMAP_DSA_H__

#define DSA_RX_RINGS_NUM 1
#define DSA_TX_RINGS_NUM 1
#define DSA_RX_SYNC_RINGS_NUM 1

#define DSA_RX_RING 0
#define DSA_RX_HOST_RING 1
#define DSA_RX_SYNC_RING 2

#define DSA_TX_RING 0

#define DSA_FROM_CPU_MODE 1
#define DSA_FORWARD_MODE 3

static inline union dsa_tag *
netmap_dsa_get_tag(u8 *buf, u8 tag_type, u8 *tag_len)
{
	struct edsa_tag *etag;
	union dsa_tag *dtag;

	buf += 2 * ETH_ALEN;
	if (tag_type == TAG_EDSA_TYPE) {
		etag = (struct edsa_tag *)buf;
		if (etag->dsa_ether_type != ETH_P_EDSA) {
			if (netmap_debug & NM_DEBUG_DSA) {
				nm_prerr("EDSA invalid header value %x, "
				         "expected %x",
				         etag->dsa_ether_type, ETH_P_EDSA);
			}
			return NULL;
		}

		dtag = &etag->dtag;
		*tag_len = EDSA_TAG_LEN;
	} else {
		dtag = (union dsa_tag *)buf;
		*tag_len = DSA_TAG_LEN;
	}

	dtag->u32 = ntohl(dtag->u32);
	return dtag;
}

static inline void
netmap_dsa_move_buffers(struct netmap_slot *to_slot,
                        struct netmap_slot *from_slot)
{
	u32 pkt = to_slot->buf_idx;

	to_slot->buf_idx = from_slot->buf_idx;
	from_slot->buf_idx = pkt;

	to_slot->len = from_slot->len;
	to_slot->data_offs = from_slot->data_offs;

	to_slot->flags |= NS_BUF_CHANGED;
	from_slot->flags |= NS_BUF_CHANGED;
}

static inline void
netmap_dsa_move_tag_buf(struct netmap_slot *slot, u8 *buf,
                        union dsa_tag *tag_ptr, u8 tag_len)
{
	union dsa_tag tag = *tag_ptr;

	memmove(buf + tag_len, buf, 2 * ETH_ALEN);
	slot->data_offs += tag_len;
	slot->len -= tag_len;

	tag_ptr = (union dsa_tag *)(buf + tag_len - DSA_TAG_LEN);
	*tag_ptr = tag;
}

static inline void
netmap_dsa_move_tag_skbuf(struct mbuf *m, union dsa_tag *tag_ptr, u8 tag_len)
{
	union dsa_tag tag = *tag_ptr;

	memmove(m->data + tag_len, m->data, 2 * ETH_ALEN);
	tag_ptr = (union dsa_tag *)(m->data + tag_len - DSA_TAG_LEN);
	*tag_ptr = tag;
}

static inline void
netmap_dsa_add_tag(u8 *buf, struct netmap_slot *slot, u8 *tag_ptr, u8 tag_len)
{
	buf = memmove(buf - tag_len, buf, 2 * ETH_ALEN);
	memcpy(buf + 2 * ETH_ALEN, tag_ptr, tag_len);
	slot->data_offs -= tag_len;
	slot->len += tag_len;
}

static inline uint32_t
nm_ring_next(struct netmap_ring *r, uint32_t i)
{
	return (unlikely(i + 1 == r->num_slots) ? 0 : i + 1);
}

static inline uint32_t
nm_rxring_pkts_avail(struct netmap_ring *ring)
{
	int ret = ring->tail - ring->head;
	if (ret < 0)
		ret += ring->num_slots;
	return ret;
}

static inline int
nm_rxring_slots_avail(struct netmap_ring *ring)
{
	int ret = ring->head - ring->tail;
	if (ret <= 0)
		ret += ring->num_slots - 1;
	return ret;
}

static inline uint32_t
nm_txring_pkts_avail(struct netmap_ring *ring)
{
	int ret = ring->head - ring->tail;
	if (ret <= 0)
		ret += ring->num_slots;
	return ret - 1;
}

static inline uint32_t
nm_txring_slots_avail(struct netmap_ring *ring)
{
	int ret = ring->tail - ring->head;
	if (ret < 0)
		ret += ring->num_slots;
	return ret;
}

#endif
