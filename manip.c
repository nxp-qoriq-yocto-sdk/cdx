/*
*   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
*   Copyright 2016 NXP
*
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/

 
/**     
 * @file                manip.c     
 * @description         dpaa manipulation funcs 
 */             

#ifndef USE_ENHANCED_EHASH 
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "misc.h"
#include "cdx.h"
#include "cdx_common.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_pppoe.h"
#include "control_tunnel.h"
#include "jenk_hash.h"

#include <linux/fsl_dpa_offload.h>
#include <linux/fsl_dpa_classifier.h>

//#define MANIP_DEBUG 	1

#ifdef MANIP_DEBUG
#define MANIP_DPRINT(fmt, args...) printk(KERN_ERR "%s:: " fmt, __func__, ##args)
#else
#define MANIP_DPRINT(fmt, args...) do { } while(0)
#endif

//default action for Frag HMD in case DF bit is set
#define DEFAULT_DFACTION	DPA_CLS_HM_DF_ACTION_DROP

#define IPV4ADDR_SWAP(x)	(x)
#define IPV6ADDR_SWAP(x)	htonl(x)
#define PORT_SWAP(x)		htons(x)

#define L3_HDR_OPS(l3_info) (l3_info.tnl_header_present || l3_info.add_tnl_header)

struct mac_addr {
	union {
		uint32_t hdr_32[3];
		uint8_t l2_hdr[12];
	};
};


//db entry for reusing a hm chain
#define TTL_HM_VALID		(1 << 0)
#define NAT_HM_REPLACE_SIP	(1 << 1)
#define NAT_HM_REPLACE_DIP	(1 << 2)
#define NAT_HM_REPLACE_SPORT	(1 << 3)
#define NAT_HM_REPLACE_DPORT	(1 << 4)
#define NAT_HM_VALID		( NAT_HM_REPLACE_SIP | NAT_HM_REPLACE_DIP | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT)
#define VLAN_STRIP_HM_VALID	(1 << 5)
#define VLAN_ADD_HM_VALID	(1 << 6)
#define ETHERNET_HM_VALID	(1 << 7)
#define PPPoE_STRIP_HM_VALID	(1 << 8)
#define NAT_HM_NATPT		(1 << 9)

#define MAX_VLAN_INS		8
#define MAX_HM_BUCKETS		64


#define IS_IPV4_NAT(entry) ( IS_IPV4(entry) && (entry->status & CONNTRACK_NAT) )
#define IS_IPV6_NAT(entry) ( IS_IPV6(entry) && ( entry->status & ( CONNTRACK_SNAT | CONNTRACK_DNAT) ))

extern int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
		struct dpa_l3hdr_info *l3_info, PRouteEntry tnl_rt_entry, int queue);

struct hm_hash_key {
	union {
		struct {
			uint32_t nat_sip;
			uint32_t nat_dip;
		} v4;
		struct {
			uint32_t nat_sip[4];
			uint32_t nat_dip[4];
		} v6;
	};
	uint16_t nat_sport;
	uint16_t nat_dport;
	uint16_t vlan_ids[MAX_VLAN_INS];
	uint16_t flags;
	uint8_t l2_hdr[(ETHER_ADDR_LEN * 2)];
}DPA_PACKED;

struct hm_chain_info {
	struct hm_hash_key key;
	int hm_chain_head;
	uint32_t ref_count;
	uint32_t hashval;
	struct hm_chain_info *next;
};

static struct hm_chain_info *hm_buckets[MAX_HM_BUCKETS];
static DEFINE_SPINLOCK(hm_db_lock);

extern void display_buf(void *, uint32_t);

static inline struct hm_chain_info *find_entry_in_hm_hash_table(
		struct hm_chain_info *info)
{
	struct hm_chain_info *tmp;

	info->hashval = compute_jenkins_hash((uint8_t *)&info->key, 
			sizeof(struct hm_hash_key), 0);	
	info->hashval &= (MAX_HM_BUCKETS - 1);
	tmp = hm_buckets[info->hashval];
	while(tmp) {
              if (memcmp(&tmp->key, &info->key, sizeof(struct hm_hash_key)) == 0) {
			tmp->ref_count++;	
			kfree(info);
			return tmp;
		}
		tmp = tmp->next;
	}
	info->hm_chain_head = DPA_OFFLD_DESC_NONE;
	info->ref_count = 1;
	return info;
}

static inline void add_entry_to_hm_hash_table(struct hm_chain_info *info)
{
	info->next = hm_buckets[info->hashval];
	hm_buckets[info->hashval] = info;
}

void delete_entry_from_hm_hash_table(struct hm_chain_info *info)
{
  struct hm_chain_info *tmp;
  struct hm_chain_info *prev;

  prev = NULL;
  spin_lock(&hm_db_lock);
  tmp = hm_buckets[info->hashval];
  while(tmp)
  {
    if (tmp == info)
    {
      info->ref_count--;
      if (info->ref_count)
      {
        MANIP_DPRINT("hm ref count is %d\n", info->ref_count);
        goto func_ret;
      }
      //remove from list
      if (prev)
        prev->next = info->next;
      else
        hm_buckets[info->hashval] = info->next;
      //free the entry
      kfree(info);
      goto func_ret;
    }
    prev = tmp;
    tmp = tmp->next;
  }
        DPA_ERROR("%s::entry %p not found\n", __FUNCTION__, info);
func_ret:
        spin_unlock(&hm_db_lock);

}

void delete_hm_chain(struct hw_ct * ct)
{
	struct hm_chain_info *info;
	struct hm_chain_info *tmp;
	struct hm_chain_info *prev;

	prev = NULL;
	info = ct->hm_info;
	if(!info)
		return;
	spin_lock(&hm_db_lock);
	tmp = hm_buckets[info->hashval];
	while(tmp) {
		if (tmp == info) {
			info->ref_count--;
			if (info->ref_count)  {
				MANIP_DPRINT("hm ref count is %d\n", info->ref_count);
				goto func_ret;
			}
			if (info->hm_chain_head != DPA_OFFLD_DESC_NONE) {
				//delete chain in the dpaa
				MANIP_DPRINT("removing hm %d\n", info->hm_chain_head);
				if (dpa_classif_free_hm(info->hm_chain_head))
				{
					DPA_ERROR("%s::failed to "
							"free hm chain hm %d\n",
							__FUNCTION__, 
							info->hm_chain_head);
					goto func_ret;
				}
			}	
			//remove from list
			if (prev) 
				prev->next = info->next;
			else
				hm_buckets[info->hashval] = 
					info->next;
			//free the entry
			kfree(info);
			goto func_ret;
		} 
		prev = tmp;
		tmp = tmp->next;
	}
	DPA_ERROR("%s::entry %p not found\n", __FUNCTION__, info);
func_ret:
	spin_unlock(&hm_db_lock);
}

static inline void fill_mac_addr(struct dpa_cls_hm_fwd_params *
		fwd_params, uint8_t *dst_mac, 
		uint8_t *src_mac)
{
	struct mac_addr mac_addr;

	memcpy(&mac_addr.l2_hdr[0], dst_mac, ETHER_ADDR_LEN);
	memcpy(&mac_addr.l2_hdr[ETHER_ADDR_LEN], src_mac, ETHER_ADDR_LEN);
	memcpy(&fwd_params->eth.macda, &mac_addr.l2_hdr[0], ETHER_ADDR_LEN);
	memcpy(&fwd_params->eth.macsa, &mac_addr.l2_hdr[ETHER_ADDR_LEN], ETHER_ADDR_LEN);
}

//routine to create a routing hmanip
//hm_index points to the next available slot for saving hm
int create_routing_hm(void *fm_pcd, uint32_t fm_idx, 
		struct dpa_l2hdr_info *l2_info,
		uint32_t mtu, uint32_t frag_poolid, 
		int32_t *hmd, int32_t *hm_index, uint32_t head)
{
	struct dpa_cls_hm_fwd_params fwd_params;

	//insert vlan headers if required
	if (l2_info->num_egress_vlan_hdrs) {
		struct dpa_cls_hm_vlan_params vlan_params;	
		uint32_t ii;

		MANIP_DPRINT("adding Vlan hdrs in pkt, curr hm_index %d, next hm %d\n",
				*hm_index, hmd[*hm_index - 1]);
		memset(&vlan_params, 0,
				sizeof(struct dpa_cls_hm_vlan_params));
		vlan_params.type = DPA_CLS_HM_VLAN_EGRESS;
		vlan_params.egress.update_op = DPA_CLS_HM_VLAN_UPDATE_NONE; 	
		vlan_params.egress.num_tags = l2_info->num_egress_vlan_hdrs;
		for (ii = 0; ii < vlan_params.egress.num_tags; ii++) {
			vlan_params.egress.qtag[ii].tpid = 
				htons(l2_info->egress_vlan_hdrs[ii].tpid);
			vlan_params.egress.qtag[ii].tci = 
				htons(l2_info->egress_vlan_hdrs[ii].tci);
		}
		vlan_params.fm_pcd = fm_pcd;	
		MANIP_DPRINT("inserting %d Vlan hdrs in egress pkt\n",
				l2_info->num_egress_vlan_hdrs);
		if (dpa_classif_set_vlan_hm(&vlan_params,
					hmd[*hm_index - 1],
					&hmd[*hm_index], 0, NULL)) {
			DPA_ERROR("%s::unable to add vlan ins manip\n",
					__FUNCTION__);
			return FAILURE;
		}
		*hm_index += 1;
		MANIP_DPRINT("created ins vlan hm handle %d\n", hmd[*hm_index - 1]);
		//head = 0;
	}
	MANIP_DPRINT("creating forward hm, curr hm_index %d, next hm %d\n",
			*hm_index, hmd[*hm_index - 1]);
	memset(&fwd_params, 0, sizeof(struct dpa_cls_hm_fwd_params));
	fwd_params.fm_pcd = fm_pcd;
	fwd_params.out_if_type = DPA_CLS_HM_IF_TYPE_ETHERNET;
	if (l2_info->add_pppoe_hdr) {
		//if pppoe header required, replace dest with ac conc address	
		fill_mac_addr(&fwd_params, &l2_info->ac_mac_addr[0], 
				&l2_info->l2hdr[ETHER_ADDR_LEN]);
	} else {
		fill_mac_addr(&fwd_params, &l2_info->l2hdr[0], 
				&l2_info->l2hdr[ETHER_ADDR_LEN]);
	}
#ifdef MANIP_DEBUG
	DPA_INFO("destmac :: ");
	display_mac_addr(&fwd_params.eth.macda[0]);
	DPA_INFO("srcmac  :: ");
	display_mac_addr(&fwd_params.eth.macsa[0]);
#endif
#if 1//def DISABLE_IPFRAG
	fwd_params.ip_frag_params.mtu = 0;
#else
	fwd_params.ip_frag_params.mtu = mtu;
#endif
	fwd_params.ip_frag_params.scratch_bpid = frag_poolid;
	fwd_params.ip_frag_params.df_action = DEFAULT_DFACTION;
	MANIP_DPRINT("adding fwd hdrmanip in pkt\n");
	if (dpa_classif_set_fwd_hm(&fwd_params, hmd[*hm_index - 1], 
				&hmd[*hm_index], head, NULL)) {
		DPA_ERROR("%s::create fwd hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created forward hm %d\n", hmd[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}

//routine to create a ipv4 ttl decr hmanip
int create_ttl_hm(void *fm_pcd, uint32_t fm_idx, int *hm, int *hm_index, 
		uint32_t head, int l3protoIPv4) 
{
	struct dpa_cls_hm_update_params upd_params;

	MANIP_DPRINT("creating ttl hm, next hm %d index %d\n",
			hm[*hm_index - 1], *hm_index);
	memset(&upd_params, 0, sizeof(struct dpa_cls_hm_update_params));
	upd_params.fm_pcd = fm_pcd;
	if(l3protoIPv4)
		upd_params.op_flags = DPA_CLS_HM_UPDATE_IPv4_UPDATE;
	else
		upd_params.op_flags = DPA_CLS_HM_UPDATE_IPv6_UPDATE;
	upd_params.update.l3.field_flags = 
		DPA_CLS_HM_IP_UPDATE_TTL_HOPL_DECREMENT;
	if (dpa_classif_set_update_hm(&upd_params, hm[*hm_index - 1], 	
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::create ttl update hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created ttl hm %d\n", hm[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}

//routine to create a ipv4 nat hmanip
int create_nat_hm(PCtEntry entry, uint16_t key_flags, void *fm_pcd, uint32_t fm_idx, 
		int *hm, int *hm_index,
		uint32_t head) 
{
	struct dpa_cls_hm_nat_params nat_params;
	PCtEntry twin_entry;
	int i;

	if ( (entry->proto != IPPROTOCOL_TCP) && (entry->proto != IPPROTOCOL_UDP) )
	{
		DPA_ERROR("%s::nat not supported for protocol %d\n",
				__FUNCTION__, entry->proto);
		return FAILURE;
	}

	twin_entry = CT_TWIN(entry);
	MANIP_DPRINT("creating nat hm, fm_pcd %p next hm %d\n",
			fm_pcd, hm[*hm_index - 1]);
	memset(&nat_params, 0, sizeof(struct dpa_cls_hm_nat_params));

	nat_params.fm_pcd = fm_pcd;
	nat_params.type = DPA_CLS_HM_NAT_TYPE_TRADITIONAL;
	nat_params.flags = 0;

	nat_params.proto = (entry->proto == IPPROTOCOL_TCP) ? DPA_CLS_NAT_PROTO_TCP : DPA_CLS_NAT_PROTO_UDP;

	if (key_flags & NAT_HM_REPLACE_SPORT)
	{
		nat_params.sport = PORT_SWAP(twin_entry->Dport);
		nat_params.flags |= DPA_CLS_HM_NAT_UPDATE_SPORT;
		MANIP_DPRINT("sport changed to %d\n", nat_params.sport);
	}
	if (key_flags &  NAT_HM_REPLACE_DPORT)
	{
		nat_params.dport = PORT_SWAP(twin_entry->Sport);
		nat_params.flags |= DPA_CLS_HM_NAT_UPDATE_DPORT;
		MANIP_DPRINT("dport changed to %d\n", nat_params.dport);
	}

	if (key_flags &  NAT_HM_REPLACE_SIP)
	{
		nat_params.flags |= DPA_CLS_HM_NAT_UPDATE_SIP;
		if (IS_IPV6_FLOW(entry))
		{
			nat_params.nat.sip.version = TYPE_IPV6;
			for (i = 0 ; i < 4; i++)
				nat_params.nat.sip.addr.ipv6.word[i] = IPV6ADDR_SWAP(twin_entry->Daddr_v6[i]);
#ifdef MANIP_DEBUG 
			MANIP_DPRINT("sip changed to ");
			display_ipv6_addr(nat_params.nat.sip.addr.ipv6.byte);
#endif
		}
		else
		{
			nat_params.nat.sip.version = TYPE_IP4;
			nat_params.nat.sip.addr.ipv4.word = IPV4ADDR_SWAP(twin_entry->Daddr_v4);
#ifdef MANIP_DEBUG
			MANIP_DPRINT("sip changed to ");
			display_ipv4_addr(nat_params.nat.sip.addr.ipv4.word);
#endif

		}
	}

	if (key_flags &  NAT_HM_REPLACE_DIP)
	{
		nat_params.flags |= DPA_CLS_HM_NAT_UPDATE_DIP;
		if (IS_IPV6_FLOW(entry))
		{
			nat_params.nat.dip.version = TYPE_IPV6;
			for (i = 0 ; i < 4; i++)
				nat_params.nat.dip.addr.ipv6.word[i] = IPV6ADDR_SWAP(twin_entry->Saddr_v6[i]);
#ifdef MANIP_DEBUG
			MANIP_DPRINT("dip changed to ");
			display_ipv6_addr(nat_params.nat.dip.addr.ipv6.byte);
#endif
		}
		else
		{
			nat_params.nat.dip.version = TYPE_IP4;
			nat_params.nat.dip.addr.ipv4.word = IPV4ADDR_SWAP(twin_entry->Saddr_v4);
#ifdef MANIP_DEBUG
			MANIP_DPRINT("dip changed to ");
			display_ipv4_addr(nat_params.nat.dip.addr.ipv4.word);
#endif

		}
	}

	if (key_flags & NAT_HM_NATPT)
	{
		nat_params.type = DPA_CLS_HM_NAT_TYPE_NAT_PT;
		if (IS_IPV6_FLOW(twin_entry))
		{
			nat_params.nat_pt.type = DPA_CLS_HM_NAT_PT_IPv4_TO_IPv6;
			*(unsigned long *)&nat_params.nat_pt.new_header = htonl(0x6FF00000);
			memcpy(&nat_params.nat_pt.new_header.ipv6.ipsa, twin_entry->Daddr_v6, sizeof(nat_params.nat_pt.new_header.ipv6.ipsa));
			memcpy(&nat_params.nat_pt.new_header.ipv6.ipda, twin_entry->Saddr_v6, sizeof(nat_params.nat_pt.new_header.ipv6.ipda));
			MANIP_DPRINT("NAT-PT 4to6, new sip=%pI6c, new dip=%pI6c, nexthdr=%d\n",
					&nat_params.nat_pt.new_header.ipv6.ipsa,
					&nat_params.nat_pt.new_header.ipv6.ipda,
					nat_params.nat_pt.new_header.ipv6.next_hdr);
		}
		else
		{
			nat_params.nat_pt.type = DPA_CLS_HM_NAT_PT_IPv6_TO_IPv4;
			nat_params.nat_pt.new_header.ipv4.header.version = 4;
			nat_params.nat_pt.new_header.ipv4.header.ihl = 5;
			nat_params.nat_pt.new_header.ipv4.header.tos = 0xFF;
			nat_params.nat_pt.new_header.ipv4.header.saddr = twin_entry->Daddr_v4;
			nat_params.nat_pt.new_header.ipv4.header.daddr = twin_entry->Saddr_v4;
			MANIP_DPRINT("NAT-PT 6to4, new sip=%pI4, new dip=%pI4, protocol=%d\n",
					&nat_params.nat_pt.new_header.ipv4.header.saddr,
					&nat_params.nat_pt.new_header.ipv4.header.daddr,
					twin_entry->proto);
		}
	}


	MANIP_DPRINT("nat flags 0x%x\n", nat_params.flags);
	if (dpa_classif_set_nat_hm(&nat_params, hm[*hm_index - 1], 	
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::create nat hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created nat hm %d\n", hm[*hm_index]);
	*hm_index += 1;	
	return SUCCESS;
}

//create pppoe header removal header modification
int create_pppoe_remove_hm(void *pcd_handle, int *hm, int *hm_index, 
		int head)
{
	struct dpa_cls_hm_remove_params params;

	MANIP_DPRINT("creating pppoe hdr remove hm, index %d, next hm %d\n",
			*hm_index, hm[*hm_index - 1]);

	//create HMC to strip pppoe headers in the ingress packet
	memset(&params, 0, sizeof(struct dpa_cls_hm_remove_params));	
	params.type = DPA_CLS_HM_REMOVE_PPPoE;
	params.fm_pcd = pcd_handle;
	if (dpa_classif_set_remove_hm(&params, hm[*hm_index - 1],
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::remove pppoe hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created pppoe hdr rm  hm %d\n", hm[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}

//create pppoe header insert header modification
int create_pppoe_insert_hm(void *pcd_handle, int *hm, int *hm_index,
		int head, uint16_t session_id)
{
	struct dpa_cls_hm_insert_params params;

	MANIP_DPRINT("creating pppoe hdr insert hm, index %d, next hm %d\n",
			*hm_index, hm[*hm_index - 1]);

	//create HMC to add pppoe headers in the egress packet
	memset(&params, 0, sizeof(struct dpa_cls_hm_insert_params));
	params.type = DPA_CLS_HM_INSERT_PPPoE;
	params.fm_pcd = pcd_handle;
	params.pppoe_header.version = 1;
	params.pppoe_header.type = 1;
	params.pppoe_header.sid = htons(session_id);
	if (dpa_classif_set_insert_hm(&params, hm[*hm_index - 1],
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::insert pppoe hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created pppoe hdr insert hm %d\n", hm[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}


int create_ethernet_insert_hm(void *pcd_handle, int *hm, int *hm_index,
		int head, int ethertype, struct dpa_l2hdr_info *l2_info)
{
  struct dpa_cls_hm_insert_params params;

  if (l2_info->num_egress_vlan_hdrs) 
  {
    struct dpa_cls_hm_vlan_params vlan_params;	
    uint32_t ii;

    MANIP_DPRINT("adding Vlan hdrs in pkt, curr hm_index %d, next hm %d\n",
				*hm_index, hm[*hm_index - 1]);
    memset(&vlan_params, 0,sizeof(struct dpa_cls_hm_vlan_params));
    vlan_params.type = DPA_CLS_HM_VLAN_EGRESS;
    vlan_params.egress.update_op = DPA_CLS_HM_VLAN_UPDATE_NONE; 	
    vlan_params.egress.num_tags = l2_info->num_egress_vlan_hdrs;
    for (ii = 0; ii < vlan_params.egress.num_tags; ii++)
    {
      vlan_params.egress.qtag[ii].tpid = 
 		htons(l2_info->egress_vlan_hdrs[ii].tpid);
      vlan_params.egress.qtag[ii].tci = 
		htons(l2_info->egress_vlan_hdrs[ii].tci);
    }
    vlan_params.fm_pcd = pcd_handle;	
    MANIP_DPRINT("inserting %d Vlan hdrs in egress pkt\n",
				l2_info->num_egress_vlan_hdrs);
    MANIP_DPRINT("Number of vlans =  %d \r\n",
				vlan_params.egress.num_tags);
    if (dpa_classif_set_vlan_hm(&vlan_params,
					hm[*hm_index - 1],
					&hm[*hm_index], 0, NULL))
    {
      DPA_ERROR("%s::unable to add vlan ins manip\n",__FUNCTION__);
      return FAILURE;
    }
    *hm_index += 1;
    MANIP_DPRINT("created ins vlan hm handle %d\n", hm[*hm_index - 1]);
  }


	MANIP_DPRINT("creating ethernet hdr insert hm, index %d, next hm %d\n",
			*hm_index, hm[*hm_index - 1]);

	memset(&params, 0, sizeof(struct dpa_cls_hm_insert_params));
	params.type = DPA_CLS_HM_INSERT_ETHERNET;
	memcpy(params.eth.eth_header.h_dest, l2_info->l2hdr, ETHER_ADDR_LEN);
	memcpy(params.eth.eth_header.h_source, &l2_info->l2hdr[ETHER_ADDR_LEN], ETHER_ADDR_LEN);
	params.eth.eth_header.h_proto = ethertype; 
	params.fm_pcd = pcd_handle;

	if (dpa_classif_set_insert_hm(&params, hm[*hm_index - 1],
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::insert ethernet hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created ethernet hdr insert hm %d\n", hm[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}



int create_ethernet_remove_hm(void *pcd_handle, int *hm, int *hm_index, 
		int head)
{
	struct dpa_cls_hm_remove_params params;

	MANIP_DPRINT("creating ethernet hdr remove hm, index %d, next hm %d\n",
			*hm_index, hm[*hm_index - 1]);

	memset(&params, 0, sizeof(struct dpa_cls_hm_remove_params));	
	params.type = DPA_CLS_HM_REMOVE_ETHERNET;
	params.fm_pcd = pcd_handle;
	if (dpa_classif_set_remove_hm(&params, hm[*hm_index - 1],
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::remove ethernet hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created ethernet hdr rm  hm %d\n", hm[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}

//create tunnel header insert header modification
int create_tunnel_insert_hm(void *pcd_handle, int *hm, int *hm_index,
		int head, struct dpa_l3hdr_info *l3info )
{
	struct dpa_cls_hm_insert_params params;

	MANIP_DPRINT("creating tunnel hdr insert hm, index %d, next hm %d\n",
			*hm_index, hm[*hm_index - 1]);

	memset(&params, 0, sizeof(struct dpa_cls_hm_insert_params));
	if(l3info->mode == TNL_MODE_4O6)
	{
		params.type = DPA_CLS_HM_INSERT_TUNNEL4o6;
		memcpy( &params.tnl_ipv6_header, &l3info->header_v6, l3info->header_size);
	}
	else
	{
		params.type = DPA_CLS_HM_INSERT_TUNNEL6o4;
		memcpy( &params.tnl_ipv4_header, &l3info->header_v4, l3info->header_size);
	}
	params.fm_pcd = pcd_handle;

	if (dpa_classif_set_insert_hm(&params, hm[*hm_index - 1],
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::insert tunnel hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created tunnel hdr insert hm %d\n", hm[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}


//create tunnel header removal header modification
int create_tunnel_remove_hm(void *pcd_handle, int *hm, int *hm_index, 
		int head, struct dpa_l3hdr_info *l3info)
{
	struct dpa_cls_hm_remove_params params;

	MANIP_DPRINT("creating tunnel hdr remove hm, index %d, next hm %d\n",
			*hm_index, hm[*hm_index - 1]);

	memset(&params, 0, sizeof(struct dpa_cls_hm_remove_params));	
	if(l3info->mode == TNL_MODE_4O6)
		params.type = DPA_CLS_HM_REMOVE_TUNNEL4o6;
	else
		params.type = DPA_CLS_HM_REMOVE_TUNNEL6o4;

	params.fm_pcd = pcd_handle;
	if (dpa_classif_set_remove_hm(&params, hm[*hm_index - 1],
				&hm[*hm_index], head, NULL)) {
		DPA_ERROR("%s::remove tunnel hm failed\n", __FUNCTION__);
		return FAILURE;
	}
	MANIP_DPRINT("created tunnel hdr rm  hm %d\n", hm[*hm_index]);
	*hm_index += 1;
	return SUCCESS;
}

//create vlan header removal header modification
int create_vlan_remove_hm(void *pcd_handle, int *hm, int *hm_index, 
		int head)
{
	//strip vlan headers in the ingress packet
        struct dpa_cls_hm_vlan_params vlan_params;

        MANIP_DPRINT("creating vlan hdr remove hm, index %d, next hm %d\n",
			*hm_index, hm[*hm_index - 1]);
        //remove all vlan tags in the incoming packet
        memset(&vlan_params, 0, sizeof(struct dpa_cls_hm_vlan_params));
        vlan_params.type = DPA_CLS_HM_VLAN_INGRESS;
        vlan_params.ingress.num_tags = DPA_CLS_HM_VLAN_CNT_ALL_QTAGS;
        vlan_params.fm_pcd = pcd_handle;
        if (dpa_classif_set_vlan_hm(&vlan_params,
        	hm[*hm_index - 1], &hm[(*hm_index)], head, NULL)) {
        	DPA_ERROR("%s::unable to add vlan rmv manip\n",
        		__FUNCTION__);
        	return FAILURE;
        }
        MANIP_DPRINT("vlan hdr strip hm %d\n", hm[(*hm_index)]);
        *hm_index += 1;
	return SUCCESS;
}

int create_sa_entry_hm_chain( PRouteEntry pRtEntry , 
		struct ins_entry_info *info, uint32_t sa_dir_in ,
			 struct hw_ct *ct )
{
	struct hm_chain_info *hm_info;
	uint32_t poolid;
	uint32_t ii, rebuild_l2_hdr = 0 ;
	uint16_t ethertype = 0;



	ct->hm_info = NULL;
	info->action.enq_params.hmd = DPA_OFFLD_DESC_NONE;
	return SUCCESS;
	
	hm_info = kzalloc(sizeof(struct hm_chain_info), 0);
	if (!hm_info)
		return FAILURE;
	if(sa_dir_in)
	{
	/* to_sec_fqid will be non zero for inpound ipsec traffic connection
	*  in this case we just need to remove vlan header, pppoe and  tunnel
	*  interface headers if present.  
	*/
		//strip vlan on ingress if incoming iface is vlan
		if (info->l2_info.vlan_present)
			hm_info->key.flags |= VLAN_STRIP_HM_VALID;
		//strip pppoe on ingress if incoming iface is pppoe 
		if (info->l2_info.pppoe_present)
			hm_info->key.flags |= PPPoE_STRIP_HM_VALID;

	} else {
		if (!pRtEntry )
			return FAILURE;
        
		//routing and ttl decr are mandatory
		// (ttl decr handled as part of NAT-PT)
	
		hm_info->key.flags = ETHERNET_HM_VALID;
		hm_info->key.flags |= TTL_HM_VALID;
		if (info->l2_info.num_egress_vlan_hdrs ) {

			hm_info->key.flags |= VLAN_ADD_HM_VALID;
			for(ii = 0;ii < info->l2_info.num_egress_vlan_hdrs;ii++)
			{
				hm_info->key.vlan_ids[ii] =
				   (info->l2_info.egress_vlan_hdrs[ii].tci);
			}	
		}		
		//copy l2hdr
		memcpy(&hm_info->key.l2_hdr[0], &info->l2_info.l2hdr[0], 
				(ETHER_ADDR_LEN * 2));

	}

	if(L3_HDR_OPS(info->l3_info))
	{
	/*  Addition of IP header requires the header to be inserted at 
	* the start of the packet. So we need to strip and rebuild the 
	* l2 header after tunnel header insertion. */
		rebuild_l2_hdr = 1;
		if(info->l3_info.add_tnl_header)
			ethertype = (info->l3_info.proto == PROTO_IPV4) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
		if(info->l3_info.tnl_header_present)
			ethertype = (info->l3_info.proto == PROTO_IPV4) ? htons(ETHERTYPE_IPV6) : htons(ETHERTYPE_IPV4);
		if(info->l2_info.add_pppoe_hdr)
			ethertype = htons(ETHERTYPE_PPPOE);
		if(info->l2_info.num_egress_vlan_hdrs)
			ethertype = htons(ETHERTYPE_VLAN);

	printk(KERN_INFO"Ethertype is %x", ethertype);
	}
	spin_lock(&hm_db_lock);
#ifdef MANIP_DEBUG
	MANIP_DPRINT("hm hash key ::\n");
	display_buf(&hm_info->key, sizeof(struct hm_hash_key));
#endif
	hm_info = find_entry_in_hm_hash_table(hm_info);
	if (hm_info->hm_chain_head != DPA_OFFLD_DESC_NONE) {
		MANIP_DPRINT("re using hm chain id %d\n", hm_info->hm_chain_head);
		ct->hm_info = hm_info;
		info->action.enq_params.hmd = hm_info->hm_chain_head;
		spin_unlock(&hm_db_lock);
		return SUCCESS;
	}
	MANIP_DPRINT("creating new hm chain\n");
	//hm chain does not exist, create one
	//FIXME
	poolid = 0;
	//clear all hm desc
	for (ii = 0; ii < MAX_HM; ii++)
		info->hm[ii] = DPA_OFFLD_DESC_NONE;
	info->hm_index = 1;

	//Add L2 header	
	if(!sa_dir_in ){
		if(create_ethernet_insert_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 0, ethertype, &info->l2_info)){
			DPA_ERROR("%s::failed to create insert L2 HM\n",
					__FUNCTION__);
			goto err_ret;
		}	
		//deal with pppoe header insertion
		if (info->l2_info.add_pppoe_hdr) {
			if (create_pppoe_insert_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 0, 
					info->l2_info.pppoe_sess_id)) {
				DPA_ERROR("%s::failed to create pppoe insert HM\n",
					__FUNCTION__);
				goto err_ret;
			}
		}
		if (info->l3_info.add_tnl_header) {
			if (create_tunnel_insert_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 0, 
					&info->l3_info)) {
				DPA_ERROR("%s::failed to create tunnel insert HM\n",
					__FUNCTION__);
				goto err_ret;
			}
		}
		//hmd for ttl decrement
		if (hm_info->key.flags & TTL_HM_VALID)	{
			if (create_ttl_hm(info->fm_pcd, info->fm_idx,
					&info->hm[0], &info->hm_index, 0, 
					1)) {
				DPA_ERROR("%s::failed to create ttl decr HM\n",
					__FUNCTION__);
				goto err_ret;
			}
		}
	//hmd for routing, first in the chain
	//create routing hm
		if (create_routing_hm(info->fm_pcd, info->fm_idx,
					&info->l2_info,
					pRtEntry->mtu, poolid,
					&info->hm[0],
					&info->hm_index, 1)) {
			DPA_ERROR("%s::failed to create routing HM\n",
					__FUNCTION__);
			goto err_ret;
		}

	}else {

		if (info->l3_info.tnl_header_present) {
			if (create_tunnel_remove_hm(info->fm_pcd, &info->hm[0], 
					&info->hm_index, 0, &info->l3_info)) {
				DPA_ERROR("%s::unable to add tunnel rmv manip\n",
					__FUNCTION__);
				goto err_ret;
			}
		}


		if (info->l2_info.vlan_present) {
		//strip vlan headers in the ingress packet
			if (create_vlan_remove_hm(info->fm_pcd, &info->hm[0], 
					&info->hm_index, 0)) {
				DPA_ERROR("%s::unable to add vlan rmv manip\n",
					__FUNCTION__);
				goto err_ret;
			}
		}
		if (info->l2_info.pppoe_present) {
		//strip pppoe headers in the ingress packet
			if (create_pppoe_remove_hm(info->fm_pcd, &info->hm[0], 
					&info->hm_index, 0)) {
				DPA_ERROR("%s::unable to add pppoe rmv manip\n",
					__FUNCTION__);
				goto err_ret;
			}
		}  

		//Strip L2 header	
#if 0
		printk(KERN_INFO"create_ethernet_remove_hm");
		if(create_ethernet_remove_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 1)){
			DPA_ERROR("%s::failed to create strip L2 HM\n",
					__FUNCTION__);
			goto err_ret;
		}	
#endif
	}
	ct->hm_info = hm_info;
	hm_info->hm_chain_head = info->hm[info->hm_index - 1];
	MANIP_DPRINT("new hm chain created, head %d\n", hm_info->hm_chain_head);
	info->action.enq_params.hmd = hm_info->hm_chain_head;
	//add hm_info to hash table and release lock	
	add_entry_to_hm_hash_table(hm_info);
	spin_unlock(&hm_db_lock);
	return SUCCESS;
err_ret:
	spin_unlock(&hm_db_lock);
	//free hm_info
	kfree(hm_info);
	//free all hms
	for (ii = 0; ii < MAX_HM; ii++) {
		if (info->hm[ii] != DPA_OFFLD_DESC_NONE) {
			if (dpa_classif_free_hm(info->hm[ii])) {
				DPA_ERROR("%s::failed to delete HM %d\n",
						__FUNCTION__, info->hm[ii]);
			}
		}
	}
	return FAILURE;
}


int create_hm_chain(PCtEntry entry, struct ins_entry_info *info)
{
	struct hm_chain_info *hm_info;
	PCtEntry twin_entry;
	uint32_t poolid;
	uint32_t ii, rebuild_l2_hdr = 0 ;
	uint16_t ethertype = 0;


	twin_entry = CT_TWIN(entry);

	entry->ct->hm_info = NULL;
	
	hm_info = kzalloc(sizeof(struct hm_chain_info), 0);
	if (!hm_info)
		return FAILURE;

	//routing and ttl decr are mandatory
	// (ttl decr handled as part of NAT-PT)

	hm_info->key.flags = ETHERNET_HM_VALID;
	if (!IS_NATPT(entry))
		hm_info->key.flags |= TTL_HM_VALID;

	//strip vlan on ingress if incoming iface is vlan
	if (info->l2_info.vlan_present)
		hm_info->key.flags |= VLAN_STRIP_HM_VALID;

	//strip pppoe on ingress if incoming iface is pppoe 
	if (info->l2_info.pppoe_present)
		hm_info->key.flags |= PPPoE_STRIP_HM_VALID;


	if((L3_HDR_OPS(info->l3_info)) ||entry->status &  CONNTRACK_SEC )
	/*  Addition of IP header requires the header to be inserted at the start of the packet.
	    So we need to strip and rebuild the l2 header after tunnel header insertion. */
	{
		rebuild_l2_hdr = 1;
		if(info->l3_info.add_tnl_header)
			ethertype = (info->l3_info.proto == PROTO_IPV4) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
		if(info->l3_info.tnl_header_present)
			ethertype = (info->l3_info.proto == PROTO_IPV4) ? htons(ETHERTYPE_IPV6) : htons(ETHERTYPE_IPV4);
              
                if(entry->status &  CONNTRACK_SEC)
		{
                /* After IPSec processing the outer ipheader will depend on SA family. During Sec processing we
                 * just copy the ethernet header from the input packet to output packet. So When this flow has outbound SA
                 *  we need to put the ethernet type based on SA family 
                 */
	 		if(info->to_sec_fqid) 
				ethertype = (info->sa_family == PROTO_IPV4) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
                	else 
				ethertype = (IS_IPV4(entry)) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
                }
		if(info->l2_info.add_pppoe_hdr)
			ethertype = htons(ETHERTYPE_PPPOE);
		if(info->l2_info.num_egress_vlan_hdrs)
			ethertype = htons(ETHERTYPE_VLAN);

	}

	//perform NAT where required
	if (IS_NATPT(entry))
	{
		hm_info->key.flags |= NAT_HM_NATPT;
		hm_info->key.nat_sport = twin_entry->Dport;
		hm_info->key.nat_dport = twin_entry->Sport;
		hm_info->key.flags |= NAT_HM_REPLACE_SPORT;
		hm_info->key.flags |= NAT_HM_REPLACE_DPORT;
		if (IS_IPV6_FLOW(twin_entry))
		{
			memcpy(hm_info->key.v6.nat_sip, twin_entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
			memcpy(hm_info->key.v6.nat_dip, twin_entry->Saddr_v6, IPV6_ADDRESS_LENGTH);
		}
		else
		{
			hm_info->key.v4.nat_sip = entry->twin_Daddr;
			hm_info->key.v4.nat_dip = entry->twin_Saddr;
		}
	}
	else if (IS_IPV4_NAT(entry) || IS_IPV6_NAT(entry))
	{
		switch(entry->proto) {
			case IPPROTOCOL_TCP:
			case IPPROTOCOL_UDP:
				if (entry->Sport != twin_entry->Dport) {
					hm_info->key.flags |= NAT_HM_REPLACE_SPORT;
					hm_info->key.nat_sport = (twin_entry->Dport);
				}
				if (entry->Dport != twin_entry->Sport) {
					hm_info->key.flags |= NAT_HM_REPLACE_DPORT;
					hm_info->key.nat_dport = (twin_entry->Dport);
				}
				break;
			default:
				break; 
		}
		//check if ip replacement have to be done
		//nat sip if required

		if (IS_IPV6(entry))
		{
			if (entry->status & CONNTRACK_SNAT)
			{
				memcpy(hm_info->key.v6.nat_sip, twin_entry->Daddr_v6 ,IPV6_ADDRESS_LENGTH);
				hm_info->key.flags |= NAT_HM_REPLACE_SIP;
			}
			if (entry->status & CONNTRACK_DNAT)
			{
				memcpy(hm_info->key.v6.nat_dip, twin_entry->Saddr_v6 ,IPV6_ADDRESS_LENGTH);
				hm_info->key.flags |= NAT_HM_REPLACE_DIP;

			}

		}
		else 
		{
			if (entry->Saddr_v4 != entry->twin_Daddr) {
				hm_info->key.v4.nat_sip = (entry->twin_Daddr);
				hm_info->key.flags |= NAT_HM_REPLACE_SIP;
			}
			//nat dip if required
			if (entry->Daddr_v4 != entry->twin_Saddr) {
				hm_info->key.v4.nat_dip = (entry->twin_Saddr);
				hm_info->key.flags |= NAT_HM_REPLACE_DIP;
			}
		}
	}
	if (info->l2_info.num_egress_vlan_hdrs) {

		hm_info->key.flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			hm_info->key.vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}

	//copy l2hdr
	memcpy(&hm_info->key.l2_hdr[0], &info->l2_info.l2hdr[0], (ETHER_ADDR_LEN * 2));
#ifdef MANIP_DEBUG
	display_buff_data(&info->l2_info.l2hdr[0], (ETHER_ADDR_LEN * 2));	
#endif
	spin_lock(&hm_db_lock);
#ifdef MANIP_DEBUG
	MANIP_DPRINT("hm hash key ::\n");
	display_buf(&hm_info->key, sizeof(struct hm_hash_key));
#endif
	hm_info = find_entry_in_hm_hash_table(hm_info);
	if (hm_info->hm_chain_head != DPA_OFFLD_DESC_NONE) {
		MANIP_DPRINT("re using hm chain id %d\n", hm_info->hm_chain_head);
		entry->ct->hm_info = hm_info;
		info->action.enq_params.hmd = hm_info->hm_chain_head;
		spin_unlock(&hm_db_lock);
		return SUCCESS;
	}
	MANIP_DPRINT("creating new hm chain\n");
	//hm chain does not exist, create one
	//FIXME
	poolid = 0;
	//clear all hm desc
	for (ii = 0; ii < MAX_HM; ii++)
		info->hm[ii] = DPA_OFFLD_DESC_NONE;
	info->hm_index = 1;

	 //if((!info->to_sec_fqid)) 
	 {
		//Add L2 header	
		if(rebuild_l2_hdr){
			if(create_ethernet_insert_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 0, ethertype, &info->l2_info)){
				DPA_ERROR("%s::failed to create insert L2 HM\n",
					__FUNCTION__);
				goto err_ret;
			}	
		}	
		//deal with pppoe header insertion
		if (info->l2_info.add_pppoe_hdr) {
			if (create_pppoe_insert_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 0, 
					info->l2_info.pppoe_sess_id)) {
				DPA_ERROR("%s::failed to create pppoe insert HM\n",
					__FUNCTION__);
				goto err_ret;
			}
		}
	}
	if (info->l3_info.add_tnl_header) {
		if (create_tunnel_insert_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 0, 
					&info->l3_info)) {
			DPA_ERROR("%s::failed to create tunnel insert HM\n",
					__FUNCTION__);
			goto err_ret;
		}
	}

	//deal with nat ops 
	if (hm_info->key.flags & NAT_HM_VALID){
		//needs nat, create nat hm
		if(create_nat_hm(entry, hm_info->key.flags, info->fm_pcd, 
					info->fm_idx,
					&info->hm[0],
					&info->hm_index, 0)) {
			DPA_ERROR("%s::failed to create nat HM\n",
					__FUNCTION__);
			goto err_ret;
		}
	}

	//hmd for ttl decrement
	if (hm_info->key.flags & TTL_HM_VALID)	{
		if (create_ttl_hm(info->fm_pcd, info->fm_idx,
					&info->hm[0], &info->hm_index, 0, IS_IPV4(entry))) {
			DPA_ERROR("%s::failed to create ttl decr HM\n",
					__FUNCTION__);
			goto err_ret;
		}
	}


	if (info->l3_info.tnl_header_present) {
		if (create_tunnel_remove_hm(info->fm_pcd, &info->hm[0], 
					&info->hm_index, 0, &info->l3_info)) {
			DPA_ERROR("%s::unable to add tunnel rmv manip\n",
					__FUNCTION__);
			goto err_ret;
		}
	}


	if ((!rebuild_l2_hdr) && (info->l2_info.vlan_present)) {
		//strip vlan headers in the ingress packet
		if (create_vlan_remove_hm(info->fm_pcd, &info->hm[0], 
					&info->hm_index, 0)) {
			DPA_ERROR("%s::unable to add vlan rmv manip\n",
					__FUNCTION__);
			goto err_ret;
		}
	}
	if (info->l2_info.pppoe_present) {
		//strip pppoe headers in the ingress packet
		if (create_pppoe_remove_hm(info->fm_pcd, &info->hm[0], 
					&info->hm_index, 0)) {
			DPA_ERROR("%s::unable to add pppoe rmv manip\n",
					__FUNCTION__);
			goto err_ret;
		}
	}  

	if(rebuild_l2_hdr) {
	//Strip L2 header	
		if(create_ethernet_remove_hm(info->fm_pcd, &info->hm[0],
					&info->hm_index, 1)){
			DPA_ERROR("%s::failed to create strip L2 HM\n",
					__FUNCTION__);
			goto err_ret;
		}	
	}
	else {
	//hmd for routing, first in the chain
	//create routing hm
	//	if((!info->to_sec_fqid)) 
		{
			if (create_routing_hm(info->fm_pcd, info->fm_idx,
					&info->l2_info,
					entry->pRtEntry->mtu, poolid,
					&info->hm[0],
					&info->hm_index, 1)) {
				DPA_ERROR("%s::failed to create routing HM\n",
					__FUNCTION__);
				goto err_ret;
			}	
		}
	}

	entry->ct->hm_info = hm_info;
	hm_info->hm_chain_head = info->hm[info->hm_index - 1];
	MANIP_DPRINT("new hm chain created, head %d\n", hm_info->hm_chain_head);
	info->action.enq_params.hmd = hm_info->hm_chain_head;

	//add hm_info to hash table and release lock	
	add_entry_to_hm_hash_table(hm_info);
	spin_unlock(&hm_db_lock);
	return SUCCESS;
err_ret:
	spin_unlock(&hm_db_lock);
	//free hm_info
	kfree(hm_info);
	//free all hms
	for (ii = 0; ii < MAX_HM; ii++) {
		if (info->hm[ii] != DPA_OFFLD_DESC_NONE) {
			if (dpa_classif_free_hm(info->hm[ii])) {
				DPA_ERROR("%s::failed to delete HM %d\n",
						__FUNCTION__, info->hm[ii]);
			}
		}
	}
	return FAILURE;
}

int create_hm_chain_for_mcast_entry(PCtEntry entry, struct ins_entry_info *info)
{
	struct hm_chain_info *hm_info;
        uint32_t ii;


	entry->ct->hm_info = NULL;
	//create infor for searching hm table
	hm_info = kzalloc(sizeof(struct hm_chain_info), 0);
	if (!hm_info)
		return FAILURE;

	//routing and ttl decr are mandatory
	// (ttl decr handled as part of NAT-PT)
	hm_info->key.flags = ETHERNET_HM_VALID;
        hm_info->key.flags |= TTL_HM_VALID;

	//strip vlan on ingress if incoming iface is vlan
	if (info->l2_info.vlan_present)
        {
		hm_info->key.flags |= VLAN_STRIP_HM_VALID;
        }

	//strip pppoe on ingress if incoming iface is pppoe 
	if (info->l2_info.pppoe_present)
		hm_info->key.flags |= PPPoE_STRIP_HM_VALID;

	//copy l2hdr
	memcpy(&hm_info->key.l2_hdr[0], &info->l2_info.l2hdr[0], (ETHER_ADDR_LEN * 2));
	spin_lock(&hm_db_lock);
#ifdef MANIP_DEBUG
	MANIP_DPRINT("hm hash key ::\n");
	display_buf(&hm_info->key, sizeof(struct hm_hash_key));
#endif
	hm_info = find_entry_in_hm_hash_table(hm_info);
	if (hm_info->hm_chain_head != DPA_OFFLD_DESC_NONE) {
		MANIP_DPRINT("re using hm chain id %d\n", hm_info->hm_chain_head);
		entry->ct->hm_info = hm_info;
		info->action.mcast_params.hmd = hm_info->hm_chain_head;
		spin_unlock(&hm_db_lock);
		return SUCCESS;
	}
	MANIP_DPRINT("creating new hm chain\n");
	//hm chain does not exist, create one

        //clear all hm desc
        for (ii = 0; ii < MAX_HM; ii++)
                info->hm[ii] = DPA_OFFLD_DESC_NONE;
        info->hm_index = 1;

	if (info->l2_info.vlan_present) {
        	//strip vlan headers in the ingress packet
		if (create_vlan_remove_hm(info->fm_pcd, &info->hm[0], 
				&info->hm_index, 0)) {
                  	DPA_ERROR("%s::unable to add vlan rmv manip\n",
                                __FUNCTION__);
                	goto err_ret;
		}
	}
	if (info->l2_info.pppoe_present) {
        	//strip pppoe headers in the ingress packet
		if (create_pppoe_remove_hm(info->fm_pcd, &info->hm[0], 
				&info->hm_index, 0)) {
                  	DPA_ERROR("%s::unable to add pppoe rmv manip\n",
                                __FUNCTION__);
                	goto err_ret;
		}
        }  
        //hmd for ttl decrement
	if (hm_info->key.flags & TTL_HM_VALID)
	{
		if (create_ttl_hm(info->fm_pcd, info->fm_idx,
			&info->hm[0], &info->hm_index, 1,IS_IPV4(entry))) {
			DPA_ERROR("%s::failed to create ttl decr HM\n",
					__FUNCTION__);
			goto err_ret;
		}
	}

	entry->ct->hm_info = hm_info;
	hm_info->hm_chain_head = info->hm[info->hm_index - 1];
	MANIP_DPRINT("new hm chain created, head %d\n", hm_info->hm_chain_head);
	info->action.mcast_params.hmd = hm_info->hm_chain_head;
	//add hm_info to hash table and release lock	
	add_entry_to_hm_hash_table(hm_info);
	spin_unlock(&hm_db_lock);
	return SUCCESS;
err_ret:
	spin_unlock(&hm_db_lock);
	//free hm_info
	kfree(hm_info);
	//free all hms
        for (ii = 0; ii < MAX_HM; ii++) {
		if (info->hm[ii] != DPA_OFFLD_DESC_NONE) {
			if (dpa_classif_free_hm(info->hm[ii])) {
				DPA_ERROR("%s::failed to delete HM %d\n",
                                __FUNCTION__, info->hm[ii]);
			}
		}
	}
	return FAILURE;
}

int create_hm_chain_for_mcast_member(RouteEntry *pRtEntry, struct ins_entry_info
       *pInsEntry, struct hm_chain_info **pphm_info, int mtu, 
       char *pInIface, int bIsFirstMem, int bIsIPv6)
{
  int ii, poolid;
  struct hm_chain_info *hm_info;
  POnifDesc onif_desc;
  RouteEntry rtEntry;
  struct dpa_l2hdr_info l2hdr;
  struct dpa_l3hdr_info l3hdr;
  uint16_t ethertype;

  hm_info = kzalloc(sizeof(struct hm_chain_info), 0);
  if (!hm_info)
  {
    DPA_ERROR("%s::%d memory allocation for hm info failed \r\n", __FUNCTION__, __LINE__);
    return FAILURE;
  }
 
  if(bIsFirstMem)
  {
    hm_info->key.flags |= TTL_HM_VALID;
  }

  memset(&rtEntry,0, sizeof(RouteEntry));
  onif_desc = get_onif_by_name(pInIface); 
  if (!onif_desc)
  {
    DPA_ERROR("%s::unable to get onif for iface %s\n",__FUNCTION__, pInIface);
    kfree(hm_info);
    return FAILURE;
  }

  rtEntry.itf = onif_desc->itf;
  rtEntry.input_itf = onif_desc->itf;

  //Using default queue for multicast packets
  if (dpa_get_tx_info_by_itf(&rtEntry, &l2hdr, &l3hdr, NULL, 1))
  {
    DPA_ERROR("%s::unable to get tx params\n",__FUNCTION__);
    kfree(hm_info);
    return FAILURE;
  }

  if (l2hdr.vlan_present)
  {
    hm_info->key.flags |= VLAN_STRIP_HM_VALID;
  }

  //strip pppoe on ingress if incoming iface is pppoe 
  if (l2hdr.pppoe_present)
    hm_info->key.flags |= PPPoE_STRIP_HM_VALID;

  /** vlan headers for egress port , need this data for adding vlan header hm node */
  if (pInsEntry->l2_info.num_egress_vlan_hdrs) 
  {
    hm_info->key.flags |= VLAN_ADD_HM_VALID;
    for (ii = 0; ii < pInsEntry->l2_info.num_egress_vlan_hdrs; ii++)
    {
      hm_info->key.vlan_ids[ii] = (pInsEntry->l2_info.egress_vlan_hdrs[ii].tci);
    }
  }
  /** vlan headers for egress port , need this data for adding vlan header hm node */

  /** Copy source mac address into egress packet **/
  memcpy(&hm_info->key.l2_hdr[0], &pInsEntry->l2_info.l2hdr[0], (ETHER_ADDR_LEN * 2));


  /*** Reuse HM chain if we have already created it*/
  spin_lock(&hm_db_lock);
  hm_info = find_entry_in_hm_hash_table(hm_info);
  if (hm_info->hm_chain_head != DPA_OFFLD_DESC_NONE)
  {
    MANIP_DPRINT("re using hm chain id %d\n", hm_info->hm_chain_head);
    pInsEntry->action.enq_params.hmd = hm_info->hm_chain_head;
    spin_unlock(&hm_db_lock);
    return SUCCESS;
  }

  MANIP_DPRINT("creating new hm chain\n");
  //hm chain does not exist, create one
  poolid = 0;
  
  //clear all hm desc
  for (ii = 0; ii < MAX_HM; ii++)
  {
    pInsEntry->hm[ii] = DPA_OFFLD_DESC_NONE;
  }
  pInsEntry->hm_index = 1;

  if(bIsIPv6)
  {
    ethertype = htons(ETHERTYPE_IPV6);
  }
  else
  {
    ethertype = htons(ETHERTYPE_IPV4);
  }
 
  //TODO: Should see if ethertype should be set 
  //  for PPPoE header or will it copy from previous header.
  // as VLAN, after ucode fix for insertion of PPPoE header.
  if (pInsEntry->l2_info.add_pppoe_hdr)
  {
    ethertype = htons(ETHERTYPE_PPPOE);
  }

  if(create_ethernet_insert_hm(pInsEntry->fm_pcd, &pInsEntry->hm[0],
		&pInsEntry->hm_index, 0, ethertype, &pInsEntry->l2_info))
  {
    DPA_ERROR("%s::failed to create insert L2 HM\n",__FUNCTION__);
    goto err_ret;
  }	

  //deal with pppoe header insertion
  if (pInsEntry->l2_info.add_pppoe_hdr)
  {
    if (create_pppoe_insert_hm(pInsEntry->fm_pcd, &pInsEntry->hm[0],
                                &pInsEntry->hm_index, 0, 
				pInsEntry->l2_info.pppoe_sess_id)) 
    {
      DPA_ERROR("%s::failed to create pppoe insert HM\n",__FUNCTION__);
      goto err_ret;
    }
  }

  if(hm_info->key.flags & TTL_HM_VALID)
  {
    if (create_ttl_hm(pInsEntry->fm_pcd, pInsEntry->fm_idx,
	&pInsEntry->hm[0], &pInsEntry->hm_index, 0,!bIsIPv6))
    {
      DPA_ERROR("%s::failed to create ttl decr HM\n",__FUNCTION__);
      goto err_ret;
    }
  }

  if (hm_info->key.flags & PPPoE_STRIP_HM_VALID)
  {
    //strip pppoe headers in the ingress packet
    if (create_pppoe_remove_hm(pInsEntry->fm_pcd, &pInsEntry->hm[0], &pInsEntry->hm_index, 0))
    {
      DPA_ERROR("%s::unable to add pppoe rmv manip\n",__FUNCTION__);
      goto err_ret;
    }
  }  

   //Strip L2 header	
   if(create_ethernet_remove_hm(pInsEntry->fm_pcd, &pInsEntry->hm[0],
                     			&pInsEntry->hm_index, 1))
   {
     DPA_ERROR("%s::failed to create strip L2 HM\n",
					__FUNCTION__);
     goto err_ret;
   }	

  hm_info->hm_chain_head = pInsEntry->hm[pInsEntry->hm_index - 1];
  MANIP_DPRINT("new hm chain created, head %d\n", hm_info->hm_chain_head);
  
  pInsEntry->action.enq_params.hmd = hm_info->hm_chain_head; 
  //add hm_info to hash table and release lock	
  add_entry_to_hm_hash_table(hm_info);
  spin_unlock(&hm_db_lock);
  *pphm_info = hm_info;
  return SUCCESS;

err_ret:
        spin_unlock(&hm_db_lock);
	//free hm_info
	kfree(hm_info);
	//free all hms
        for (ii = 0; ii < MAX_HM; ii++)
	{
	  if (pInsEntry->hm[ii] != DPA_OFFLD_DESC_NONE)
          {
	    if (dpa_classif_free_hm(pInsEntry->hm[ii]))
            {
	      DPA_ERROR("%s::failed to delete HM %d\n",__FUNCTION__, pInsEntry->hm[ii]);
            }
	  }
	}
	return FAILURE;
}
#endif
