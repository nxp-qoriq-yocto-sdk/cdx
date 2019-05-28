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
 * @file                cdx_ehash.c     
 * @description         cdx DPAA external hash functions
 */             
#ifdef USE_ENHANCED_EHASH
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include "linux/netdevice.h"
#include "portdefs.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "misc.h"
#include "types.h"
#include "cdx.h"
#include "cdx_common.h"
#include "list.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_ipsec.h"
#include "control_tunnel.h"
#include "control_bridge.h"
#include "fm_ehash.h"
#include "dpa_control_mc.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "module_rtp_relay.h"

//#define CDX_DPA_DEBUG 1

#ifdef CDX_DPA_DEBUG
#define CDX_DPA_DPRINT(fmt, args...) printk(KERN_ERR "%s:: " fmt, __func__, ##args)
#else
#define CDX_DPA_DPRINT(fmt, args...) do { } while(0)
#endif

#define PAD(val, padsize) ((val) % (padsize)) ? ((padsize) - ((val) % (padsize))) : 0

//db entry for reusing a hm chain
#define TTL_HM_VALID            (1 << 0)
#define NAT_HM_REPLACE_SIP      (1 << 1)
#define NAT_HM_REPLACE_DIP      (1 << 2)
#define NAT_HM_REPLACE_SPORT    (1 << 3)
#define NAT_HM_REPLACE_DPORT    (1 << 4)
#define NAT_HM_VALID            ( NAT_HM_REPLACE_SIP | NAT_HM_REPLACE_DIP | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT)
#define VLAN_STRIP_HM_VALID     (1 << 5)
#define VLAN_ADD_HM_VALID       (1 << 6)
#define ETHERNET_HM_VALID       (1 << 7)
#define PPPoE_STRIP_HM_VALID    (1 << 8)
#define NAT_HM_NATPT            (1 << 9)
#define NAT_V6	                (1 << 10)
#define EHASH_IPV6_FLOW		(1 << 11)

#define L3_HDR_OPS(l3_info) (l3_info.tnl_header_present || l3_info.add_tnl_header)
#define IS_IPV4_NAT(entry) ( IS_IPV4(entry) && (entry->status & CONNTRACK_NAT) )
#define IS_IPV6_NAT(entry) ( IS_IPV6(entry) && ( entry->status & ( CONNTRACK_SNAT | CONNTRACK_DNAT) ))

extern int dpa_get_mac_addr(char *name, char *mac_addr);
extern void display_ctentry(PCtEntry entry);
extern void display_route_entry(PRouteEntry entry);
extern void display_buf(void *, uint32_t);
void display_SockEntries(PSockEntry SockA, PSockEntry SockB);

extern int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index ,
                uint32_t *fm_index, uint32_t *port_index, uint32_t *portid);
extern void *dpa_get_pcdhandle(uint32_t fm_index);
extern void *dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type);
extern int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
                                struct dpa_l3hdr_info *l3_info, PRouteEntry tnl_rt_entry,
                                uint32_t  queue_no);
extern int create_hm_chain(PCtEntry entry, struct ins_entry_info *info);
extern int create_hm_chain_for_mcast_entry(PCtEntry entry, struct ins_entry_info *info);
extern void delete_hm_chain(PCtEntry entry);
extern int dpa_get_tx_fqid_by_name(char *name, uint32_t *fqid);
extern int disp_muram(void);
extern void *dpa_get_fm_ctx(uint32_t fm_idx);
extern uint32_t dpa_get_fm_timestamp(void *fm_ctx);
extern int dpa_add_oh_if(char *name);
extern void *  get_oh_port_td(uint32_t fm_index, uint32_t port_idx, uint32_t type);
extern uint32_t dpa_get_timestamp_addr(uint32_t id);
extern int add_incoming_iface_info(PCtEntry entry);
extern int ExternalHashTableAddKey(void *h_HashTbl, uint8_t keySize,
                                       void *tbl_entry);
extern int ExternalHashTableDeleteKey(void *h_HashTbl, uint16_t index,
                                       void *tbl_entry);
extern int ExternalHashTableEntryGetStatsAndTS(void *tbl_entry,
                                struct en_tbl_entry_stats *stats);
int insert_pppoe_relay_entry_in_classif_table(pPPPoE_Info  entry);
int delete_pppoe_relay_entry_from_classif_table(pPPPoE_Info entry);
static int insert_opcodeonly_hm(struct ins_entry_info *info, uint8_t opcode);
static int create_nat_hm(struct ins_entry_info *info);
static int create_tunnel_insert_hm(struct ins_entry_info *info);
static int create_ethernet_hm(struct ins_entry_info *info, uint32_t replace);
static int create_enque_hm(struct ins_entry_info *info);
static int create_replicate_hm(struct ins_entry_info *info);
static int fill_mcast_member_actions(RouteEntry *pRtEntry, struct ins_entry_info *info);
static int fill_pppoe_relay_actions(struct ins_entry_info *info,pPPPoE_Info entry);
static int create_tunnel_remove_hm(struct ins_entry_info *info);
static int create_pppoe_relay_hm(struct ins_entry_info *info,pPPPoE_Info entry);
static int insert_remove_pppoe_hm(struct ins_entry_info *info);
static int insert_remove_vlan_hm(struct ins_entry_info *info);
static int cdx_rtprelay_insert_remove_vlan_hm(struct ins_entry_info *info, PRouteEntry pRtEntry);
static int create_eth_rx_stats_hm(struct ins_entry_info *info);
extern int dpa_get_num_vlan_iface_stats_entries(struct _itf *input_itf,
			struct _itf *underlying_input_itf,
                        uint32_t *num_entries);
extern int dpa_get_pppoe_iface_stats_entries(struct _itf *input_itf, 
                        uint8_t *offsets, uint32_t type);
extern int dpa_get_tunnel_iface_stats_entries(struct _itf *input_itf, 
                        uint8_t *offsets, uint32_t type);
extern uint32_t get_logical_ifstats_base(void);
extern int dpa_get_vlan_iface_stats_entries(struct _itf *input_itf, 
			struct _itf *underlying_input_itf,
                        uint8_t *offsets, uint32_t type);
extern int dpa_get_ether_iface_stats_entries(struct _itf *input_itf,
                        struct _itf *underlying_input_itf,
                        uint8_t *offset, uint8_t type);
extern int dpa_get_ifstatsinfo_by_name(char *name, uint32_t *rxstats_index,
                uint32_t *txistats_index);

extern int cdx_ipsec_fill_sec_info( PCtEntry entry, 
		struct ins_entry_info *info); 
extern void drain_bp_pool(struct dpa_bp *bp);
extern t_Error FM_MURAM_FreeMem(t_Handle h_FmMuram, void *ptr);
extern void *dpa_get_fm_MURAM_handle(uint32_t fm_idx, uint64_t *phyBaseAddr,
					uint32_t *MuramSize);
extern void  * FM_MURAM_AllocMem(t_Handle h_FmMuram, uint32_t size, uint32_t align);
#define create_ethernet_remove_hm(info) insert_opcodeonly_hm(info, STRIP_ETH_HDR)
#define create_pppoe_remove_hm(info) insert_opcodeonly_hm(info, STRIP_PPPoE_HDR)
#define create_ttl_hm(info) insert_opcodeonly_hm(info, UPDATE_TTL)
#define create_hoplimit_hm(info) insert_opcodeonly_hm(info, UPDATE_HOPLIMIT)
#define create_routing_hm(info) create_ethernet_hm(info, 1)
#define create_ethernet_insert_hm(info) create_ethernet_hm(info, 0)

#define CDX_FRAG_BUFFERS_CNT	2048
#define CDX_FRAG_BUFF_SIZE	1500

/* Flags that reside in MSB of t_IPF_TD.FragmentedFramesCounter field       */
#define DF_ACTION_MASK          0x30  /* DFAction mask                */
#define DF_ACTION_ERROR         0x00  /* DFAction: treat as error     */
#define DF_ACTION_IGNORE        0x10  /* DFAction: ignore DF bit      */
#define DF_ACTION_DONT_FRAG     0x20  /* DFAction: don't fragment     */

#define BPID_ENABLE              0x08  /* BufferPoolIDEn field         */
#define OPT_COUNTER_EN           0x04  /* IP options copy or not            */
#define CDX_FRAG_USE_BUFF_POOL

typedef struct __attribute__ ((packed)) cdx_ucode_frag_info_s
{
	uint16_t frag_options; // configure the dfAction whether to ignore or honor the DF bit
	uint16_t pad;
	uint32_t alloc_buff_failures;
	uint32_t v4_frames_counter;
	uint32_t v6_frames_counter;
	uint32_t v4_frags_counter;
	uint32_t v6_frags_counter;
	uint32_t v6_identification;
}cdx_ucode_frag_info_t;

typedef struct cdx_frag_info_s
{
	struct dpa_bp 			*frag_bufpool;
	cdx_ucode_frag_info_t		*muram_frag_params;
//	uint32_t			muram_frag_params_addr;
	struct port_bman_pool_info	parent_pool_info;
	uint8_t				frag_bp_id;
} cdx_frag_info_t;

cdx_frag_info_t  frag_info_g;

void cdx_deinit_fragment_bufpool(void);
static int cdx_create_fragment_bufpool(void);
void cdx_deinit_frag_module(void);
int cdx_init_frag_module(void);
extern uint64_t SYS_VirtToPhys(uint64_t addr);
extern int get_phys_port_poolinfo_bysize(uint32_t size, struct port_bman_pool_info *pool_info);
#define PTR_TO_UINT(_ptr)           ((uintptr_t)(_ptr))
uint64_t XX_VirtToPhys(void * addr)
{
    return (uint64_t)SYS_VirtToPhys(PTR_TO_UINT(addr));
}


static int fill_key_info(PCtEntry entry, uint8_t *keymem, uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	int i;
	uint32_t key_size;

	key = (union dpa_key *)keymem;
	//portid added to key
	key->portid = port_id;
	switch (entry->proto) {
		case IPPROTOCOL_TCP: 
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);;
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];
				key->ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key->ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = entry->Dport;
			}
			else
			{

				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key->ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = entry->Dport;
			}
			break;

		case IPPROTOCOL_UDP:
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key->ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
				  	key_size -= 4;
			}
			else
			{
				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key->ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
					key_size -= 4;
			}
			break;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, entry->proto);
			key_size = 0;
	}
#ifdef CDX_DPA_DEBUG
	if (key_size) {
		DPA_INFO("keysize %d\n", key_size);
		display_buf(key, key_size);
	}
#endif
	return key_size;
}

//check activity
void hw_ct_get_active(struct hw_ct *ct)
{
	struct en_tbl_entry_stats stats;
	memset(&stats, 0, sizeof(struct en_tbl_entry_stats));
	ExternalHashTableEntryGetStatsAndTS(ct->handle, &stats);
	ct->pkts = stats.pkts;
	ct->bytes = stats.bytes;
	ct->timestamp = stats.timestamp;
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::ct %p pkts %lu, bytes %lu, timestamp %x jiffies %x\n", 
		__FUNCTION__, ct, (unsigned long)ct->pkts, (unsigned long)ct->bytes, ct->timestamp,
		JIFFIES32);
#endif
}

//delete classif entry from table
int delete_entry_from_classif_table(PCtEntry entry)
{

	CDX_DPA_DPRINT("\n");
	if (ExternalHashTableDeleteKey(entry->ct->td, 
			entry->ct->index, entry->ct->handle)) {
                DPA_ERROR("%s::unable to remove entry from hash table\n", __FUNCTION__);
		return FAILURE;
	}
	//free table entry
	ExternalHashTableEntryFree(entry->ct->handle);
	entry->ct->handle =  NULL;
	kfree(entry->ct);
	entry->ct = NULL;
	return SUCCESS;
}

int delete_pppoe_relay_entry_from_classif_table(pPPPoE_Info entry)
{
   struct hw_ct *ct;

   ct = entry->hw_entry.ct;

   CDX_DPA_DPRINT("\n");
   if(ExternalHashTableDeleteKey(ct->td,ct->index, ct->handle))
   {
     DPA_ERROR("%s::unable to remove entry from hash table\n", __FUNCTION__);
     return FAILURE;
   }
   //free table entry
   ExternalHashTableEntryFree(ct->handle);
   ct->handle =  NULL;
   kfree(ct);
   ct = NULL;
   return SUCCESS;
}

//delete classif entry from table
int delete_l2br_entry_classif_table(struct hw_ct *ct)
{
        if (ExternalHashTableDeleteKey(ct->td, ct->index, ct->handle)) {
                DPA_ERROR("%s::unable to remove entry from hash table\n", __FUNCTION__);
                return FAILURE;
        }
        //free table entry
        ExternalHashTableEntryFree(ct->handle);
	return SUCCESS;
}

static int get_table_type(PCtEntry entry, uint32_t *type)
{
	switch (entry->proto) {
		case IPPROTOCOL_TCP:
            if (IS_IPV6_FLOW(entry)) 
				*type = IPV6_TCP_TABLE;
			else
				*type = IPV4_TCP_TABLE;
			return SUCCESS;
			
		case IPPROTOCOL_UDP:
           if (IS_IPV6_FLOW(entry)) {
                if(entry->Sport == 0 && entry->Dport == 0)
				  	*type = IPV6_MULTICAST_TABLE;
				else 
					*type = IPV6_UDP_TABLE;
			}
			else {
                if(entry->Sport == 0 && entry->Dport == 0)
				  	*type = IPV4_MULTICAST_TABLE;
				else
					*type = IPV4_UDP_TABLE;
			}
			return SUCCESS;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, entry->proto);
			break;
	}
	return FAILURE;
}

static int fill_actions(PCtEntry entry, struct ins_entry_info *info)
{
	PCtEntry twin_entry;
	uint32_t ii; 
	uint32_t rebuild_l2_hdr;
	

#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n", 
		__FUNCTION__, entry, info->opcptr, info->paramptr, info->param_size);
#endif
	twin_entry = CT_TWIN(entry);
	
	//routing and ttl decr are mandatory
	//ttl decr handled as part of NAT-PT
	info->flags = ETHERNET_HM_VALID;

	//mask it as ipv6 flow if required
	if (IS_IPV6_FLOW(entry))
		info->flags |= EHASH_IPV6_FLOW;
	if (!IS_NATPT(entry))
		info->flags |= TTL_HM_VALID;

	//strip vlan on ingress if incoming iface is vlan
	if (info->l2_info.vlan_present)
		info->flags |= VLAN_STRIP_HM_VALID;

	//strip pppoe on ingress if incoming iface is pppoe 
	if (info->l2_info.pppoe_present)
		info->flags |= PPPoE_STRIP_HM_VALID;
	if(L3_HDR_OPS(info->l3_info))	{
	/*  Addition of IP header requires the header to be inserted at the start of the packet.
	    So we need to strip and rebuild the l2 header after tunnel header insertion. */
		rebuild_l2_hdr = 1;

	}else {
		rebuild_l2_hdr = 0;
		if((entry->status & CONNTRACK_SEC) && (!info->to_sec_fqid)){ 
			info->eth_type  = (IS_IPV4(entry)) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
			info->l2_info.add_eth_type = 1;
		}
	}
	//perform NAT where required
	if (IS_NATPT(entry)) {
		info->flags |= (NAT_HM_NATPT | NAT_HM_REPLACE_SPORT | NAT_HM_REPLACE_DPORT);
		info->nat_sport = twin_entry->Dport;
		info->nat_dport = twin_entry->Sport;
		if (IS_IPV6_FLOW(twin_entry))
		{
			info->flags |= NAT_V6;
			memcpy(info->v6.nat_sip, twin_entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
			memcpy(info->v6.nat_dip, twin_entry->Saddr_v6, IPV6_ADDRESS_LENGTH);
		}
		else
		{
			info->v4.nat_sip = entry->twin_Daddr;
			info->v4.nat_dip = entry->twin_Saddr;
		}
                rebuild_l2_hdr = 1;
	} else {
		if (IS_IPV4_NAT(entry) || IS_IPV6_NAT(entry)) {
			switch(entry->proto) {
				case IPPROTOCOL_TCP:
				case IPPROTOCOL_UDP:
					if (entry->Sport != twin_entry->Dport) {
						info->flags |= NAT_HM_REPLACE_SPORT;
						info->nat_sport = (twin_entry->Dport);
					}
					if (entry->Dport != twin_entry->Sport) {
						info->flags |= NAT_HM_REPLACE_DPORT;
						info->nat_dport = (twin_entry->Sport);
					}
					break;
				default:
					break; 
			}
		}
		//check if ip replacement have to be done
		//nat sip if required

		if (IS_IPV6(entry))
		{
			if (entry->status & CONNTRACK_SNAT)
			{
				memcpy(info->v6.nat_sip, twin_entry->Daddr_v6 ,IPV6_ADDRESS_LENGTH);
				info->flags |= NAT_HM_REPLACE_SIP;
			}
			if (entry->status & CONNTRACK_DNAT)
			{
				memcpy(info->v6.nat_dip, twin_entry->Saddr_v6 ,IPV6_ADDRESS_LENGTH);
				info->flags |= NAT_HM_REPLACE_DIP;
			}
		}
		else 
		{
			if (entry->Saddr_v4 != entry->twin_Daddr) {
				info->v4.nat_sip = (entry->twin_Daddr);
				info->flags |= NAT_HM_REPLACE_SIP;
			}
			//nat dip if required
			if (entry->Daddr_v4 != entry->twin_Saddr) {
				info->v4.nat_dip = (entry->twin_Saddr);
				info->flags |= NAT_HM_REPLACE_DIP;
			}
		}
	}
	if (info->l2_info.num_egress_vlan_hdrs) {

		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	while(1) {
#ifdef INCLUDE_ETHER_IFSTATS
		if (create_eth_rx_stats_hm(info)) 
			break;
#endif
		if (info->l2_info.pppoe_present) {
			//strip pppoe hdrs
			if (insert_remove_pppoe_hm(info))
				break;
                }
		if (info->l2_info.vlan_present) {
			//strip vlan hdrs
			if (insert_remove_vlan_hm(info))
				break;
		}
		if (!info->num_mcast_members)
		{
			if(rebuild_l2_hdr) {
       				 //Strip ethernet header
				if (insert_opcodeonly_hm(info, STRIP_ETH_HDR))
				break;
			} else {
				//create routing header modification
				if (create_routing_hm(info))
				break;
			}
		}
		if (info->l3_info.tnl_header_present) { 
			if (create_tunnel_remove_hm(info))
				break;
		}
		if (info->flags & NAT_HM_VALID) {
                	//needs nat, create nat hm, roll in ttl as well
                	if(create_nat_hm(info))
				break;
                } else {
			//may need only TTL hm
        		if (info->flags & TTL_HM_VALID) {
				if (info->flags & EHASH_IPV6_FLOW) {
					if (create_hoplimit_hm(info))
						break;
				} else {
					if (create_ttl_hm(info))
						break;
				}
			}
		}
		if (!info->num_mcast_members)
		{
			if (info->l3_info.add_tnl_header) {
				if (create_tunnel_insert_hm(info)) 
					break;
			}
			if(rebuild_l2_hdr){
				if(create_ethernet_insert_hm(info))
					break;
			}
			//enqueue
			info->enqueue_params = info->paramptr;
			if(create_enque_hm(info))
				break;
		}
		else
		{
			info->replicate_params =  info->paramptr;
			if (create_replicate_hm(info))
				break;
		}
		return SUCCESS;
	}
	return FAILURE;
}

//insert classif entry into table
int insert_entry_in_classif_table(PCtEntry entry)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
        struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::\n", __FUNCTION__);
        display_ctentry(entry);
#endif

	entry->ct = NULL;
	tbl_entry = NULL;	

	info = kzalloc(sizeof(struct ins_entry_info), 0);
        if (!info)
                return FAILURE;

	info->entry = entry;
	// This can never be NULL for connection routes.
        underlying_input_itf = entry->pRtEntry->underlying_input_itf;
        //clear hw entry pointer
        entry->ct = NULL;
        if (add_incoming_iface_info(entry))
        {
                DPA_ERROR("%s::unable to get interface %d\n",__FUNCTION__,
                        entry->inPhyPortNum);
                return FAILURE;
        }
	//get fman index and port index and port id where this entry need to be added
        if (dpa_get_fm_port_index(entry->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
                                &info->port_idx, &info->port_id)) {
                DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
                                __FUNCTION__, entry->inPhyPortNum);
                goto err_ret;
        }
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
		__FUNCTION__, __LINE__, entry->inPhyPortNum, underlying_input_itf->index,
		info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
        info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
        if (!info->fm_pcd) {
                DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
                                __FUNCTION__, info->fm_idx);
                goto err_ret;
        }
	if (get_table_type(entry, &tbl_type)) {
                DPA_ERROR("%s::unable to get table type\n",
                                __FUNCTION__);
                goto err_ret;
	}
	info->tbl_type = tbl_type;

#if 0
	if (entry->pRtEntry->input_itf->type & IF_TYPE_WLAN)
                td = get_oh_port_td(fm_idx, port_idx, tbl_type);
        else
                //get table descriptor based on type and port
                td = dpa_get_tdinfo(fm_idx, port_idx, tbl_type);
#endif
        //get table descriptor based on type and port
        info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
        if (info->td == NULL) {
                DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
                                __FUNCTION__, entry->inPhyPortNum,
                                tbl_type);
                goto err_ret;
        }
#ifdef DPA_IPSEC_OFFLOAD
        /* if the connection is a secure one  and  SA direction is inbound
	 * then, we should add the entry into offline ports's classification
	 * table. cdx_ipsec_fill_sec_info()  will check for the SA direction
	 * and if it is inbound will replace the table id;
	 * if the SA is outbound direction then it will fill sec_fqid in the 
	 * info struture.  
 	 */ 
	if(entry->status &  CONNTRACK_SEC)
	{
		if(cdx_ipsec_fill_sec_info(entry,info))
		{
			DPA_ERROR("%s::unable to get td for offline port, type %d\n",
                        	__FUNCTION__, info->tbl_type);
        			goto err_ret;
		}
	}
#endif

#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s:: td info :%p\n", __FUNCTION__, info->td);
#endif
	//allocate connection tracker entry
        entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
        if (!entry->ct) {
                DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
                                __FUNCTION__);
                goto err_ret;
        }
	//save table descriptor for entry release
        entry->ct->td = info->td;
	//get fm context
        entry->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
        if (entry->ct->fm_ctx == NULL) {
                DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
                        __FUNCTION__, info->fm_idx);
                goto err_ret;
        }

	if (dpa_get_tx_info_by_itf(entry->pRtEntry, &info->l2_info,
                        &info->l3_info, entry->tnl_route, entry->queue)) {
                DPA_ERROR("%s::unable to get tx params\n",
                                __FUNCTION__);
                goto err_ret;
        }

	//allocate hash table entry
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::info->td %p\n", __FUNCTION__, info->td);
#endif
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
                DPA_ERROR("%s::unable to alloc hash tbl memory\n",
                                __FUNCTION__);
                goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
#endif
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	//fill key information from entry
        key_size = fill_key_info(entry, &tbl_entry->hashentry.key[0], info->port_id);
	if (!key_size) {
                DPA_ERROR("%s::unable to compose key\n",
                                __FUNCTION__);
                goto err_ret;
	}	
	
	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];          
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list 
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - 
		GET_PARAM_OFFSET(flags));
	if (fill_actions(entry, info)) {
                DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
                goto err_ret;
	}
	tbl_entry->enqueue_params = info->enqueue_params;
	entry->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry); 
	if (retval == -1) {
                DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
                goto err_ret;
	}	
	entry->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (entry->ct) {
		kfree(entry->ct);
		entry->ct = NULL;
	}
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	kfree(info);
	return FAILURE;
}

int insert_mcast_entry_in_classif_table(struct _tCtEntry *entry, 
					unsigned int num_members, uint64_t first_member_flow_addr,
					void *first_listener_entry)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;
	
	DPA_INFO("%s::\n", __FUNCTION__);
#ifdef CDX_DPA_DEBUG
//	display_ctentry(entry);
#endif
	
	entry->ct = NULL;
	tbl_entry = NULL;	
	
	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info)
		return FAILURE;
	
	info->entry = entry;
	// same as above function insert_entry_in_classif_table, FOLLOWING TWO LINES ADDED ADDITIONALLY
	info->first_member_flow_addr_hi = cpu_to_be16((first_member_flow_addr >> 32) & 0xffff);
	info->first_member_flow_addr_lo = cpu_to_be32(first_member_flow_addr  & 0xffffffff);
	info->num_mcast_members = num_members;
	info->first_listener_entry = first_listener_entry;
	// This can never be NULL for connection routes.
	underlying_input_itf = entry->pRtEntry->underlying_input_itf;
	//clear hw entry pointer
	entry->ct = NULL;
	if (add_incoming_iface_info(entry))
	{
		DPA_ERROR("%s::unable to get interface %d\n",__FUNCTION__,
							entry->inPhyPortNum);
		return FAILURE;
	}
	//get fman index and port index and port id where this entry need to be added
	if (dpa_get_fm_port_index(entry->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
			&info->port_idx, &info->port_id)) {
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
						__FUNCTION__, entry->inPhyPortNum);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__FUNCTION__, __LINE__, entry->inPhyPortNum, underlying_input_itf->index,
			info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
					__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (get_table_type(entry, &tbl_type)) {
		DPA_ERROR("%s::unable to get table type\n",
							__FUNCTION__);
		goto err_ret;
	}
	
	//get table descriptor based on type and port
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
	if (info->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
							__FUNCTION__, entry->inPhyPortNum,
								tbl_type);
		goto err_ret;
	}
	DPA_INFO("%s:: td info :%p\n", __FUNCTION__, info->td);
	//allocate connection tracker entry
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
								__FUNCTION__);
		goto err_ret;
	}
	//save table descriptor for entry release
	entry->ct->td = info->td;
	//get fm context
	entry->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (entry->ct->fm_ctx == NULL) {
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
						__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	
	if (dpa_get_tx_info_by_itf(entry->pRtEntry, &info->l2_info,
			&info->l3_info, entry->tnl_route, entry->queue)) {
		DPA_ERROR("%s::unable to get tx params\n",
									__FUNCTION__);
		goto err_ret;
	}
	
	//allocate hash table entry
	DPA_INFO("%s::info->td %p\n", __FUNCTION__, info->td);
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
									__FUNCTION__);
		goto err_ret;
	}
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
		flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
			cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
//fill key information from entry
	key_size = fill_key_info(entry, &tbl_entry->hashentry.key[0], info->port_id);
	if (!key_size) {
		DPA_ERROR("%s::unable to compose key\n",
								__FUNCTION__);
		goto err_ret;
	}	
		
	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list 
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - 
		GET_PARAM_OFFSET(flags));
	if (fill_actions(entry, info)) {
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
	tbl_entry->replicate_params = info->replicate_params;
	tbl_entry->enqueue_params = info->enqueue_params;
	entry->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry); 
	if (retval == -1) {
		DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
		goto err_ret;
	}	
	entry->ct->index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (entry->ct)
		kfree(entry->ct);
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	kfree(info);
	return FAILURE;
}

static int fill_bridge_actions(struct ins_entry_info *info, uint8_t rx_stats_offset)
{
#ifdef INCLUDE_ETHER_IFSTATS
        uint32_t stats_ptr;
        struct en_ehash_update_ether_rx_stats *param;

        if (info->opc_count == MAX_OPCODES)
                return FAILURE;
        if (sizeof(struct en_ehash_update_ether_rx_stats) > info->param_size)
                return FAILURE;
        param = (struct en_ehash_update_ether_rx_stats *)info->paramptr;
        stats_ptr = (get_logical_ifstats_base() +
                                (rx_stats_offset * sizeof(struct en_ehash_stats)));
#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, stats_ptr);
#endif
        param->stats_ptr = cpu_to_be32(stats_ptr);
        //update opcode and param ptr
        *(info->opcptr) = UPDATE_ETH_RX_STATS;
        info->opcptr++;
        info->opc_count--;
        info->param_size -= sizeof(struct en_ehash_update_ether_rx_stats);
        info->paramptr += sizeof(struct en_ehash_update_ether_rx_stats);
#endif
	if(create_enque_hm(info))
		return FAILURE;
	return SUCCESS;
}

int insert_pppoe_relay_entry_in_classif_table(pPPPoE_Info entry)  /* struct _tPPPoE_Info *entry)*/
{
   struct en_exthash_tbl_entry *tbl_entry = NULL;
   union dpa_key *key;
   struct ins_entry_info *info;
   uint8_t *ptr;
   POnifDesc ifdesc;
   uint32_t portid,flags,key_size;
   struct hw_ct *ct = NULL;
   int retval;

   info = kzalloc(sizeof(struct ins_entry_info), 0);
   if(!info)
   {
     DPA_ERROR("%s::unable to allocate mem for info\n", __FUNCTION__);
     goto err_ret;
   }
   DPA_INFO("%s(%d) incoming interface %s\n",__FUNCTION__,__LINE__,&entry->hw_entry.in_ifname[0]);
   DPA_INFO("%s(%d) outgoing interface %s\n",__FUNCTION__,__LINE__,&entry->relay->hw_entry.in_ifname[0]);   

   if((ifdesc = get_onif_by_name(&entry->hw_entry.in_ifname[0])) == NULL)
   {
    DPA_ERROR("%s::unable to validate incoming iface %s\n", __FUNCTION__,&entry->hw_entry.in_ifname[0]);
    goto err_ret;
   }
   DPA_INFO("%s(%d) ifdesc->itf->index %d\n",__FUNCTION__,__LINE__,ifdesc->itf->index);

   if(dpa_get_fm_port_index(ifdesc->itf->index,0, &info->fm_idx,&info->port_idx, &portid))
   {
     DPA_ERROR("%s::unable to get fm-index for input iface %s\n",__FUNCTION__, &entry->hw_entry.in_ifname[0]);
     goto err_ret;
   }
   DPA_INFO("%s(%d) fm_idx %d, port_idx %d, port_id %d\n",__FUNCTION__,__LINE__,info->fm_idx, info->port_idx, portid);
 
   info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
   if(!info->fm_pcd)
   {
     DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",__FUNCTION__, info->fm_idx);
     goto err_ret;
   }
   DPA_INFO("%s(%d) fm_pcd %p \n",__FUNCTION__,__LINE__, info->fm_pcd);

   //get egress FQID
   if(dpa_get_tx_fqid_by_name(&entry->relay->hw_entry.in_ifname[0], &info->l2_info.fqid))
   {
     DPA_ERROR("%s::unable to get tx params-fqid\n",__FUNCTION__);
     goto err_ret;
   }
   DPA_INFO("\r\n egress fq_id = %d \r\n",info->l2_info.fqid); 

   //disable frag
   info->l2_info.mtu = 0xffff;

   #ifdef CDX_DPA_DEBUG
//     DPA_INFO("%s:: mtu %d\n", __FUNCTION__, dev->mtu);
   #endif

   //get table descriptor based on type and port
   info->td = dpa_get_tdinfo(info->fm_idx, portid, PPPOE_RELAY_TABLE);    //ETHERNET_TABLE
   if(info->td == NULL)
   {
     DPA_ERROR("%s::unable to get td for input iface %s\n",__FUNCTION__, &entry->hw_entry.in_ifname[0]);
     goto err_ret;
   }
   DPA_INFO("%s(%d) td %p \n",__FUNCTION__,__LINE__, info->td); 

   //allocate hw entry
   ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct) , GFP_KERNEL);
   if(!ct)
   {
     DPA_ERROR("%s::unable to alloc mem for hw_ct\n",__FUNCTION__);
     goto err_ret;
   }

   entry->hw_entry.ct = ct;
   ct->handle = NULL;
   //save table descriptor for entry release
   ct->td = info->td;

   //get fm context
   ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
   if(ct->fm_ctx == NULL)
   {
     DPA_ERROR("%s::failed to get ctx from fm idx %d\n", __FUNCTION__, info->fm_idx);
     goto err_ret;
   }

   //Allocate hash table entry
   tbl_entry = ExternalHashTableAllocEntry(info->td);
   if(!tbl_entry)
   {
     DPA_ERROR("%s::unable to alloc hash tbl memory\n",__FUNCTION__);
     goto err_ret;
   }

   #ifdef CDX_DPA_DEBUG
     printk("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
   #endif

   //fill key info
   key = (union dpa_key *)&tbl_entry->hashentry.key[0];
   //portid added to key
   key->portid = portid;

   //fill src mac address,ethtype and pppoe session id
   memcpy(&key->pppoe_relay_key.ether_sa[0], &entry->DstMAC[0],6);
   key->pppoe_relay_key.ether_type = cpu_to_be16(0x8864);
   DPA_INFO("\r\n session id %x",entry->sessionID);
   DPA_INFO("\r\n relay session id %x",entry->relay->sessionID);
   key->pppoe_relay_key.session_id = entry->sessionID;
   key_size = (sizeof(struct pppoe_relay_key) + 1);
   DPA_INFO("\r\n key size = %d",key_size);

   #ifdef CDX_DPA_DEBUG
   if(key_size)
   {
     DPA_INFO("keysize %d\n", key_size);
     display_buf(key, key_size);
   }
   #endif

   flags = 0;

   //round off keysize to next 4 bytes boundary
   ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
   ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);

   info->opcptr = ptr;   //set start of opcode list
   ptr += MAX_OPCODES;   //ptr now after opcode section

   //set offset to first opcode
   SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
   //set param offset
   SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));

   //param_ptr now points after timestamp location
   tbl_entry->hashentry.flags = cpu_to_be16(flags);
   /* param pointer and opcode pointer now valid */
   info->paramptr = ptr;
   info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - GET_PARAM_OFFSET(flags));

   /* fill the pppoe relay parameters */

   if(fill_pppoe_relay_actions(info,entry))
   {
     DPA_ERROR("%s::unable to fill pppoe relay actions\n", __FUNCTION__);
     goto err_ret;
   }
   DPA_INFO("\r\ninsert_pppoe_relay_entry_in_classif_table:pppoe relay actions are filled successfully");
   ct->handle = tbl_entry;

   #ifdef CDX_DPA_DEBUG
      display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
   #endif 

   //insert entry into hash table
   retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry);
   if(retval == -1)
   {
     DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
     goto err_ret;
   }
   DPA_INFO("\r\n insert_pppoe_relay_entry_in_classif_table: Added the pppoe relay key successfully");
   ct->index = (uint16_t)retval;
   ct->handle = tbl_entry;
   kfree(info);
   return SUCCESS;

   err_ret:
   DPA_INFO("%s::unable to add entry in hash table\n", __FUNCTION__);
   //release all allocated items
   if(entry->hw_entry.ct)
     kfree(entry->hw_entry.ct);
   if(tbl_entry)
     ExternalHashTableEntryFree(tbl_entry);

   kfree(info);
   return FAILURE;
}     

//fill all opcodes and parameters for pppoe relay functionality.
static int fill_pppoe_relay_actions(struct ins_entry_info *info,pPPPoE_Info entry) /* struct _tPPPoE_Info *entry) */
{

  #ifdef CDX_DPA_DEBUG
   // DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n",
    //          __FUNCTION__, pRtEntry, info->opcptr, info->paramptr, info->param_size);
  #endif

  DPA_INFO("%s(%d) create_pppoe_relay_hm\n",__FUNCTION__,__LINE__);
  if(create_pppoe_relay_hm(info,entry))
    return FAILURE;  
  return SUCCESS;
}

int add_l2flow_to_hw(struct L2Flow_entry *entry)
{
	int retval;
	POnifDesc ifdesc; 
	uint32_t flags;
	uint32_t fm_idx;
	uint32_t port_idx;
	void *td;
	uint8_t *ptr;
	uint32_t fqid;
	struct ins_entry_info *info;
	struct hw_ct *ct;
        uint32_t portid;
	struct en_exthash_tbl_entry *tbl_entry;

	if((ifdesc = get_onif_by_name(&entry->in_ifname[0])) == NULL) {
		DPA_ERROR("%s::unable to validate iface %s\n", __FUNCTION__,
				&entry->in_ifname[0]);
                return FAILURE;
	}
	if (dpa_get_fm_port_index(ifdesc->itf->index,0, &fm_idx,
		&port_idx, &portid)) {
		DPA_ERROR("%s::unable to get fmindex for iface %s\n",
			__FUNCTION__, &entry->out_ifname[0]);
                return FAILURE;
	}

	//get table handle	
	td = dpa_get_tdinfo(fm_idx, portid, ETHERNET_TABLE);
	if (td == NULL) {
		DPA_ERROR("%s::unable to get td for iface %s\n",
			__FUNCTION__, &entry->out_ifname[0]); 
                return FAILURE;
	}
	//get egress FQID 
	if (dpa_get_tx_fqid_by_name(&entry->out_ifname[0], &fqid)) {
		DPA_ERROR("%s::unable to get tx params\n",
			__FUNCTION__);
                return FAILURE;
	}

	info = kzalloc(sizeof(struct ins_entry_info), 0);
        if (!info) {
		DPA_ERROR("%s::unable to allocate mem for info\n",
			__FUNCTION__);
                return FAILURE;
	}
	info->td = td;
	tbl_entry = NULL;
	//allocate hw entry
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct) , GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
				__FUNCTION__);
        	goto err_ret;
	}
	ct = entry->ct;
	ct->handle = NULL;
	ct->td = td;
	//allocate hash table entry
        tbl_entry = ExternalHashTableAllocEntry(info->td);
        if (!tbl_entry) {
                DPA_ERROR("%s::unable to alloc hash tbl memory\n",
                                __FUNCTION__);
                goto err_ret;
        }
#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
#endif
	{
		union dpa_key *key;
		
		//fill key info
	        key = (union dpa_key *)&tbl_entry->hashentry.key[0];
        	//portid added to key
        	key->portid = portid;
		//fill mac addresses and type
		memcpy(&key->ether_key.ether_da[0], &entry->l2flow.da[0], ETH_ALEN);
		memcpy(&key->ether_key.ether_sa[0], &entry->l2flow.sa[0], ETH_ALEN);
		key->ether_key.ether_type = (entry->l2flow.ethertype); 
        }
        //round off keysize to next 4 bytes boundary
        ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
        ptr += ALIGN((sizeof(struct ethernet_key) + 1), TBLENTRY_OPC_ALIGN);
        //set start of opcode list
        info->opcptr = ptr;
        //ptr now after opcode section
        ptr += MAX_OPCODES;

	flags = 0;
        //set offset to first opcode
        SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
        //set param offset
        SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
		cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	entry->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
        //param_ptr now points after timestamp location
        tbl_entry->hashentry.flags = cpu_to_be16(flags);
        //param pointer and opcode pointer now valid
        info->paramptr = ptr;
        info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - GET_PARAM_OFFSET(flags));
	//disable frag
	info->l2_info.mtu = 0xffff;
	//fix fqid
	info->l2_info.fqid = fqid;
#ifdef INCLUDE_ETHER_IFSTATS
	{
		uint32_t rxidx;
		uint32_t txidx;

		if (dpa_get_ifstatsinfo_by_name(&entry->out_ifname[0],
			&rxidx, &txidx)) {
                	DPA_ERROR("%s::unable to get ifstats info for iface %s\n",
                                __FUNCTION__, &entry->out_ifname[0]);
			
                	goto err_ret;
		}
		//provide the egress interface tx stats index
		info->l2_info.ether_stats_offset = txidx;	
		//add ingress eth stats 	
		if (dpa_get_ifstatsinfo_by_name(&entry->in_ifname[0],
                        &rxidx, &txidx)) {
                        DPA_ERROR("%s::unable to get ifstats info for iface %s\n",
                                __FUNCTION__, &entry->in_ifname[0]);

                        goto err_ret;
                }
		//fill actions required by entry
        	if (fill_bridge_actions(info, rxidx)) {
                	DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
                	goto err_ret;
        	}
	}
#else
	//fill actions required by entry
        if (fill_bridge_actions(info, 0)) {
                DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
                goto err_ret;
        }
#endif
	//add entry to table
	retval = ExternalHashTableAddKey(info->td, 
		(sizeof(struct ethernet_key) + 1), tbl_entry);
	if (retval == -1) {
                DPA_ERROR("%s::unable to add table entry\n", __FUNCTION__);
                goto err_ret;
	}
	entry->ct->index = retval;
	//save handle for delete
	ct->handle = tbl_entry;
        kfree(info);
        return SUCCESS;
err_ret:
	if (tbl_entry) {
		ExternalHashTableEntryFree(tbl_entry);
	}
	if (entry->ct) {
		if (delete_l2br_entry_classif_table(entry->ct) == 0)
			kfree(entry->ct);
	}
        kfree(info);
        return FAILURE;
}

static int create_pppoe_relay_hm(struct ins_entry_info *info,pPPPoE_Info entry) /* struct _tPPPoE_Info *entry) */
{
  struct en_ehash_replace_pppoe_hdr_params *param;

  if(info->opc_count == MAX_OPCODES)
    return FAILURE;
  if(sizeof(struct en_ehash_replace_pppoe_hdr_params) > info->param_size)
    return FAILURE;

  param = (struct en_ehash_replace_pppoe_hdr_params *)info->paramptr;
  info->paramptr += sizeof(struct en_ehash_replace_pppoe_hdr_params);
  info->param_size -= sizeof(struct en_ehash_replace_pppoe_hdr_params);
  *(info->opcptr) = REPLACE_PPPOE_HDR;
  info->opc_count++;
  info->opcptr++;

  memcpy(&param->destination_mac[0], &entry->relay->DstMAC[0], ETHER_ADDR_LEN);
  memcpy(&param->source_mac[0], &entry->relay->hw_entry.SrcMAC[0], ETHER_ADDR_LEN);
  param->session_id = entry->relay->sessionID;
  param->fqid = cpu_to_be32(info->l2_info.fqid);
  
  #ifdef INCLUDE_ETHER_IFSTATS
  {
    uint8_t offset;
    uint32_t word;

    offset = info->l2_info.ether_stats_offset;
    word = ((get_logical_ifstats_base() +
            (offset * sizeof(struct en_ehash_stats))) & 0xffffff);
    param->stats_ptr = cpu_to_be32(word);

    #ifdef CDX_DPA_DEBUG
       DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, (word & 0xffffff));
    #endif
  }
  #else
    param->stats_ptr = 0;
  #endif  
  
  return SUCCESS;
}

static int create_pppoe_ins_hm(struct ins_entry_info *info)
{
	struct en_ehash_insert_pppoe_hdr *param;	
	uint32_t word;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_insert_pppoe_hdr) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_insert_pppoe_hdr *)info->paramptr;
	info->paramptr += sizeof(struct en_ehash_insert_pppoe_hdr);
        info->param_size -= sizeof(struct en_ehash_insert_pppoe_hdr);
        *(info->opcptr) = INSERT_PPPoE_HDR;
        info->opc_count++;
        info->opcptr++;
#ifdef INCLUDE_PPPoE_IFSTATS
	{
		uint8_t offset;

		offset = (info->l2_info.pppoe_stats_offset & ~STATS_WITH_TS);
		word = (get_logical_ifstats_base() + 
			(offset * sizeof(struct en_ehash_stats_with_ts)));
		param->stats_ptr = cpu_to_be32(word);
	}
#else
	param->stats_ptr = 0;	
#endif
	word = ((PPPoE_VERSION << 28) | (PPPoE_TYPE << 24) | (PPPoE_CODE << 16) | 
		(info->l2_info.pppoe_sess_id));
	param->word = cpu_to_be32(word);
	return SUCCESS;
}

static int create_vlan_ins_hm(struct ins_entry_info *info)
{
	uint32_t ii;
	uint32_t word;
	struct en_ehash_insert_vlan_hdr *param;
	uint32_t *ptr;
	uint32_t param_size;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	param_size = (sizeof(struct en_ehash_insert_vlan_hdr) + 
		(info->l2_info.num_egress_vlan_hdrs * sizeof(uint32_t)));
	param = (struct en_ehash_insert_vlan_hdr *)info->paramptr;
	word = (info->l2_info.num_egress_vlan_hdrs << 24);
	//add vlan headers
	ptr = (uint32_t *)&param->vlanhdr[0];
	info->vlan_hdrs = ptr;
	for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
                *ptr = cpu_to_be32(((uint32_t )info->l2_info.egress_vlan_hdrs[ii].tpid << 16) | 
                        info->l2_info.egress_vlan_hdrs[ii].tci);
			ptr++;
	}
#ifdef INCLUDE_VLAN_IFSTATS
	{
		uint8_t *st_ptr;
		if (info->l2_info.num_egress_vlan_hdrs > 1) {
			uint32_t padding;

			padding = PAD(info->l2_info.num_egress_vlan_hdrs, sizeof(uint32_t));
			//set pointer last vlan offset 
			st_ptr = ((uint8_t *)ptr + (info->l2_info.num_egress_vlan_hdrs - 1));
			param_size += (padding + info->l2_info.num_egress_vlan_hdrs);
			if (param_size > info->param_size)
				return FAILURE;	
			//add padding and stats base 
			word |= (get_logical_ifstats_base() | padding << 30);
			for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
				*st_ptr = info->l2_info.vlan_stats_offsets[ii];
				//save offset reversed order so that uCode can update easily
				st_ptr--;
			}
		} else {
			//single Vlan header, add stats ptr directly
			word |= (get_logical_ifstats_base() + 
				info->l2_info.vlan_stats_offsets[0] * sizeof(struct en_ehash_stats));
			if (param_size > info->param_size)
				return FAILURE;	
		}
	}
#else
	if (param_size > info->param_size)
		return FAILURE;	
	DPA_INFO("%s::Vlan statistics disabled\n", __FUNCTION__);
#endif
	//write word
	param->word = cpu_to_be32(word);
	//write opcode and update pointers
        *(info->opcptr) = INSERT_VLAN_HDR;
        info->opc_count++;
        info->opcptr++;
	info->paramptr += param_size;
        info->param_size -= param_size;
	return SUCCESS;
}

static int create_ethernet_hm(struct ins_entry_info *info, uint32_t replace)
{
	struct dpa_l2hdr_info *l2_info;
	uint32_t ii;
	uint32_t header_padding;
	uint32_t hdrlen;
	struct en_ehash_insert_l2_hdr *l2param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;

	l2_info = &info->l2_info;
	l2param = (struct en_ehash_insert_l2_hdr *)info->paramptr;
	hdrlen = (ETHER_ADDR_LEN * 2);
        if(l2_info->add_eth_type){
		hdrlen +=ETHER_TYPE_LEN;
	}
	ii = ALIGN((hdrlen + sizeof(struct en_ehash_insert_l2_hdr)), sizeof(uint32_t));
	if (ii > info->param_size)
		return FAILURE;
	//adjust param ptrs and size
	info->paramptr += ii;
	info->param_size -= ii;
	header_padding =  ((hdrlen + sizeof(struct en_ehash_insert_l2_hdr))% sizeof(uint32_t));
	ii = ((replace << 31) | hdrlen |(header_padding << 29));
	//add opcode, adjust size and ptr
	l2param->word = cpu_to_be32(ii);
	*(info->opcptr) = INSERT_L2_HDR;
	info->opc_count++;
	info->opcptr++;
	if (l2_info->add_pppoe_hdr) {
                //if pppoe header required, replace dest with ac conc address
                memcpy(&l2param->l2hdr[0], &l2_info->ac_mac_addr[0],
                                ETHER_ADDR_LEN);
        } else {
                //if no pppoe header required, replace dest with gw address
                memcpy(&l2param->l2hdr[0], &l2_info->l2hdr[0],
                                ETHER_ADDR_LEN);
        }
        // write source address
        memcpy(&l2param->l2hdr[ETHER_ADDR_LEN], &l2_info->l2hdr[ETHER_ADDR_LEN],
                                ETHER_ADDR_LEN);
	// write eth_ type if requested
        if(l2_info->add_eth_type){
                memcpy(&l2param->l2hdr[2*ETHER_ADDR_LEN], &info->eth_type,
                                ETHER_TYPE_LEN);
	}
	//insert vlan headers
	if (l2_info->num_egress_vlan_hdrs) {
		if (create_vlan_ins_hm(info))
			return FAILURE;
	}
	if (l2_info->add_pppoe_hdr)  {
		if (create_pppoe_ins_hm(info))
			return FAILURE;
	}
	return SUCCESS;
}

static int insert_remove_pppoe_hm(struct ins_entry_info *info)
{
	uint32_t param_size;
	struct en_ehash_strip_pppoe_hdr *param;
	uint32_t stats_ptr;
	PCtEntry ctentry;
		
	param = (struct en_ehash_strip_pppoe_hdr *)info->paramptr;
        param_size = sizeof(struct en_ehash_strip_pppoe_hdr);
	if (param_size > info->param_size)
		return FAILURE;
	ctentry = info->entry;
#ifdef INCLUDE_PPPoE_IFSTATS
	{
		uint8_t offset;
		struct _itf *itf;

                if (ctentry->pRtEntry->input_itf->type & IF_TYPE_PPPOE)
                        itf = ctentry->pRtEntry->input_itf;
                else
                        itf = ctentry->pRtEntry->underlying_input_itf;
                if (dpa_get_pppoe_iface_stats_entries(itf,
                        &offset, RX_IFSTATS)) {
                	DPA_ERROR("%s::unable to get stats offset on pppoe iface on ingress\n",
                               		 __FUNCTION__);
                        return FAILURE;
                }
		offset &= ~STATS_WITH_TS;
		stats_ptr = (get_logical_ifstats_base() + 
				(offset * sizeof(struct en_ehash_stats_with_ts)));
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, stats_ptr);
#endif
	}
#else
	stats_ptr = 0;
	DPA_INFO("%s:PPPoE ingress stats disabled\n", __FUNCTION__);
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//add opcode
	*(info->opcptr) = STRIP_PPPoE_HDR;
        //adjust opc, param ptrs and size
        info->opc_count++;
        info->opcptr++;
	info->param_size -= param_size;
        info->paramptr += param_size;
	return SUCCESS;
}


static int insert_remove_vlan_hm(struct ins_entry_info *info)
{
	uint32_t param_size;
	struct en_ehash_strip_all_vlan_hdrs *param;
	uint32_t num_entries;
	uint32_t word;
	PCtEntry ctentry;
		
	param = (struct en_ehash_strip_all_vlan_hdrs *)info->paramptr;
	ctentry = info->entry;
        param_size = sizeof(struct en_ehash_strip_all_vlan_hdrs);
#ifdef INCLUDE_VLAN_IFSTATS
	{
		uint32_t padding;
		if (dpa_get_num_vlan_iface_stats_entries(ctentry->pRtEntry->input_itf,	
			ctentry->pRtEntry->underlying_input_itf,
			&num_entries)) {
			DPA_ERROR("%s::unable to get number on vlan iface on ingress\n",
			__FUNCTION__);
                	return FAILURE;
		}
		if (num_entries > 1) {
			padding = PAD(num_entries, sizeof(uint32_t));
			param_size += (padding + num_entries);
			//check if we have room
			if (param_size > info->param_size)
				return FAILURE;
			word = ((padding << 30) | (num_entries << 24)| get_logical_ifstats_base());
			if (dpa_get_vlan_iface_stats_entries(ctentry->pRtEntry->input_itf,
					ctentry->pRtEntry->underlying_input_itf, 
					&param->stats_offsets[0], RX_IFSTATS)) {
				DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
					__FUNCTION__);
        	        	return FAILURE;
			}
		} else {
			uint8_t offset;
			
			padding = 0;
			//check if we have room
			if (param_size > info->param_size)
				return FAILURE;
			 if (dpa_get_vlan_iface_stats_entries(ctentry->pRtEntry->input_itf,
                                ctentry->pRtEntry->underlying_input_itf,
                                &offset, RX_IFSTATS)) {
                       		 DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
                               		 __FUNCTION__);
                        	return FAILURE;
                	}
			word = ((num_entries << 24) |
				(get_logical_ifstats_base() + 
				(offset * sizeof(struct en_ehash_stats))));
		}
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::padding %d, stats ptr %x, num_entries %d\n", \
			__FUNCTION__, padding, (word & 0xffffff), num_entries);
#endif
	}
#else
	if (param_size > info->param_size)
		return FAILURE;
	word = 0;
	DPA_INFO("%s::Vlan ingress stats disabled\n", __FUNCTION__);
#endif
	param->word = cpu_to_be32(word);
	//add opcode
	*(info->opcptr) = STRIP_ALL_VLAN_HDRS;
        //adjust opc, param ptrs and size
        info->opc_count++;
        info->opcptr++;
	info->param_size -= param_size;
        info->paramptr += param_size;
	return SUCCESS;
}

static int cdx_rtprelay_insert_remove_vlan_hm(struct ins_entry_info *info,PRouteEntry pRtEntry)
{
	uint32_t param_size;
	struct en_ehash_strip_all_vlan_hdrs *param;
	uint32_t num_entries;
	uint32_t word;
		
	param = (struct en_ehash_strip_all_vlan_hdrs *)info->paramptr;
        param_size = sizeof(struct en_ehash_strip_all_vlan_hdrs);
#ifdef INCLUDE_VLAN_IFSTATS
	{
		uint32_t padding;
		if (dpa_get_num_vlan_iface_stats_entries(pRtEntry->input_itf,	
			pRtEntry->underlying_input_itf,
			&num_entries)) {
			DPA_ERROR("%s::unable to get number on vlan iface on ingress\n",
			__FUNCTION__);
                	return FAILURE;
		}
		if (num_entries > 1) {
			padding = PAD(num_entries, sizeof(uint32_t));
			param_size += (padding + num_entries);
			//check if we have room
			if (param_size > info->param_size)
				return FAILURE;
			word = ((padding << 30) | (num_entries << 24)| get_logical_ifstats_base());
			if (dpa_get_vlan_iface_stats_entries(pRtEntry->input_itf,
					pRtEntry->underlying_input_itf, 
					&param->stats_offsets[0], RX_IFSTATS)) {
				DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
					__FUNCTION__);
        	        	return FAILURE;
			}
		} else {
			uint8_t offset;
			
			padding = 0;
			//check if we have room
			if (param_size > info->param_size)
				return FAILURE;
			 if (dpa_get_vlan_iface_stats_entries(pRtEntry->input_itf,
                                pRtEntry->underlying_input_itf,
                                &offset, RX_IFSTATS)) {
                       		 DPA_ERROR("%s::unable to get stats offset on vlan iface on ingress\n",
                               		 __FUNCTION__);
                        	return FAILURE;
                	}
			word = ((num_entries << 24) |
				(get_logical_ifstats_base() + 
				(offset * sizeof(struct en_ehash_stats))));
		}
#ifdef CDX_DPA_DEBUG
		DPA_INFO("%s::padding %d, stats ptr %x, num_entries %d\n", \
			__FUNCTION__, padding, (word & 0xffffff), num_entries);
#endif
	}
#else
	if (param_size > info->param_size)
		return FAILURE;
	word = 0;
	DPA_INFO("%s::Vlan ingress stats disabled\n", __FUNCTION__);
#endif
	param->word = cpu_to_be32(word);
	//add opcode
	*(info->opcptr) = STRIP_ALL_VLAN_HDRS;
        //adjust opc, param ptrs and size
        info->opc_count++;
        info->opcptr++;
	info->param_size -= param_size;
        info->paramptr += param_size;
	return SUCCESS;
}



static int insert_opcodeonly_hm(struct ins_entry_info *info, uint8_t opcode)
{
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	*(info->opcptr) = opcode;
	info->opc_count++;
	info->opcptr++;
	return SUCCESS;
}

static int create_nat_hm(struct ins_entry_info *info)
{
	uint8_t opcode;
	uint32_t size;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	opcode = 0;
	if (info->flags & NAT_HM_REPLACE_SPORT) {
		opcode = UPDATE_SPORT;
	}
	if (info->flags & NAT_HM_REPLACE_DPORT) {
		opcode |= UPDATE_DPORT;
	}
	//add port translation info
	if (opcode) {
		struct en_ehash_update_port *natport;

		if (info->param_size < sizeof(struct en_ehash_update_port))
			return FAILURE;
		*(info->opcptr) = opcode;
		info->opcptr++;
		info->opc_count--;
		natport = (struct en_ehash_update_port *)info->paramptr;

		natport->sport = (info->nat_sport);
		natport->dport = (info->nat_dport);

		info->paramptr += sizeof(struct en_ehash_update_port);
		info->param_size -= sizeof(struct en_ehash_update_port);
	}

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;

	 //handle NATPT case
	if (info->flags & NAT_HM_NATPT) {
		struct en_ehash_natpt_hdr *ptr;
		PCtEntry entry;
		PCtEntry twin_entry;
		uint32_t word;
 
		entry = info->entry;
		twin_entry = CT_TWIN(entry);
		ptr = (struct en_ehash_natpt_hdr *)info->paramptr;
		if (IS_IPV4_FLOW(twin_entry)) {
			ipv4_hdr_t *hdr;
 
			// 6 to 4
			printk("%s::changing ipv6 hdr to ipv4\n", __FUNCTION__);
			opcode = NATPT_6to4;
			size = (sizeof(struct en_ehash_natpt_hdr) +
                                sizeof(ipv4_hdr_t));
			if (size > info->param_size)
				return FAILURE;
			memset(ptr, 0, size);
			//inherit TOS and TTL values from ipv6 header fields
			//ipident from flow
			word = (NATPT_TOU | NATPT_TLU | (sizeof(ipv4_hdr_t) << 16)
                                        | IPID_STARTVAL);
			ptr->word = cpu_to_be32(word);
			hdr = (ipv4_hdr_t *)&ptr->l3hdr[0];
			hdr->Version_IHL = 0x45;
			hdr->SourceAddress = (twin_entry->Daddr_v4);
			hdr->DestinationAddress = (twin_entry->Saddr_v4);
		} 
		else 
		{
			ipv6_hdr_t *hdr;
 
			// 4 to 6
			printk("%s::changing ipv4 hdr to ipv6\n", __FUNCTION__);
			opcode = NATPT_4to6;
			size = (sizeof(struct en_ehash_natpt_hdr) +
                                sizeof(ipv6_hdr_t));
			if (size > info->param_size)
				return FAILURE;
			memset(ptr, 0, size);
			//inherit Traffic class and hoplimit from ipv4 header fields
			word = (NATPT_TCU | NATPT_HLU | (sizeof(ipv6_hdr_t) << 16));
			ptr->word = cpu_to_be32(word);
			hdr = (ipv6_hdr_t *)&ptr->l3hdr[0];
			hdr->Version_TC_FLHi = 0x60;
			memcpy(&hdr->SourceAddress[0], twin_entry->Daddr_v6, 16);
			memcpy(&hdr->DestinationAddress[0], twin_entry->Saddr_v6, 16);
		}
		//update opcode and param pointers and size
		info->paramptr += size;
		info->param_size -= size;
		*(info->opcptr) = opcode;
		info->opcptr++;
		return SUCCESS;
	}
	size = 0;
	opcode = 0;
	if (info->flags & NAT_HM_REPLACE_SIP) {
		if (info->flags & EHASH_IPV6_FLOW) {
			opcode |= UPDATE_SIP_V6;
			size += sizeof(struct en_ehash_update_ipv6_ip);
		} else {
			opcode |= UPDATE_SIP_V4;
			size += sizeof(struct en_ehash_update_ipv4_ip);
		}
	}
	if (info->flags & NAT_HM_REPLACE_DIP) {
                if (info->flags & EHASH_IPV6_FLOW) {
                        opcode |= UPDATE_DIP_V6;
			size += sizeof(struct en_ehash_update_ipv6_ip);
                } else {
                        opcode |= UPDATE_DIP_V4;
			size += sizeof(struct en_ehash_update_ipv4_ip);
                }
        }
	if (opcode) {
		uint8_t *ptr;
		if (size > info->param_size)
			return FAILURE;
		ptr = info->paramptr;
		if (info->flags & NAT_HM_REPLACE_SIP) {
			if (info->flags & EHASH_IPV6_FLOW) {
				memcpy(ptr, &info->v6.nat_sip[0], sizeof(struct en_ehash_update_ipv6_ip));
				ptr += sizeof(struct en_ehash_update_ipv6_ip);
			} else {
				memcpy(ptr, &info->v4.nat_sip, sizeof(struct en_ehash_update_ipv4_ip));
				ptr += sizeof(struct en_ehash_update_ipv4_ip);
			}
		}	
		if (info->flags & NAT_HM_REPLACE_DIP) {
			if (info->flags & EHASH_IPV6_FLOW) {
				memcpy(ptr, &info->v6.nat_dip[0], sizeof(struct en_ehash_update_ipv6_ip));
				ptr += sizeof(struct en_ehash_update_ipv6_ip);
			} else {
				memcpy(ptr, &info->v4.nat_dip, sizeof(struct en_ehash_update_ipv4_ip));
				ptr += sizeof(struct en_ehash_update_ipv4_ip);
			}
		}
		info->paramptr = ptr;
		info->param_size -= size;
	}
	if(info->flags & TTL_HM_VALID) {
                if (info->flags & EHASH_IPV6_FLOW) 
			opcode |= UPDATE_HOPLIMIT;
		else
			opcode |= UPDATE_TTL;
	}
	*(info->opcptr) = opcode;
	info->opcptr++;
	return SUCCESS;
}
static int create_tunnel_insert_hm(struct ins_entry_info *info) 
{
	uint32_t size;
	uint32_t word;
	
	struct en_ehash_insert_l3_hdr *ptr;

	if (info->opc_count == MAX_OPCODES)
                return FAILURE;
	size = (sizeof(struct en_ehash_insert_l3_hdr) + 
		info->l3_info.header_size);
	size = ALIGN(size, sizeof(uint32_t));
	if (size > info->param_size)
		return FAILURE;

	ptr = (struct en_ehash_insert_l3_hdr *)info->paramptr;
	switch (info->l3_info.mode) {
		case TNL_MODE_4O6:
			word = (TYPE_4o6 << 24);		
			memcpy(&ptr->l3hdr[0], &info->l3_info.header_v6, 
				info->l3_info.header_size);
			break;
		case TNL_MODE_6O4:
			word = (TYPE_6o4 << 24);		
			memcpy(&ptr->l3hdr[0], &info->l3_info.header_v4, 
				info->l3_info.header_size);
			break;
		default:
			//other types to be supported later
			return FAILURE;
	}
	word |= ((info->l3_info.header_size << 16) | IPID_STARTVAL);
	//TODO:QOS, CCS, DF, not handled now
	ptr->word = cpu_to_be32(word);
	//TODO: routing destination offset is now 0
	word = 0;
#ifdef INCLUDE_TUNNEL_IFSTATS
	{
		uint8_t offset;
		PCtEntry ctentry;

		ctentry = info->entry;
		if (dpa_get_tunnel_iface_stats_entries(ctentry->pRtEntry->itf,
                        &offset, RX_IFSTATS)) {
                       	DPA_ERROR("%s::unable to get stats offset on tunnel iface on ingress\n",
                        	__FUNCTION__);
                        return FAILURE;
		}
		word |= ((get_logical_ifstats_base() +
                                (offset * sizeof(struct en_ehash_stats))) & 0xffffff);
#ifdef CDX_DPA_DEBUG
                DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, (word & 0xffffff));
#endif
	}
#endif
	ptr->word_1 = cpu_to_be32(word);
	*(info->opcptr) = INSERT_L3_HDR;
	info->opcptr++;
	info->opc_count--;
	info->param_size -= size;
	info->paramptr += size;
	return SUCCESS;
}

static int create_tunnel_remove_hm(struct ins_entry_info *info)
{
	PCtEntry ctentry;
	uint32_t stats_ptr;
	struct en_ehash_remove_first_ip_hdr *param;

	if (info->opc_count == MAX_OPCODES)
                return FAILURE;
	if (sizeof(struct en_ehash_remove_first_ip_hdr) > info->param_size)
		return FAILURE;
	ctentry = info->entry;
	param = (struct en_ehash_remove_first_ip_hdr *)info->paramptr;
#ifdef INCLUDE_TUNNEL_IFSTATS
	{
		uint8_t offset;

		if (dpa_get_tunnel_iface_stats_entries(ctentry->pRtEntry->input_itf,
                        &offset, RX_IFSTATS)) {
                       	DPA_ERROR("%s::unable to get stats offset on tunnel iface on ingress\n",
                        	__FUNCTION__);
                        return FAILURE;
		}
		stats_ptr = (get_logical_ifstats_base() +
                                (offset * sizeof(struct en_ehash_stats)));
                DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, stats_ptr);
	}
#else
	stats_ptr = 0;
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//update opcode and param ptr
	*(info->opcptr) = REMOVE_FIRST_IP_HDR;
	info->opcptr++;
	info->opc_count--;
	info->param_size -= sizeof(struct en_ehash_remove_first_ip_hdr);
	info->paramptr += sizeof(struct en_ehash_remove_first_ip_hdr);
	return SUCCESS;
}
static int create_eth_rx_stats_hm(struct ins_entry_info *info)
{
#ifdef INCLUDE_ETHER_IFSTATS
	PCtEntry ctentry;
	uint8_t offset;
	uint32_t stats_ptr;
	struct en_ehash_update_ether_rx_stats *param;

	if (info->opc_count == MAX_OPCODES)
                return FAILURE;
	if (sizeof(struct en_ehash_update_ether_rx_stats) > info->param_size)
		return FAILURE;
	ctentry = info->entry;
	param = (struct en_ehash_update_ether_rx_stats *)info->paramptr;

	if (dpa_get_ether_iface_stats_entries(ctentry->pRtEntry->input_itf,
			ctentry->pRtEntry->underlying_input_itf,
                        &offset, RX_IFSTATS)) {
        	DPA_ERROR("%s::unable to get stats offset on ethernet iface on ingress\n",
                	__FUNCTION__);
                return FAILURE;
	}
	stats_ptr = (get_logical_ifstats_base() +
                                (offset * sizeof(struct en_ehash_stats)));
#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, stats_ptr);
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//update opcode and param ptr
	*(info->opcptr) = UPDATE_ETH_RX_STATS;
	info->opcptr++;
	info->opc_count--;
	info->param_size -= sizeof(struct en_ehash_update_ether_rx_stats);
	info->paramptr += sizeof(struct en_ehash_update_ether_rx_stats);
#endif
	return SUCCESS;
}

static int cdx_rtpflow_create_eth_rx_stats_hm(
					struct ins_entry_info *info, PRouteEntry pRtEntry)
{
#ifdef INCLUDE_ETHER_IFSTATS
	uint8_t offset;
	uint32_t stats_ptr;
	struct en_ehash_update_ether_rx_stats *param;

	if (info->opc_count == MAX_OPCODES)
                return FAILURE;
	if (sizeof(struct en_ehash_update_ether_rx_stats) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_update_ether_rx_stats *)info->paramptr;

	if (dpa_get_ether_iface_stats_entries(pRtEntry->input_itf,
			pRtEntry->underlying_input_itf,
                        &offset, RX_IFSTATS))
	{
		DPA_ERROR("%s::unable to get stats offset on ethernet iface on ingress\n",
                	__FUNCTION__);
		return FAILURE;
	}
	stats_ptr = (get_logical_ifstats_base() +
                                (offset * sizeof(struct en_ehash_stats)));
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, stats_ptr);
#endif
	param->stats_ptr = cpu_to_be32(stats_ptr);
	//update opcode and param ptr
	*(info->opcptr) = UPDATE_ETH_RX_STATS;
	info->opcptr++;
	info->opc_count--;
	info->param_size -= sizeof(struct en_ehash_update_ether_rx_stats);
	info->paramptr += sizeof(struct en_ehash_update_ether_rx_stats);
#endif
	return SUCCESS;
}


static int create_enque_hm(struct ins_entry_info *info)
{
	struct en_ehash_enqueue_param *param;
	uint32_t tmp;

	if (info->l2_info.mtu == 0) {
		DPA_ERROR("%s::mtu is null\n", __FUNCTION__);
		return FAILURE;
	}
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_enqueue_param) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_enqueue_param *)info->paramptr;
	param->mtu = cpu_to_be16(info->l2_info.mtu);
	//param->bpid = cpu_to_be16(frag_info_g.frag_bp_id);
	param->bpid = frag_info_g.frag_bp_id;
#if 0
{
int ii;
	struct bm_buffer bmb[128];
for (ii =0; ii< 128; ii++)
{
	if (bman_acquire(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0) != 1) {
	DPA_INFO("%s(%d) bman_acquire failed \n", __FUNCTION__,__LINE__);
		bmb[ii].addr = 0;
	}
	else
	{
		DPA_INFO("%s(%d) bman_acquire success (ii %d) ,%lx \n", 
			__FUNCTION__,__LINE__,ii,(long unsigned int)bmb[ii].opaque);
	}
}
for (ii =0; ii< 128; ii++)
{
if (bmb[ii].addr)
	bman_release(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0);
}

}
#endif // 0
	tmp = XX_VirtToPhys(frag_info_g.muram_frag_params);
	param->muram_frag_param_addr = (uint32_t)cpu_to_be32(tmp);
	if(info->to_sec_fqid) {
		param->fqid = cpu_to_be32(info->to_sec_fqid);
	} else {
		param->fqid = cpu_to_be32(info->l2_info.fqid);
	}
#ifdef INCLUDE_ETHER_IFSTATS
	{
		uint8_t offset;
		uint32_t word;

		offset = info->l2_info.ether_stats_offset;
                word = ((get_logical_ifstats_base() +
                               (offset * sizeof(struct en_ehash_stats))) & 0xffffff);
		param->stats_ptr = cpu_to_be32(word);
#ifdef CDX_DPA_DEBUG
                DPA_INFO("%s::stats ptr %x\n", __FUNCTION__, (word & 0xffffff));
#endif
	}
#else
	param->stats_ptr = 0;
#endif
	*(info->opcptr) = ENQUEUE_PKT;
	info->opcptr++;
	info->param_size -= sizeof(struct en_ehash_enqueue_param);
	info->paramptr += sizeof(struct en_ehash_enqueue_param);
	return SUCCESS;
}

static int create_rtprelay_process_opcode(struct ins_entry_info *info, 
				uint32_t *in_sockstats_ptr, uint32_t *rtpinfo_ptr,
				uint32_t *out_sockstats_ptr, uint8_t opcode)
{
	struct en_ehash_rtprelay_param *param;
	uint32_t ptr_val;
	
	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_rtprelay_param) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_rtprelay_param *)info->paramptr;
	ptr_val = PTR_TO_UINT(rtpinfo_ptr);
	param->rtpinfo_ptr =  cpu_to_be32(ptr_val);
	ptr_val = PTR_TO_UINT(in_sockstats_ptr);
	param->in_sock_stats_ptr =  cpu_to_be32(ptr_val);
	ptr_val = PTR_TO_UINT(out_sockstats_ptr);
	param->out_sock_stats_ptr =  cpu_to_be32(ptr_val);
	*(info->opcptr) = opcode;
	info->opcptr++;
	info->param_size -= sizeof(struct en_ehash_rtprelay_param);
	info->paramptr += sizeof(struct en_ehash_rtprelay_param);
	return SUCCESS;
}

static int create_replicate_hm(struct ins_entry_info *info)
{
	struct en_ehash_replicate_param *param;

	if (info->opc_count == MAX_OPCODES)
		return FAILURE;
	if (sizeof(struct en_ehash_replicate_param) > info->param_size)
		return FAILURE;
	param = (struct en_ehash_replicate_param *)info->paramptr;
	param->first_member_flow_addr_hi = info->first_member_flow_addr_hi;
	param->first_member_flow_addr_lo = info->first_member_flow_addr_lo;
	param->first_listener_entry =  info->first_listener_entry;
	*(info->opcptr) = REPLICATE_PKT;
	info->opcptr++;
    info->param_size -= 8;
	info->paramptr += 8;
	return SUCCESS;
}

int fill_ipsec_actions(PSAEntry entry, struct ins_entry_info *info, 
			uint32_t sa_dir_in)
{
	uint32_t ii;
	uint32_t rebuild_l2_hdr;

	if (sa_dir_in)
        {
                //strip vlan on ingress if incoming iface is vlan
                if (info->l2_info.vlan_present)
                        info->flags |= VLAN_STRIP_HM_VALID;
                //strip pppoe on ingress if incoming iface is pppoe
                if (info->l2_info.pppoe_present)
                        info->flags |= PPPoE_STRIP_HM_VALID;
        } else {
                //routing and ttl decr are mandatory
                info->flags = (ETHERNET_HM_VALID | TTL_HM_VALID);

                if (info->l2_info.num_egress_vlan_hdrs ) {
                        info->flags |= VLAN_ADD_HM_VALID;
			for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
	                        info->vlan_ids[ii] =
        	                        (info->l2_info.egress_vlan_hdrs[ii].tci);
			}
                }

        }

	if (L3_HDR_OPS(info->l3_info))
        {
	        /*  Addition of IP header requires the header to be inserted at
        	* the start of the packet. So we need to strip and rebuild the
        	* l2 header after tunnel header insertion. */
                rebuild_l2_hdr = 1;
        } else 
		rebuild_l2_hdr = 0;

	if(!sa_dir_in) {
		//insert L2 hdr
		info->eth_type = (entry->family == PROTO_IPV4) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
		info->l2_info.add_eth_type = 1;
		if (create_routing_hm(info)) {
                        DPA_ERROR("%s::failed to create insert L2 HM\n",
                                        __FUNCTION__);
                        	return FAILURE;
                }
                //deal with pppoe header insertion
                if (info->l2_info.add_pppoe_hdr) {
                        if (create_pppoe_ins_hm(info)) {
                                DPA_ERROR("%s::failed to create pppoe insert HM\n",
                                        __FUNCTION__);
                        	return FAILURE;
                        }
                }
		//insert tunnel header
                if (info->l3_info.add_tnl_header) {
                        if (create_tunnel_insert_hm(info)) {
                                DPA_ERROR("%s::failed to create tunnel insert HM\n",
                                        __FUNCTION__);
                        	return FAILURE;
                        }
                }
                //hmd for ttl decrement
                if (info->flags & TTL_HM_VALID) {
                        if (create_ttl_hm(info)) {
                                DPA_ERROR("%s::failed to create ttl decr HM\n",
                                        __FUNCTION__);
                        	return FAILURE;
                        }
                }
	} else {		

#if 0 //def INCLUDE_ETHER_IFSTATS
		//update fast path ethernet stats
		if (create_eth_rx_stats_hm(info)) {
                	DPA_ERROR("%s::unable to add ethernet stats\n",
                                        __FUNCTION__);
                        return FAILURE;
		}
#endif
		//remove tunnel header
		if (info->l3_info.tnl_header_present) {
                        if (create_tunnel_remove_hm(info)) {
                                DPA_ERROR("%s::unable to add tunnel rmv manip\n",
                                        __FUNCTION__);
                        	return FAILURE;
                        }
                }

                //strip vlan headers in the ingress packet
                if (info->l2_info.vlan_present) {
                        if (insert_remove_vlan_hm(info)) {
                                DPA_ERROR("%s::unable to add vlan rmv manip\n",
                                        __FUNCTION__);
                        	return FAILURE;
                        }
                }
                //strip pppoe headers in the ingress packet
                if (info->l2_info.pppoe_present) {
                        if (create_pppoe_remove_hm(info)) {
                                DPA_ERROR("%s::unable to add pppoe rmv manip\n",
                                        __FUNCTION__);
                        	return FAILURE;
                        }
                }
	}
	//enqueue
	info->enqueue_params = info->paramptr;
        if(create_enque_hm(info)) {
        	DPA_ERROR("%s::unable to add enque hm\n",
                	__FUNCTION__);
                return FAILURE;
	}
	return SUCCESS;
}

struct en_exthash_tbl_entry* create_exthash_entry4mcast_member(RouteEntry *pRtEntry,
	struct ins_entry_info *pInsEntryInfo, MC4Output	*pListener, struct en_exthash_tbl_entry* prev_tbl_entry, 
	uint32_t tbl_type)
{
	POnifDesc onif_desc;
	int fm_idx, port_idx;
	struct dpa_l2hdr_info *pL2Info;
	struct dpa_l3hdr_info *pL3Info;
	struct en_exthash_tbl_entry *tbl_entry = NULL;
	struct net_device *dev;
	uint64_t phyaddr;
	uint16_t flags;
	uint8_t *ptr;

	DPA_INFO("%s(%d) listener output device %s\n",__FUNCTION__,__LINE__,pListener->output_device_str);
	onif_desc = get_onif_by_name(pListener->output_device_str); 
	if (!onif_desc)
	{
		DPA_ERROR("%s::unable to get onif for iface %s\n", __FUNCTION__, pListener->output_device_str);
		goto err_ret;
	}

	
	DPA_INFO("%s(%d) onif_desc->itf->index %d\n",__FUNCTION__,__LINE__,onif_desc->itf->index);
	if(dpa_get_fm_port_index(onif_desc->itf->index,0, &fm_idx, &port_idx, &pInsEntryInfo->port_id))
	{
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",__FUNCTION__, onif_desc->itf->index);
		goto err_ret;
	}
	
	DPA_INFO("%s(%d) fm_idx %d, port_idx %d, port_id %d\n",__FUNCTION__,__LINE__,fm_idx, port_idx, pInsEntryInfo->port_id);
	pInsEntryInfo->fm_pcd = dpa_get_pcdhandle(fm_idx);
	if (!pInsEntryInfo->fm_pcd)
	{
	  DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",__FUNCTION__, fm_idx);
	  goto err_ret;
	} 

	DPA_INFO("%s(%d) fm_pcd %p \n",__FUNCTION__,__LINE__, pInsEntryInfo->fm_pcd);
	//get table descriptor based on type and port
	pInsEntryInfo->td = dpa_get_tdinfo(pInsEntryInfo->fm_idx, pInsEntryInfo->port_id, tbl_type);
	if (pInsEntryInfo->td == NULL) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
			__FUNCTION__, onif_desc->itf->index,tbl_type);
		goto err_ret;
	}
	DPA_INFO("%s(%d) td %p \n",__FUNCTION__,__LINE__, pInsEntryInfo->td);

	//Code to create hm for mcast single member
	
	pInsEntryInfo->fm_idx = fm_idx;
	pInsEntryInfo->port_idx = port_idx;
	pL2Info = &pInsEntryInfo->l2_info;
	pL3Info = &pInsEntryInfo->l3_info;


	//Code to get Tx fqid of given interface
	
	pRtEntry->itf = onif_desc->itf;
	pRtEntry->input_itf = onif_desc->itf;
	pRtEntry->underlying_input_itf =  pRtEntry->input_itf;
	
	//Using default queue for multicast packets
	if (dpa_get_tx_info_by_itf(pRtEntry, pL2Info, pL3Info, NULL, 1))
	{
		DPA_ERROR("%s::unable to get tx params\n",__FUNCTION__);
		goto err_ret;
	}
	DPA_INFO("dpa_get_tx_info_by_itf success\n");
	dev = dev_get_by_name(&init_net, pListener->output_device_str);
	if(dev == NULL)
	{
		goto err_ret;
	}
	dev_put(dev);

	pL2Info->mtu = dev->mtu;
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: mtu %d\n", __FUNCTION__, dev->mtu);
#endif
	
	//allocate hash table entry
	tbl_entry = ExternalHashTableAllocEntry(pInsEntryInfo->td);
	if (!tbl_entry) {
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",__FUNCTION__);
		goto err_ret;
	}

//#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
//#endif
	flags = 0;
	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	//set start of opcode list 
	pInsEntryInfo->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;

	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(pInsEntryInfo->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	pInsEntryInfo->paramptr = ptr;
	pInsEntryInfo->param_size = (MAX_EN_EHASH_ENTRY_SIZE - 
		GET_PARAM_OFFSET(flags));
	if (fill_mcast_member_actions(pRtEntry, pInsEntryInfo)) {
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, 0);
#endif // CDX_DPA_DEBUG
	phyaddr = XX_VirtToPhys(tbl_entry);
	//fill next pointer info and link into chain
	if (prev_tbl_entry)
	{
		prev_tbl_entry->next = tbl_entry;
		tbl_entry->prev = prev_tbl_entry;
		//adjust the prev pointer in the old entry
		//fill next pointer physaddr for uCode
		prev_tbl_entry->hashentry.next_entry_hi = cpu_to_be16((phyaddr >> 32) & 0xffff);
		prev_tbl_entry->hashentry.next_entry_lo = cpu_to_be32((phyaddr & 0xffffffff));
	}
	return tbl_entry;
err_ret:
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	return NULL;
}

static int fill_mcast_member_actions(RouteEntry *pRtEntry, struct ins_entry_info *info)
{
	uint32_t ii; 
	uint32_t rebuild_l2_hdr;
	//POnifDesc onif_desc;
	

#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: entry %p, opc_ptr %p, param_ptr %p, size %d\n", 
		__FUNCTION__, pRtEntry, info->opcptr, info->paramptr, info->param_size);
#endif
	
	//routing and ttl decr are mandatory
	//ttl decr handled as part of NAT-PT
	info->flags = ETHERNET_HM_VALID;

	if(L3_HDR_OPS(info->l3_info))
	/*  Addition of IP header requires the header to be inserted at the start of the packet.
	    So we need to strip and rebuild the l2 header after tunnel header insertion. */
		rebuild_l2_hdr = 1;
	else
		rebuild_l2_hdr = 0;

	DPA_INFO("%s(%d) rebuild_l2_hdr  %d\n",__FUNCTION__,__LINE__,rebuild_l2_hdr);
	if (info->l2_info.num_egress_vlan_hdrs) {
		DPA_INFO("%s(%d) num egress vlan hdrs %d\n",
			__FUNCTION__,__LINE__, info->l2_info.num_egress_vlan_hdrs);
		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	while(1) {
		if(rebuild_l2_hdr) {
			DPA_INFO("%s(%d) insert_opcodeonly_hm\n",__FUNCTION__,__LINE__);
       			 //Strip ethernet header
			if (insert_opcodeonly_hm(info, STRIP_ETH_HDR))
				break;
		} else {
			DPA_INFO("%s(%d) create_routing_hm\n",__FUNCTION__,__LINE__);
			//create routing header modification
			if (create_routing_hm(info))
				break;
		}
		if (info->l3_info.add_tnl_header) {
			DPA_INFO("%s(%d) create_tunnel_insert_hm\n",__FUNCTION__,__LINE__);
			if (create_tunnel_insert_hm(info)) 
				break;
		}
		if(rebuild_l2_hdr){
			DPA_INFO("%s(%d) create_ethernet_insert_hm\n",__FUNCTION__,__LINE__);
			if(create_ethernet_insert_hm(info))
				break;
		}
		//enqueue
		DPA_INFO("%s(%d) create_enque_hm\n",__FUNCTION__,__LINE__);
		if(create_enque_hm(info))
			break;
		return SUCCESS;
	}
	return FAILURE;
}

int cdx_init_frag_procfs(void);
cdx_ucode_frag_info_t  *ucode_frag_args;
int cdx_init_frag_module(void)
{
	int ret;
	uint16_t frag_options;
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;


#ifdef CDX_FRAG_USE_BUFF_POOL
	ret = cdx_create_fragment_bufpool();
	if (ret)
	{
		DPA_ERROR("%s(%d) create_fragment_bufpool failed\n",__FUNCTION__,__LINE__);
		return -1;
	}
	frag_options = BPID_ENABLE;
#endif //CDX_FRAG_USE_BUFF_POOL

	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif //CDX_FRAG_USE_BUFF_POOL
		return -1;
	}

	//frag_info_g.muram_frag_params_addr = FM_MURAM_AllocMem(h_FmMuram,
	frag_info_g.muram_frag_params = (cdx_ucode_frag_info_t *)FM_MURAM_AllocMem(h_FmMuram,
			 sizeof(cdx_ucode_frag_info_t) , 32);
	ucode_frag_args =  frag_info_g.muram_frag_params;
	if (!ucode_frag_args)
	{
#ifdef CDX_FRAG_USE_BUFF_POOL
		cdx_deinit_fragment_bufpool();
#endif //CDX_FRAG_USE_BUFF_POOL
		return -1;
	}	

	ucode_frag_args->alloc_buff_failures = 0;
	ucode_frag_args->v4_frames_counter = 0;
	ucode_frag_args->v6_frames_counter = 0;
	ucode_frag_args->v6_frags_counter = 0;
	ucode_frag_args->v4_frags_counter = 0;
	ucode_frag_args->v6_identification = cpu_to_be32(1);
	frag_options |= OPT_COUNTER_EN;
	ucode_frag_args->frag_options = cpu_to_be16(frag_options); 

	cdx_init_frag_procfs();
	return 0;
}

#define PROC_FRAG_DIR "ucode_frag"
struct file_operations frag_stats_fp;
struct file_operations buf_alloc_test_fp;

static struct proc_dir_entry *frag_proc_dir, *stats_file, *alloc_free_test_file;

ssize_t stats_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	int  tot_len = 0;
	
	if (*ppos)
		return 0;

	tot_len += sprintf(buf+tot_len, "IPv4 frames received : %u\n", be32_to_cpu(ucode_frag_args->v4_frames_counter));
	tot_len += sprintf(buf+tot_len, "IPv6 frames received : %u\n", be32_to_cpu(ucode_frag_args->v6_frames_counter));
	tot_len += sprintf(buf+tot_len, "Number of IPv4 fragments sent : %u\n", be32_to_cpu(ucode_frag_args->v4_frags_counter));
	tot_len += sprintf(buf+tot_len, "Number of IPv6 fragments sent : %u\n", be32_to_cpu(ucode_frag_args->v6_frags_counter));
	tot_len += sprintf(buf+tot_len, "Failures in allocating buffers: %u\n", be32_to_cpu(ucode_frag_args->alloc_buff_failures));
	*ppos += tot_len;
//	return 0;
	return tot_len;
}


ssize_t buff_alloc_test(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
int ii;
	struct bm_buffer bmb[128];
	if (*ppos)
		return 0;

for (ii =0; ii< 128; ii++)
{
	if (bman_acquire(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0) != 1) {
	DPA_INFO("%s(%d) bman_acquire failed \n", __FUNCTION__,__LINE__);
		bmb[ii].addr = 0;
	}
	else
	{
		DPA_INFO("%s(%d) bman_acquire success (ii %d) ,%lx \n", 
			__FUNCTION__,__LINE__,ii,(long unsigned int)bmb[ii].opaque);
	}
}
for (ii =0; ii< 128; ii++)
{
if (bmb[ii].addr)
	bman_release(frag_info_g.frag_bufpool->pool, &bmb[ii], 1, 0);
}
	ii = sprintf(buf, "128 buffers allocated and freed successfully\n");
	*ppos += ii;
	return ii;
}



int cdx_init_frag_procfs(void)
{
	frag_proc_dir = proc_mkdir(PROC_FRAG_DIR, NULL);
	if (!frag_proc_dir)
	{
		DPA_INFO("%s(%d) proc_mkdir failed \n",__FUNCTION__,__LINE__);
		return -1;
	}
	memset (&frag_stats_fp, 0, sizeof(frag_stats_fp));
	memset (&buf_alloc_test_fp, 0, sizeof(buf_alloc_test_fp));
	frag_stats_fp.read = stats_read;
	
	stats_file = proc_create("stats", 0444, frag_proc_dir, &frag_stats_fp);
	if (!stats_file)
	{
		DPA_INFO("%s(%d) proc_create failed\n",__FUNCTION__,__LINE__);
		return -1;
	}

	buf_alloc_test_fp.read = buff_alloc_test;
	alloc_free_test_file = proc_create("test_alloc_buf_n_free", 0444, frag_proc_dir, &buf_alloc_test_fp);
        if (!alloc_free_test_file)
        {
                DPA_INFO("%s(%d) proc_create failed\n",__FUNCTION__,__LINE__);
                return -1;
        }

	return 0;
}

void cdx_deinit_frag_module(void)
{
	t_Handle h_FmMuram;
	uint64_t physicalMuramBase;
	uint32_t MuramSize;
#ifdef CDX_FRAG_USE_BUFF_POOL
	cdx_deinit_fragment_bufpool();
#endif //CDX_FRAG_USE_BUFF_POOL
	h_FmMuram = dpa_get_fm_MURAM_handle(0, &physicalMuramBase, &MuramSize);
	if (!h_FmMuram)
	{
		DPA_ERROR("%s(%d) Error in getting MURAM handle\n", __FUNCTION__,__LINE__);
		return;
	}
	//FM_MURAM_FreeMem(h_FmMuram, (void *)frag_info_g.muram_frag_params_addr);
	FM_MURAM_FreeMem(h_FmMuram, (void *)frag_info_g.muram_frag_params);
	frag_info_g.muram_frag_params = NULL;
	//frag_info_g.muram_frag_params_addr = 0;
	return;
}

static int cdx_create_fragment_bufpool(void)
{
	struct dpa_bp *bp, *bp_parent;
	int buffer_count = 0, ret = 0, refill_cnt ;

	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPA_ERROR("%s::failed to allocate mem for bman pool \n",
				__FUNCTION__);
		return -1;
	}
	
	bp->size = CDX_FRAG_BUFF_SIZE;
	bp->config_count = CDX_FRAG_BUFFERS_CNT;

	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(CDX_FRAG_BUFF_SIZE, &frag_info_g.parent_pool_info)) {
                DPA_ERROR("%s::failed to locate eth bman pool\n", 
				__FUNCTION__);
		bman_free_pool(bp->pool);
		kfree(bp);
        	return -1;
	}

	bp_parent = dpa_bpid2pool(frag_info_g.parent_pool_info.pool_id);
	bp->dev = bp_parent->dev;
        if (dpa_bp_alloc(bp, bp->dev)) {
                DPA_ERROR("%s::dpa_bp_alloc failed\n",
                                __FUNCTION__);
                kfree(bp);
                return -1;
        }
        DPA_INFO("%s::bp->size :%zu\n", __FUNCTION__, bp->size);


	frag_info_g.frag_bufpool = bp;
	frag_info_g.frag_bp_id = bp->bpid;

	while (buffer_count < CDX_FRAG_BUFFERS_CNT)
	{
		refill_cnt = 0;
		ret = dpaa_eth_refill_bpools(bp, &refill_cnt);
		if (ret < 0)
		{
			DPA_ERROR("%s:: Error returned for dpaa_eth_refill_bpools %d\n", __FUNCTION__,ret);
			break;
		}

		buffer_count += refill_cnt;
	}
	bp->config_count = buffer_count;

	DPA_INFO("%s::buffers_allocated %d\n", __FUNCTION__,bp->config_count);
	return 0;
}

void cdx_deinit_fragment_bufpool()
{
	if (frag_info_g.frag_bufpool)
	{
		drain_bp_pool(frag_info_g.frag_bufpool);
		frag_info_g.frag_bufpool = NULL;
		frag_info_g.frag_bp_id = 0;
	}
	return;
}

int cdx_check_rx_iface_type_vlan(struct _itf *input_itf);
static int cdx_rtpflow_fill_actions(PSockEntry pFromSocket, PSockEntry pToSocket,
						PRTPflow pFlow, struct ins_entry_info *info)
{
	uint32_t ii; 
	uint32_t rebuild_l2_hdr;
	uint8_t opcode;
	

#ifdef CDX_DPA_DEBUG
	DPA_INFO(" opc_ptr %p, param_ptr %p, size %d dport %d , (pToSocket->Dport mod 2) %d\n", 
		 info->opcptr, info->paramptr, info->param_size,
		htons(pToSocket->Dport), (htons(pToSocket->Dport) % 2));
#endif


	//routing and ttl decr are mandatory
	//ttl decr handled as part of NAT-PT
	info->flags = ETHERNET_HM_VALID;

	//mask it as ipv6 flow if required
	if (pFromSocket->SocketFamily == PROTO_IPV6)
		info->flags |= EHASH_IPV6_FLOW;
	// setting TTL bit
	info->flags |= TTL_HM_VALID;

	//strip vlan on ingress if incoming iface is vlan
//	if (info->l2_info.vlan_present)
	if (cdx_check_rx_iface_type_vlan(pFromSocket->pRtEntry->itf))
		info->flags |= VLAN_STRIP_HM_VALID;

	//strip pppoe on ingress if incoming iface is pppoe 
	if (info->l2_info.pppoe_present)
		info->flags |= PPPoE_STRIP_HM_VALID;

	// assumption : no tunneling
	rebuild_l2_hdr = 0;

	//TODO IPSEC for RTP relay traffic
#ifdef TODO_IPSEC
	if((entry->status & CONNTRACK_SEC) && (!info->to_sec_fqid)){ 
		info->eth_type  = (IS_IPV4(entry)) ? htons(ETHERTYPE_IPV4) : htons(ETHERTYPE_IPV6);
		info->l2_info.add_eth_type = 1;
	}
#endif // TODO_IPSEC

	//Not expecting NATPT for rtp-relay traffic
	info->flags |= NAT_HM_REPLACE_SPORT;
	info->flags |= NAT_HM_REPLACE_DPORT;
	info->flags |= NAT_HM_REPLACE_SIP;
	info->flags |= NAT_HM_REPLACE_DIP;
	switch(pFromSocket->proto) 
	{
		case IPPROTOCOL_TCP:
		case IPPROTOCOL_UDP:
			info->nat_sport = pToSocket->Dport;
			info->nat_dport = pToSocket->Sport;
			break;
		default:
			break; 
	}

	//ip replacement have to be done
	//nat sip if required

	if (pFromSocket->SocketFamily == PROTO_IPV6)
	{
		memcpy(info->v6.nat_sip, pToSocket->Daddr_v6 ,IPV6_ADDRESS_LENGTH);
		memcpy(info->v6.nat_dip, pToSocket->Saddr_v6 ,IPV6_ADDRESS_LENGTH);
	}
	else 
	{
		info->v4.nat_sip = pToSocket->Daddr_v4;
		info->v4.nat_dip = pToSocket->Saddr_v4;
	}
	if (info->l2_info.num_egress_vlan_hdrs)
	{

		info->flags |= VLAN_ADD_HM_VALID;
		for (ii = 0; ii < info->l2_info.num_egress_vlan_hdrs; ii++) {
			info->vlan_ids[ii] =
				(info->l2_info.egress_vlan_hdrs[ii].tci);
		}
	}
	//fill all opcodes and parameters
	while(1)
	{
#ifdef INCLUDE_ETHER_IFSTATS
		DPA_INFO("%s(%d) calling cdx_rtpflow_create_eth_rx_stats_hm\n",
		  __FUNCTION__, __LINE__);
		
		if (cdx_rtpflow_create_eth_rx_stats_hm(info, pFromSocket->pRtEntry)) 
			break;
#endif
		if (info->l2_info.pppoe_present)
		{
			DPA_INFO("%s(%d) \n",
			  __FUNCTION__, __LINE__);
			//strip pppoe hdrs
			if (insert_remove_pppoe_hm(info))
				break;
		}
		if (cdx_check_rx_iface_type_vlan(pFromSocket->pRtEntry->itf))
		{
			DPA_INFO("%s(%d) \n",
			  __FUNCTION__, __LINE__);
			//strip vlan hdrs
			if (cdx_rtprelay_insert_remove_vlan_hm(info, pFromSocket->pRtEntry))
				break;
		}
		// create RTP_PROCESS opcode
		pFlow->hw_flow->ehash_rtp_relay_params =  info->paramptr;
		if ((htons(pToSocket->Dport)) % 2)
			opcode = PROCESS_RTCP_PAYLOAD;
		else
			opcode = PROCESS_RTP_PAYLOAD;

		DPA_INFO("%s(%d) opcode %x \n",
		  __FUNCTION__, __LINE__, opcode);

		if (create_rtprelay_process_opcode(info, pFromSocket->hw_stats, 
							(uint32_t *)pFlow->hw_flow->rtp_info,
							pToSocket->hw_stats, opcode))
		{
			DPA_ERROR("%s(%d) create_rtprelay_process_opcode failed\n",__FUNCTION__, __LINE__);
			break;
		}
		DPA_INFO("%s(%d) \n",
		  __FUNCTION__, __LINE__);
		//create routing header modification
		if (create_routing_hm(info))
			break;
		DPA_INFO("%s(%d) \n",
		  __FUNCTION__, __LINE__);
		if (info->l2_info.num_egress_vlan_hdrs)
			pFlow->hw_flow->vlan_hdr_ptr = info->vlan_hdrs;
		pFlow->hw_flow->num_vlan_hdrs = info->l2_info.num_egress_vlan_hdrs;
		if(create_nat_hm(info))
			break;
		//may need only TTL hm
		if (info->flags & TTL_HM_VALID)
		{
			if (info->flags & EHASH_IPV6_FLOW) 
			{
				DPA_INFO("%s(%d) \n",
				  __FUNCTION__, __LINE__);
				if (create_hoplimit_hm(info))
					break;
			} 
			else
			{
				DPA_INFO("%s(%d) \n",
				  __FUNCTION__, __LINE__);
				if (create_ttl_hm(info))
					break;
			}
		}
		//enqueue
		DPA_INFO("%s(%d) \n",
		  __FUNCTION__, __LINE__);
		info->enqueue_params = info->paramptr;
		if(create_enque_hm(info))
			break;
		return SUCCESS;
	}
	return FAILURE;
}

static int get_rtp_classif_table_type(PSockEntry pSocket, uint32_t *type)
{
	switch (pSocket->proto) {
		case IPPROTOCOL_TCP:
			if (pSocket->SocketFamily == PROTO_IPV4)
			{
				if (!pSocket->unconnected)
					*type = IPV4_TCP_TABLE;
				else
					*type = IPV4_3TUPLE_TCP_TABLE;
			}
			else
			{
				if (!pSocket->unconnected)
					*type = IPV6_TCP_TABLE;
				else
					*type = IPV6_3TUPLE_TCP_TABLE;
			}
			return SUCCESS;
			
		case IPPROTOCOL_UDP:
			if (pSocket->SocketFamily == PROTO_IPV4)
			{
				if (!pSocket->unconnected)
					*type = IPV4_UDP_TABLE;
				else
					*type = IPV4_3TUPLE_UDP_TABLE;
			}
			else
			{
				if (!pSocket->unconnected)
					*type = IPV6_UDP_TABLE;
				else
					*type = IPV6_3TUPLE_UDP_TABLE;
			}
			return SUCCESS;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, pSocket->proto);
			break;
	}
	return FAILURE;
}

static int cdx_rtpflow_fill_key_info(PSockEntry pSocket, uint8_t *keymem, uint32_t port_id)
{
	union dpa_key *key;
	unsigned char *saddr, *daddr;
	int i;
	uint32_t key_size;

	key = (union dpa_key *)keymem;
	//portid added to key
	key->portid = port_id;
	switch (pSocket->SocketFamily) {
		case PROTO_IPV4: 
			if (pSocket->unconnected) // unconnected, key = daddr + proto + dport
			{
				key_size = (sizeof(struct ipv4_3tuple_tcpudp_key) + 1);
				key->ipv4_3tuple_tcpudp_key.ipv4_daddr = pSocket->Daddr_v4;
				key->ipv4_3tuple_tcpudp_key.ipv4_protocol = pSocket->proto;
				key->ipv4_3tuple_tcpudp_key.ipv4_dport = pSocket->Dport;
			}
			else
			{

				key_size = (sizeof(struct ipv4_tcpudp_key) + 1);
				key->ipv4_tcpudp_key.ipv4_saddr = pSocket->Saddr_v4;
				key->ipv4_tcpudp_key.ipv4_daddr = pSocket->Daddr_v4;
				key->ipv4_tcpudp_key.ipv4_protocol = pSocket->proto;
				key->ipv4_tcpudp_key.ipv4_sport = pSocket->Sport;
				key->ipv4_tcpudp_key.ipv4_dport = pSocket->Dport;
			}
			break;

		case PROTO_IPV6:
			// in case of connected , key will have 5 tuples, 
			// in case of unconnected, key will have only 3 tuples
			if (!pSocket->unconnected)
			{
				saddr = (unsigned char*)pSocket->Saddr_v6;
				daddr = (unsigned char*)pSocket->Daddr_v6;
				key_size = (sizeof(struct ipv6_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key->ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_tcpudp_key.ipv6_protocol = pSocket->proto;
				key->ipv6_tcpudp_key.ipv6_sport = pSocket->Sport;
				key->ipv6_tcpudp_key.ipv6_dport = pSocket->Dport;
			}
			else
			{
				daddr = (unsigned char*)pSocket->Daddr_v6;
				key_size = (sizeof(struct ipv6_3tuple_tcpudp_key) + 1);
				for (i = 0; i < 16; i++)
					key->ipv6_3tuple_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key->ipv6_3tuple_tcpudp_key.ipv6_protocol = pSocket->proto;
				key->ipv6_3tuple_tcpudp_key.ipv6_dport = pSocket->Dport;
			}
			break;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, pSocket->proto);
			key_size = 0;
	}
#ifdef CDX_DPA_DEBUG
	if (key_size) {
		DPA_INFO("keysize %d\n", key_size);
		display_buf(key, key_size);
	}
#endif
	return key_size;
}

//display socket entries
void display_SockEntries(PSockEntry SockA, PSockEntry SockB)
{
	printk("SockA unconnected \t%x SockB unconnected \t%x\n\n", SockA->unconnected, SockB->unconnected);
	if (SockA->SocketFamily == PROTO_IPV6) {
		printk("SOCK_A ipv6 entry\n");
		printk("source ip	\t");
		display_ipv6_addr((uint8_t *)SockA->Saddr_v6);
		printk("dest ip		\t");
		display_ipv6_addr((uint8_t *)SockA->Daddr_v6);
		
		printk("SOCK_B ipv6 entry\n");
		printk("source ip	\t");
		display_ipv6_addr((uint8_t *)SockB->Saddr_v6);
		printk("dest ip		\t");
		display_ipv6_addr((uint8_t *)SockB->Daddr_v6);
	} else {
		printk("SOCK_A ipv4 entry\n");
		printk("source ip	\t");
		display_ipv4_addr(SockA->Saddr_v4);
		printk("dest ip		\t");
		display_ipv4_addr(SockA->Daddr_v4);
		printk("SOCK_B ipv4 entry\n");
		printk("source ip	\t");
		display_ipv4_addr(SockB->Saddr_v4);
		printk("dest ip		\t");
		display_ipv4_addr(SockB->Daddr_v4);
	}
	if ((SockA->proto == IPPROTOCOL_UDP) ||
	    (SockA->proto == IPPROTOCOL_TCP)) {
		printk("SOCK_A protocol	\t%d\n", SockA->proto);
		printk("SOCK_A sport		\t%d\n", htons(SockA->Sport));
		printk("SOCK_A dport		\t%d\n", htons(SockA->Dport));
		printk("SOCK_B protocol	\t%d\n", SockA->proto);
		printk("SOCK_B sport		\t%d\n", htons(SockA->Sport));
		printk("SOCK_B dport		\t%d\n", htons(SockA->Dport));
	}
	printk("SOCK_A Route entry	\t%p\n", SockA->pRtEntry);
	if (SockA->pRtEntry) {
		display_route_entry(SockA->pRtEntry);
	}
	else
	{
		printk("No route entry\n");
	}
	printk("SOCK_B Route entry	\t%p\n", SockB->pRtEntry);
	if (SockB->pRtEntry)
	{
		display_route_entry(SockB->pRtEntry);
	}
	else 
	{
		printk("No route entry\n");
	}
	printk(">>>>>\n");
}
EXPORT_SYMBOL(display_SockEntries);

int cdx_create_rtp_conn_in_classif_table (PRTPflow pFlow, PSockEntry pFromSocket, PSockEntry pToSocket)
{
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	struct _itf *underlying_input_itf;
	uint32_t tbl_type;
	uint16_t flags;
	uint32_t key_size;
	uint8_t *ptr;
	int retval;
	
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
	display_SockEntries(pFromSocket, pToSocket);
#endif
	
	tbl_entry = NULL;	
	
	if (!pFromSocket->pRtEntry)
	{
		DPA_INFO("%s(%d)\n",__FUNCTION__,__LINE__);
		return FAILURE;
	}

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info)
		return FAILURE;
	
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
	info->entry = pFlow;

	// This can never be NULL for connection routes.
	if (pFromSocket->pRtEntry->underlying_input_itf)
		underlying_input_itf = pFromSocket->pRtEntry->underlying_input_itf;
	else
	{
		underlying_input_itf = pFromSocket->pRtEntry->itf ;
		pFromSocket->pRtEntry->underlying_input_itf = pFromSocket->pRtEntry->itf;
	}

	if (!pFromSocket->pRtEntry->input_itf)
		pFromSocket->pRtEntry->input_itf = pFromSocket->pRtEntry->itf;
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);

	//clear hw entry pointer
	if ((!pFromSocket->pRtEntry) || ( (!pFromSocket->pRtEntry->input_itf) 
		&& (!pFromSocket->pRtEntry->itf)))
	{
		DPA_ERROR("%s(%d)::unable to get interface \n",__FUNCTION__,
						__LINE__);
		return FAILURE;
	}
	if (!pFromSocket->pRtEntry->input_itf) 
		pFlow->inPhyPortNum = pFromSocket->pRtEntry->itf->index;
	else
		pFlow->inPhyPortNum = pFromSocket->pRtEntry->input_itf->index;

	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
	//get fman index and port index and port id where this entry need to be added
	if (dpa_get_fm_port_index(pFlow->inPhyPortNum, underlying_input_itf->index, &info->fm_idx,
							&info->port_idx, &info->port_id))
	{
		DPA_ERROR("%s(%d)::unable to get fmindex for itfid %d\n",
						__FUNCTION__, __LINE__, pFlow->inPhyPortNum);
		goto err_ret;
	}
	DPA_INFO("%s(%d)\n", __FUNCTION__, __LINE__);
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s(%d) inPhyPortNum 0x%x, underlying_input_itf->index %d, fm_idx 0x%x, port_idx %d port_id %d\n",
			__FUNCTION__, __LINE__, pFlow->inPhyPortNum, underlying_input_itf->index,
			info->fm_idx, info->port_idx, info->port_id);
#endif // CDX_DPA_DEBUG
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd)
	{
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
									__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (get_rtp_classif_table_type(pFromSocket, &tbl_type))
	{
		DPA_ERROR("%s::unable to get table type\n",
									__FUNCTION__);
		goto err_ret;
	}
	info->tbl_type = tbl_type;
	
	//get table descriptor based on type and port based on incoming packet Socket A
	info->td = dpa_get_tdinfo(info->fm_idx, info->port_id, tbl_type);
	if (info->td == NULL)
	{
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
					__FUNCTION__, pFlow->inPhyPortNum,
					tbl_type);
		goto err_ret;
	}
#ifdef TODO_DPA_IPSEC_OFFLOAD
	/* if the connection is a secure one  and  SA direction is inbound
	 * then, we should add the entry into offline ports's classification
	 * table. cdx_ipsec_fill_sec_info()  will check for the SA direction
	 * and if it is inbound will replace the table id;
	 * if the SA is outbound direction then it will fill sec_fqid in the 
	 * info struture.  
	 */ 
	if(entry->status &	CONNTRACK_SEC)
	{
		if(cdx_ipsec_fill_sec_info(entry,info))
		{
			DPA_ERROR("%s::unable to get td for offline port, type %d\n",
							__FUNCTION__, info->tbl_type);
			goto err_ret;
		}
	}
#endif
	
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: td info :%p\n", __FUNCTION__, info->td);
#endif

	//save table descriptor for entry release
	pFlow->hw_flow->td = info->td;
	//get fm context
	pFlow->hw_flow->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (pFlow->hw_flow->fm_ctx == NULL)
	{
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
							__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	if (!pToSocket->pRtEntry)
	{
		DPA_ERROR("%s:: No route entry for to_socket \n",
			__FUNCTION__);
		goto err_ret;
	}
	if (!pToSocket->pRtEntry->input_itf)
	{
		DPA_INFO("%s(%d) pToSocket->pRtEntry->itf %p\n",
			__FUNCTION__, __LINE__, pToSocket->pRtEntry->itf);
		pToSocket->pRtEntry->input_itf =  pToSocket->pRtEntry->itf;
	}

	if (!pToSocket->pRtEntry->underlying_input_itf)
	{
		DPA_INFO("%s(%d) pToSocket->pRtEntry->itf %p\n",
			__FUNCTION__, __LINE__, pToSocket->pRtEntry->itf);
		pToSocket->pRtEntry->underlying_input_itf = pToSocket->pRtEntry->itf;
	}

	if (dpa_get_tx_info_by_itf(pToSocket->pRtEntry, &info->l2_info,
				&info->l3_info, NULL, pToSocket->queue))
	{
		DPA_ERROR("%s::unable to get tx params\n",
						__FUNCTION__);
		goto err_ret;
	}
	
	//allocate hash table entry
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s::info->td %p\n", __FUNCTION__, info->td);
#endif
	tbl_entry = ExternalHashTableAllocEntry(info->td);
	if (!tbl_entry)
	{
		DPA_ERROR("%s::unable to alloc hash tbl memory\n",
									__FUNCTION__);
		goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: hash tbl entry %p\n", __FUNCTION__, tbl_entry);
#endif
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
	SET_TIMESTAMP_ENABLE(flags);
	tbl_entry->hashentry.timestamp_counter = 
			cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
	pFlow->hw_flow->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
	SET_STATS_ENABLE(flags);
#endif
	//fill key information from entry
	key_size = cdx_rtpflow_fill_key_info(pFromSocket, &tbl_entry->hashentry.key[0], info->port_id);
	if (!key_size)
	{
		DPA_ERROR("%s::unable to compose key\n",
						__FUNCTION__);
		goto err_ret;
	}	
		
	//round off keysize to next 4 bytes boundary 
	ptr = (uint8_t *)&tbl_entry->hashentry.key[0];			
	ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
	//set start of opcode list 
	info->opcptr = ptr;
	//ptr now after opcode section
	ptr += MAX_OPCODES;
	
	//set offset to first opcode
	SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
	//set param offset 
	SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
	//param_ptr now points after timestamp location
	tbl_entry->hashentry.flags = cpu_to_be16(flags);
	//param pointer and opcode pointer now valid
	info->paramptr = ptr;
	info->param_size = (MAX_EN_EHASH_ENTRY_SIZE - GET_PARAM_OFFSET(flags));
	if (cdx_rtpflow_fill_actions(pFromSocket, pToSocket, pFlow, info))
	{
		DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
		goto err_ret;
	}
	tbl_entry->enqueue_params = info->enqueue_params;
	pFlow->hw_flow->eeh_entry_handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
	display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
	//insert entry into hash table
	retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry); 
	if (retval == -1) {
			DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
			goto err_ret;
	}	
	pFlow->hw_flow->eeh_entry_index = (uint16_t)retval;
	kfree(info);
	return SUCCESS;
err_ret:
	//release all allocated items
	if (tbl_entry)
		ExternalHashTableEntryFree(tbl_entry);
	kfree(info);
	return FAILURE;
}

void cdx_ehash_set_rtp_info_params(uint8_t *rtp_relay_param, PRTPflow pFlow, PSockEntry pSocket)
{
	struct en_ehash_rtprelay_param *param;
	uint16_t rtp_flags;
	
	param = (struct en_ehash_rtprelay_param *)rtp_relay_param;

	rtp_flags = 0;

	if (pSocket->unconnected == SOCKET_UNCONNECTED)
	{
		if (pSocket->SocketFamily == PROTO_IPV4)
		{
			param->src_ipv4_val = pSocket->Saddr_v4;
//			param->src_ipv4_val = cpu_to_be32(pSocket->Saddr_v4);
		}
		else
		{
			param->src_ipv6_val[0] = pSocket->Saddr_v6[0];
			param->src_ipv6_val[1] = pSocket->Saddr_v6[1];
			param->src_ipv6_val[2] = pSocket->Saddr_v6[2];
			param->src_ipv6_val[3] = pSocket->Saddr_v6[3];
//			param->src_ipv6_val[0] = cpu_to_be32(pSocket->Saddr_v6[0]);
	//		param->src_ipv6_val[1] = cpu_to_be32(pSocket->Saddr_v6[1]);
		//	param->src_ipv6_val[2] = cpu_to_be32(pSocket->Saddr_v6[2]);
			//param->src_ipv6_val[3] = cpu_to_be32(pSocket->Saddr_v6[3]);
		}
	}
	param->TimeStampIncr =  cpu_to_be32(pFlow->TimeStampIncr);
	param->seq_base =  cpu_to_be16(pFlow->Seq);
	param->egress_socketID = cpu_to_be16(pFlow->egress_socketID);
	param->DTMF_PT[0] =  gDTMF_PT[0];
	param->DTMF_PT[1] =  gDTMF_PT[1];
	param->SSRC_1 =  cpu_to_be32(pFlow->SSRC_1);
	if (pSocket->expt_flag == 1)
	{
		rtp_flags |= EEH_RTP_SEND_FIRST_PACKET_TO_CP;
	}

	if (pFlow->pkt_dup_enable)
	{
		rtp_flags |= EEH_RTP_DUPLICATE_PKT_SEND_TO_CP;
	}

	if (pFlow->hw_flow->flags & RTP_RELAY_ENABLE_VLAN_P_BIT_LEARNING)
	{
		rtp_flags |= EEH_RTP_ENABLE_VLAN_P_BIT_LEARN;
		DPA_INFO("%s(%d) enabling VLAN p bit learning feature in UCODE\n",
			__FUNCTION__,__LINE__);
	}
	
	param->rtp_flags = cpu_to_be16(rtp_flags);
}

void cdx_ehash_update_rtp_info_params(uint8_t *rtp_relay_param, uint32_t *rtpinfo_ptr)
{
	struct en_ehash_rtprelay_param *param;
	uint32_t ptr_val;
	
	param = (struct en_ehash_rtprelay_param *)rtp_relay_param;
	ptr_val = PTR_TO_UINT(rtpinfo_ptr);
	param->rtpinfo_ptr =  cpu_to_be32(ptr_val);
	return;
}

void cdx_ehash_update_dtmf_rtp_info_params(uint8_t *rtp_relay_param, uint8_t *DTMF_PT)
{
	struct en_ehash_rtprelay_param *param;
	
	param = (struct en_ehash_rtprelay_param *)rtp_relay_param;
	param->DTMF_PT[0] = DTMF_PT[0];
	param->DTMF_PT[1] = DTMF_PT[1];
	return;
}

#endif
