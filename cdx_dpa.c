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
 * @file                cdx_dpa.c     
 * @description         cdx DPAA interface functions
 */             

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "misc.h"
#include "cdx.h"
#include "cdx_common.h"
#include "types.h"
#include "list.h"
#include "cdx_ioctl.h"
#include "layer2.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_tunnel.h"
#include "control_bridge.h"
#include "dpa_ipsec.h"


//#define CDX_DPA_DEBUG 1

#ifdef CDX_DPA_DEBUG
#define CDX_DPA_DPRINT(fmt, args...) printk(KERN_ERR "%s:: " fmt, __func__, ##args)
#else
#define CDX_DPA_DPRINT(fmt, args...) do { } while(0)
#endif

//disable flow statistics
#define ENABLE_STATISTICS 1

#define PPPoE_HASH_TBL_BUCKETS	(1 << 4) //16 
struct pppoe_table_entry {
	struct pppoe_table_entry *next;
	struct pppoe_key key;	
	int dpa_handle;
};

struct pppoe_sess_table {
	spinlock_t lock;	
	struct pppoe_table_entry *head;
};


extern int cdx_ipsec_fill_sec_info( PCtEntry entry, 
		struct ins_entry_info *info); 
//static struct pppoe_sess_table *pppoe_tbl[MAX_FRAME_MANAGERS][MAX_PORTS_PER_FMAN];

extern int dpa_get_mac_addr(char *name, char *mac_addr);
extern void display_ctentry(PCtEntry entry);
extern void display_buf(void *, uint32_t);

extern int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index , 
		uint32_t *fm_index, uint32_t *port_index, uint32_t *portid);
extern void *dpa_get_pcdhandle(uint32_t fm_index);
extern void *dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type);
extern int create_routing_hm(void *fm_pcd, uint32_t fm_idx,
                struct dpa_l2hdr_info *l2_info,
                uint32_t mtu, uint32_t frag_poolid,
                int32_t *hmd, int32_t *hm_index, uint32_t head);
extern int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info, 
				PRouteEntry tnl_rt_entry, uint32_t queue);
extern int create_hm_chain(PCtEntry entry, struct ins_entry_info *info);
extern int create_hm_chain_for_mcast_entry(PCtEntry entry, struct ins_entry_info *info);
extern void delete_hm_chain(struct hw_ct * ct);
extern int dpa_get_tx_fqid_by_name(char *name, uint32_t *fqid);
extern int disp_muram(void);
extern void *dpa_get_fm_ctx(uint32_t fm_idx);
extern uint32_t dpa_get_fm_timestamp(void *fm_ctx);
extern int dpa_add_oh_if(char *name);
extern int get_oh_port_td(uint32_t fm_index, uint32_t port_idx, uint32_t type);
extern uint32_t dpa_get_timestamp_addr(uint32_t id);

//add ethernet type device
extern struct physical_port phy_port[MAX_PHY_PORTS];
int cdx_add_eth_onif(char *name)
{
	uint32_t ii;

	CDX_DPA_DPRINT("adding iface %s\n", name);
	//find free slot in phys list
	for (ii = 0; ii < MAX_PHY_PORTS; ii++) {
		if (!phy_port[ii].flags) {
			phy_port[ii].id = ii;
			phy_port[ii].flags = 
				(IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
			break;
		}
	}
	if (ii == MAX_PHY_PORTS) {
		DPA_ERROR("%s::mac phys port limit reached\n", __FUNCTION__);
		return -EINVAL;
	}
	//call add onif to add device
	if (add_onif(name, &phy_port[ii].itf, NULL, 
				(IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL)) == NULL) 	{
		memset(&phy_port[ii], 0, sizeof(struct physical_port));
		DPA_ERROR("%s::add_onif failed\n", __FUNCTION__);
		return -EIO;
	}
	//fill mac address in phys port
	dpa_get_mac_addr(name, &phy_port[ii].mac_addr[0]);
	CDX_DPA_DPRINT("added iface %s\n", name);
	return 0;
}

int cdx_add_oh_iface(char *name)
{

#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s::adding oh iface %s\n", __FUNCTION__,
                       name);
#endif
        if (dpa_add_oh_if(name)) {
                DPA_ERROR("%s::add oh port failed\n", __FUNCTION__);
                return -EIO;
        }
#ifdef CDX_DPA_DEBUG
        DPA_INFO("%s::added oh iface %s\n", __FUNCTION__,
                       name);
#endif
        return 0;
}


#ifndef USE_ENHANCED_EHASH
static int fill_key_info(PCtEntry entry, struct ins_entry_info *info)
{
	struct dpa_offload_key_info *key_info;
	unsigned char *saddr, *daddr;
	int i;

	key_info = &info->key_info;
	memset(&key_info->key.key_array[0], 0, sizeof(union dpa_key));
#ifdef USE_EXACT_MATCH_TABLE
	memset(&key_info->mask.key_array[0], 0, sizeof(union dpa_key));
#endif
	memset(&key_info->mask.key_array[0], 0, sizeof(union dpa_key));
	switch (entry->proto) {
		case IPPROTOCOL_TCP: 
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_info->type = IPV6_TCP_TABLE;
				key_info->dpa_key.size = sizeof(struct ipv6_tcpudp_key);
				for (i = 0; i < 16; i++)
					key_info->key.ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key_info->key.ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];
				key_info->key.ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key_info->key.ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key_info->key.ipv6_tcpudp_key.ipv6_dport = entry->Dport;
#ifdef USE_EXACT_MATCH_TABLE
				key_info->key.ipv6_tcpudp_key.flags = 0;
#endif
			}
			else
			{

				key_info->type = IPV4_TCP_TABLE;
				key_info->dpa_key.size = sizeof(struct ipv4_tcpudp_key);
				key_info->key.ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key_info->key.ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key_info->key.ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key_info->key.ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key_info->key.ipv4_tcpudp_key.ipv4_dport = entry->Dport;
#ifdef USE_EXACT_MATCH_TABLE
				key_info->key.ipv4_tcpudp_key.flags = 0;
#endif
			}
			CDX_DPA_DPRINT("key len %d\n", key_info->dpa_key.size);
#ifdef USE_EXACT_MATCH_TABLE
                        memset(&key_info->mask.key_array[0], 0, 14);
                        memset(&key_info->mask.key_array[14], 0xff,
                                        (key_info->dpa_key.size - 15));
			key_info->mask.key_array[(key_info->dpa_key.size - 1)] =
				0x07;
#endif
			break;
		case IPPROTOCOL_UDP:
			if (IS_IPV6_FLOW(entry))
			{
				saddr = (unsigned char*)entry->Saddr_v6;
				daddr = (unsigned char*)entry->Daddr_v6;
				key_info->type = IPV6_UDP_TABLE;
				key_info->dpa_key.size = sizeof(struct ipv6_tcpudp_key);
				for (i = 0; i < 16; i++)
					key_info->key.ipv6_tcpudp_key.ipv6_saddr[i] = saddr[i];
				for (i = 0; i < 16; i++)
					key_info->key.ipv6_tcpudp_key.ipv6_daddr[i] = daddr[i];

				key_info->key.ipv6_tcpudp_key.ipv6_protocol = entry->proto;
				key_info->key.ipv6_tcpudp_key.ipv6_sport = entry->Sport;
				key_info->key.ipv6_tcpudp_key.ipv6_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
                                {
				  key_info->type = IPV6_MULTICAST_TABLE;
				  key_info->dpa_key.size = sizeof(struct ipv6_tcpudp_key) - 4;
                                }
			}
			else
			{
				key_info->type = IPV4_UDP_TABLE;
				key_info->dpa_key.size = sizeof(struct ipv4_tcpudp_key);
				key_info->key.ipv4_tcpudp_key.ipv4_saddr = entry->Saddr_v4;
				key_info->key.ipv4_tcpudp_key.ipv4_daddr = entry->Daddr_v4;
				key_info->key.ipv4_tcpudp_key.ipv4_protocol = entry->proto;
				key_info->key.ipv4_tcpudp_key.ipv4_sport = entry->Sport;
				key_info->key.ipv4_tcpudp_key.ipv4_dport = entry->Dport;
                                if(entry->Sport == 0 && entry->Dport == 0)
                                {
				  key_info->type = IPV4_MULTICAST_TABLE;
				  key_info->dpa_key.size = sizeof(struct ipv4_tcpudp_key) - 4;
                                }
#ifdef USE_EXACT_MATCH_TABLE
				key_info->key.ipv4_tcpudp_key.flags = 0;
#endif
			}
#ifdef USE_EXACT_MATCH_TABLE
			memset(&key_info->mask.key_array[0], 0, 14);
                        memset(&key_info->mask.key_array[14], 0xff,
                                        (key_info->dpa_key.size - 15));
			key_info->mask.key_array[(key_info->dpa_key.size -1)] =
				0;
#endif
			break;
		default:
			DPA_ERROR("%s::protocol %d not supported\n",
					__FUNCTION__, entry->proto);
			return FAILURE;

	}
	//portid added to key
	key_info->key.portid = info->portid;
	key_info->dpa_key.size++;
	//set key values 

	key_info->dpa_key.byte = &key_info->key.key_array[0];
#ifdef USE_EXACT_MATCH_TABLE
	key_info->dpa_key.mask = &key_info->mask.key_array[0];
#else
#ifdef USE_INTERNAL_TIMESTAMP
	key_info->dpa_key.timestamp_type = FMAN_INTERNAL_TIMESTAMP;
#else
	key_info->dpa_key.timestamp_type = EXTERNAL_TIMESTAMP_TIMERID;
#endif
#endif

#ifdef CDX_DPA_DEBUG
	DPA_INFO("keysize %d\n", key_info->dpa_key.size);
	display_buf(key_info->dpa_key.byte, key_info->dpa_key.size);
#ifdef USE_EXACT_MATCH_TABLE
	display_buf(key_info->dpa_key.mask, key_info->dpa_key.size);
#endif
#endif
	return SUCCESS;
}

//check activity
void hw_ct_get_active(struct hw_ct *ct)
{
	struct dpa_cls_tbl_entry_stats stats;
	memset(&stats, 0, sizeof(struct dpa_cls_tbl_entry_stats));
	if (dpa_classif_table_get_entry_stats_by_ref(ct->td, ct->dpa_handle, &stats))
	{
		//alloc conn to timeout if stats get fails, something wrong
                DPA_ERROR("%s::get stats for ref %d failed\n", __FUNCTION__,
                        ct->dpa_handle);
		return;
        }
	if (ct->pkts != stats.pkts)
	{
        	ct->pkts = stats.pkts;
        	ct->bytes = stats.bytes;
		if (dpa_classif_table_get_timestamp_by_ref(ct->td, ct->dpa_handle, 
					&ct->timestamp)) {
                	DPA_ERROR("%s::get timestamp for ref %d failed\n", __FUNCTION__,
                        	ct->dpa_handle);

		}
#if 0
		printk(KERN_CRIT "%s::ct %p pkts %lu, bytes %lu, timestamp %x jiffies %x\n", 
			__FUNCTION__, ct, (unsigned long)ct->pkts, (unsigned long)ct->bytes, ct->timestamp,
			JIFFIES32);
#endif
	}
}


//delete classif entry from table
int delete_entry_from_classif_table(PCtEntry entry)
{

	CDX_DPA_DPRINT("\n");
	if (dpa_classif_table_delete_entry_by_ref(entry->ct->td, 
		entry->ct->dpa_handle)) {
		DPA_ERROR("%s::failed to remove entry\n", 
			__FUNCTION__);
        	return FAILURE;
	}
	delete_hm_chain(entry->ct);
	kfree(entry->ct);
	entry->ct = NULL;
	return SUCCESS;
}

//delete classif entry from table
int delete_l2br_entry_classif_table(struct hw_ct *ct)
{
#ifdef USE_EXACT_MATCH_TABLE
	uint32_t ii;
	for (ii = 0; ii < MAX_MATCH_TABLES; ii++) {
#endif
		if (dpa_classif_table_delete_entry_by_ref(ct->td,
					ct->dpa_handle)) {
			DPA_ERROR("%s::failed to remove entry\n",
					__FUNCTION__);
			return FAILURE;
		}
	
	ct->dpa_handle = -1;
#ifdef USE_EXACT_MATCH_TABLE
	ct++;
	}
#endif
	return SUCCESS;
}
#endif

int add_incoming_iface_info(PCtEntry entry)
{
	if (!entry->pRtEntry) 
		return 1;
	if (!entry->pRtEntry->input_itf)
	{
		DPA_ERROR("%s No Input interface information \n",__func__);
		return ERR_UNKNOWN_INTERFACE;
	}

        entry->inPhyPortNum = entry->pRtEntry->input_itf->index;
        return NO_ERR;
}

//insert entry in pppoe class table
int insert_entry_in_pppoe_table(int fm_idx, int port_idx,
			uint8_t *ac_mac_addr, uint32_t sessid, 
			uint32_t ppp_pid)
{
	printk("%s::not implemented\n", __FUNCTION__);
	return FAILURE;
}

//insert classif entry into table
#ifndef USE_ENHANCED_EHASH
int insert_entry_in_classif_table(PCtEntry entry)
{
	int ii;
	struct ins_entry_info *info;
	// This can never be NULL for connection routes. 
	struct _itf *underlying_input_itf = entry->pRtEntry->underlying_input_itf;

#ifdef CDX_DPA_DEBUG
	CDX_DPA_DPRINT("\n");
	display_ctentry(entry);
#endif
	//clear hw entry pointer
	entry->ct = NULL;
	if (add_incoming_iface_info(entry))
	{
		DPA_ERROR("%s::unable to get interface %d\n",__FUNCTION__, 
			entry->inPhyPortNum);
		return FAILURE;
	}

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info)
        	return FAILURE;
	
        memset(info, 0, sizeof(struct ins_entry_info));
	if (fill_key_info(entry, info))
        	goto err_ret;
	//get fman index and port index where this entry need to be added
	if (dpa_get_fm_port_index(entry->inPhyPortNum, underlying_input_itf->index ,&info->fm_idx, 
				&info->port_idx, &info->portid)) {
		DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
                        	__FUNCTION__, entry->inPhyPortNum);
        	goto err_ret;
	}
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
                        	__FUNCTION__, info->fm_idx);
        	goto err_ret;
	}	
#ifdef CDX_DPA_DEBUG
	DPA_INFO("%s:: input_itf idx:%x - type :%x\n", __FUNCTION__, entry->pRtEntry->input_itf->index, entry->pRtEntry->input_itf->type);
	DPA_INFO("%s:: underlying input_itf idx:%x - type :%x\n", __FUNCTION__, underlying_input_itf->index, underlying_input_itf->type);
#endif
	//get table descriptor based on type and port
	info->td = (int)dpa_get_tdinfo(info->fm_idx, info->portid, 
			info->key_info.type);
	if (info->td == -1) {
		DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
                        	__FUNCTION__, entry->inPhyPortNum, 
				info->key_info.type);
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
                        	__FUNCTION__, info->key_info.type);
        			goto err_ret;
		}
        	/*
		*  if this is a ipsec secure inbound connection, then plain traffic will be at 
		* the ofline port. So the port_id in the selector key need a change.
		*/
		info->key_info.key.portid = info->portid;

	}
#ifdef CDX_DPA_DEBUG
	printk("keysize %d\n", info->key_info.dpa_key.size);
	display_buf(info->key_info.dpa_key.byte, info->key_info.dpa_key.size);
#ifdef USE_EXACT_MATCH_TABLE
	display_buf(info->key_info.dpa_key.mask, info->key_info.dpa_key.size);
#endif
#endif
#endif
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
				__FUNCTION__);
        	goto err_ret;
	}
        memset(entry->ct, 0, sizeof(struct hw_ct ));
	entry->ct->td = info->td;
	//set actions
	memset(&info->action, 0, sizeof(struct dpa_cls_tbl_action));
	if (dpa_get_tx_info_by_itf(entry->pRtEntry, &info->l2_info, 
			&info->l3_info, entry->tnl_route, entry->queue)) {
		DPA_ERROR("%s::unable to get tx params\n",
                        	__FUNCTION__);
        	goto err_ret;
	}	
	info->action.type = DPA_CLS_TBL_ACTION_ENQ;
	info->action.enable_statistics = 1;
	/* In case of secure connection if  to_sec_fqid is non zero, 
	 * then asign it to table entry fqid
	 */
	if(info->to_sec_fqid)
		info->action.enq_params.new_fqid = info->to_sec_fqid;
	else
		info->action.enq_params.new_fqid = info->l2_info.fqid;
	info->action.enq_params.override_fqid = 1;
#ifdef  CDX_DPA_DEBUG
	CDX_DPA_DPRINT("new fqid %x td %d\n",
		info->action.enq_params.new_fqid, info->td);
#endif
	if (create_hm_chain(entry, info)) {
		goto err_ret;
	}
	
	//insert entry
	entry->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (entry->ct->fm_ctx == NULL) {
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
			__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
#ifdef USE_INTERNAL_TIMESTAMP
	entry->ct->timestamp = dpa_get_fm_timestamp(entry->ct->fm_ctx);
#else
	entry->ct->timestamp = JIFFIES32;
#endif
	ii = dpa_classif_table_insert_entry(info->td, &info->key_info.dpa_key,
		 &info->action, 0, &entry->ct->dpa_handle);
	if (ii) {
		DPA_ERROR("%s::failed to insert forward entry err %d\n", 
			__FUNCTION__, ii);
        	goto err_ret;
	}
	CDX_DPA_DPRINT("classid id  %d\n", entry->ct->dpa_handle);
#ifdef CDX_DPA_DEBUG
	printk("Class tbl = %d class entry handle  = %d entry fqid = %d \n",info->td, entry->ct->dpa_handle,info->action.enq_params.new_fqid );
#endif
	kfree(info);
	return SUCCESS;
err_ret:
	//free hw flow entry if allocated
	if (entry->ct)
		kfree(entry->ct);
	entry->ct = NULL;
	kfree(info);
	return FAILURE;
}

int insert_mcast_entry_in_classif_table(struct _tCtEntry *pCtEntry, int mc_grpid)
{
  struct ins_entry_info *info;
  PRouteEntry pRtEntry;
  int iRet;
  uint32_t underlying_iface_itf_index;


  info = kzalloc(sizeof(struct ins_entry_info), 0);
  if (!info)
  {
    return FAILURE;
  }

  //get fman index and port index where this entry need to be added
  pRtEntry = pCtEntry->pRtEntry;
  if(pRtEntry->underlying_input_itf)
      underlying_iface_itf_index = pRtEntry->underlying_input_itf->index;
  else
      underlying_iface_itf_index =  0;

  if (dpa_get_fm_port_index(pRtEntry->itf->index, underlying_iface_itf_index, &info->fm_idx,
                                &info->port_idx, &info->portid))
  {
    DPA_ERROR("%s::unable to get fmindex for itfid %d\n", __FUNCTION__, pRtEntry->itf->index);
    goto err_ret;
  }

  if (fill_key_info(pCtEntry, info))
  {
    goto err_ret;
  }

  //get pcd handle based on determined fman
  info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
  if (!info->fm_pcd)
  {
    DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n", __FUNCTION__, info->fm_idx);
    goto err_ret;
  }

  //get table descriptor based on type and port
  info->td = (int)dpa_get_tdinfo(info->fm_idx, info->port_idx, info->key_info.type);
  if (info->td == -1)
  {
    DPA_ERROR("%s::unable to get td for itfid %d, type %d\n",
                 __FUNCTION__, pCtEntry->inPhyPortNum, info->key_info.type);
                goto err_ret;
  	}

  	pCtEntry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
  	if (!pCtEntry->ct) {
    		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",__FUNCTION__);
    		goto err_ret;
  	}

  	pCtEntry->ct->td = info->td;
  	//set actions
  	memset(&info->action, 0, sizeof(struct dpa_cls_tbl_action));
  	//Setting default queue for multicast traffic
  	if (dpa_get_tx_info_by_itf(pCtEntry->pRtEntry, &info->l2_info, &info->l3_info,NULL, 1)) {
    		DPA_ERROR("%s::unable to get tx params\n",__FUNCTION__);
 	   	goto err_ret;
  	}
  	info->action.type = DPA_CLS_TBL_ACTION_MCAST;
  	info->action.enable_statistics = 1;
  	info->action.mcast_params.grpd = mc_grpid;
  	info->action.mcast_params.hmd = DPA_OFFLD_DESC_NONE;
  	if (create_hm_chain_for_mcast_entry(pCtEntry, info)) {
    		goto err_ret;
  	}

  	//insert entry
  	iRet = dpa_classif_table_insert_entry(info->td, &info->key_info.dpa_key,
                 &info->action, 0, &pCtEntry->ct->dpa_handle);
  	if (iRet) {
    		DPA_ERROR("%s::failed to insert forward entry err %d\n",
                        __FUNCTION__, iRet);
                goto err_ret;
  	}
  	kfree(info);
  	return SUCCESS;
err_ret:
        //free hw flow entry if allocated
        if (pCtEntry->ct)
                kfree(pCtEntry->ct);
        kfree(info);
        return FAILURE;
}



static void fill_l2brkey_info(struct L2Flow_entry *entry, 
		uint32_t type, struct dpa_offload_key_info *key_info, uint32_t portid)
{
	key_info->type = type;
	switch (type) {
		case ETHERNET_TABLE: 
			key_info->dpa_key.size = sizeof(struct ethernet_key);
			//fill mac addresses and type
			memcpy(&key_info->key.ether_key.ether_da[0], &entry->l2flow.da[0], ETH_ALEN);
			memcpy(&key_info->key.ether_key.ether_sa[0], &entry->l2flow.sa[0], ETH_ALEN);
			key_info->key.ether_key.ether_type = (entry->l2flow.ethertype); 
			memset(&key_info->mask.key_array[0], 0xff, 14);
			break;

#ifdef USE_EXACT_MATCH_TABLE
		case IPV4_UDP_TABLE:
		case IPV4_TCP_TABLE:
			key_info->dpa_key.size = sizeof(struct ipv4_tcpudp_key);
			//fill mac addresses and type
			memcpy(&key_info->key.ipv4_tcpudp_key.ether_da[0], &entry->l2flow.da[0], ETH_ALEN);
			memcpy(&key_info->key.ipv4_tcpudp_key.ether_sa[0], &entry->l2flow.sa[0], ETH_ALEN);
			key_info->key.ipv4_tcpudp_key.ether_type = (entry->l2flow.ethertype); 
			memset(&key_info->mask.key_array[14], 0, (sizeof(struct ipv4_tcpudp_key) - 14));
			memset(&key_info->mask.key_array[0], 0xff, 14);
			memset(&key_info->mask.key_array[14], 0, (sizeof(struct ipv4_tcpudp_key) - 14));
			break;
		
		case IPV6_UDP_TABLE:
		case IPV6_TCP_TABLE:
			key_info->dpa_key.size = sizeof(struct ipv6_tcpudp_key);
			//fill mac addresses and type
			memcpy(&key_info->key.ipv6_tcpudp_key.ether_da[0], &entry->l2flow.da[0], ETH_ALEN);
			memcpy(&key_info->key.ipv6_tcpudp_key.ether_sa[0], &entry->l2flow.sa[0], ETH_ALEN);
			key_info->key.ipv6_tcpudp_key.ether_type = (entry->l2flow.ethertype); 
			memset(&key_info->mask.key_array[14], 0, (sizeof(struct ipv6_tcpudp_key) - 14));
			memset(&key_info->mask.key_array[0], 0xff, 14);
			memset(&key_info->mask.key_array[14], 0, (sizeof(struct ipv6_tcpudp_key) - 14));
			break;
#endif
		
	}
	//fill key info
	//set key values 
	key_info->key.portid = portid;
	key_info->dpa_key.size++;
	key_info->dpa_key.byte = &key_info->key.key_array[0];
#ifdef USE_EXACT_MATCH_TABLE
	key_info->dpa_key.mask = &key_info->mask.key_array[0];
#endif
#ifdef CDX_DPA_DEBUG
	DPA_ERROR("%s::keysize %d\n", __FUNCTION__, key_info->dpa_key.size);
	display_buf(key_info->dpa_key.byte, key_info->dpa_key.size);
#ifdef USE_EXACT_MATCH_TABLE
	display_buf(key_info->dpa_key.mask, key_info->dpa_key.size);
#endif
#endif
}

int add_l2flow_to_hw(struct L2Flow_entry *entry)
{
	POnifDesc ifdesc; 
	uint32_t fm_idx;
	uint32_t port_idx;
	uint32_t ii;
	uint32_t td[MAX_MATCH_TABLES];
	uint32_t fqid;
	struct ins_entry_info *info;
	struct hw_ct *ct;
        uint32_t portid;

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

	
#ifdef USE_EXACT_MATCH_TABLE
	for (ii = 0; ii < MAX_MATCH_TABLES; ii++) {
#else
	for (ii = ETHERNET_TABLE; ii < MAX_MATCH_TABLES; ii++) {
#endif
		td[ii] = (int)dpa_get_tdinfo(fm_idx, portid, ii);

		if (td[ii] == -1) {
			DPA_ERROR("%s::unable to get td type %d for iface %s\n",
				__FUNCTION__, ii, &entry->out_ifname[0]); 
                	return FAILURE;
		}
	}
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


	//allocate hw entry
#ifdef USE_EXACT_MATCH_TABLE 
	entry->ct = (struct hw_ct *)kzalloc((sizeof(struct hw_ct) * MAX_MATCH_TABLES), GFP_KERNEL);
#else
	entry->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct) , GFP_KERNEL);
#endif
	if (!entry->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n",
				__FUNCTION__);
        	goto err_ret;
	}
	ct = entry->ct;

#ifdef USE_EXACT_MATCH_TABLE 
	for (ii = 0; ii < MAX_MATCH_TABLES; ii++)
                (ct + ii)->dpa_handle = -1;
#else
	ct->dpa_handle = -1;
#endif

#ifdef USE_EXACT_MATCH_TABLE
	for (ii = 0; ii < MAX_MATCH_TABLES; ii++) {
#else
	for (ii = ETHERNET_TABLE; ii < MAX_MATCH_TABLES; ii++) {
#endif
		ct->td = td[ii];
		//get pcd handle based on fman instance
		info->fm_pcd = dpa_get_pcdhandle(fm_idx);
        	info->action.type = DPA_CLS_TBL_ACTION_ENQ;
        	info->action.enable_statistics = 1;
        	info->action.enq_params.new_fqid = fqid;
        	info->action.enq_params.override_fqid = 1;
		info->action.enq_params.hmd = DPA_OFFLD_DESC_NONE;
		fill_l2brkey_info(entry, ii, &info->key_info, portid);
#ifdef CDX_DPA_DEBUG
        	CDX_DPA_DPRINT("new fqid %x td %d\n",
                	info->action.enq_params.new_fqid, info->td);
#endif
		//insert entry
        	if (dpa_classif_table_insert_entry(ct->td, &info->key_info.dpa_key,
               			&info->action, 0, &ct->dpa_handle)) {
                	DPA_ERROR("%s::failed to insert forward entry\n",
                        	__FUNCTION__);
                	goto err_ret;
        	}	
        	CDX_DPA_DPRINT("type %d classif id  %d\n", ETHERNET_TABLE, ct->dpa_handle);
		ct++;
	}
        kfree(info);
        return SUCCESS;
err_ret:
	if (entry->ct) {
		if (delete_l2br_entry_classif_table(entry->ct) == 0)
			kfree(entry->ct);
	}
        kfree(info);
        return FAILURE;
}
#endif
