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
 * @file                devman.c     
 * @description         device management routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/if_inet6.h>
#include <uapi/linux/in6.h> 
#include <linux/spinlock.h>
#include <linux/if_arp.h>
#include "lnxwrp_fm.h"
#include <linux/fsl_oh_port.h>
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "fm_ehash.h"
#include "portdefs.h"
#include "layer2.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "mac.h"
#include "cdx.h"
#include "cdx_common.h"
#include "fe.h"
#include "control_pppoe.h"
#include "control_tunnel.h"
#include "control_ipv6.h"
#include "cdx_ceetm_app.h"
#include "endian_ext.h" 

//#define DEVMAN_DEBUG	1

#define NULL_MAC_ADDR(mac) (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5] )

DEFINE_SPINLOCK(dpa_devlist_lock);
struct dpa_iface_info *dpa_interface_info;


extern struct net init_net;
extern int get_dpa_eth_iface_info(struct eth_iface_info *iface_info, char *name);
extern int dpa_get_tx_chnl_info(uint32_t fqid, uint32_t *ch_id, uint32_t *wq_id);
extern int find_pcd_fq_info(uint32_t fqid);
extern int cdxdrv_create_of_fqs(struct oh_iface_info *iface_info);
extern void add_pcd_fq_info(struct dpa_fq *fq_info);
extern void display_ohport_info(struct oh_iface_info *ohinfo);

extern int dpaa_get_vap_fwd_fq(uint16_t vap_id, uint32_t* fqid);
extern int dpaa_get_wifi_ohport_handle( uint32_t* oh_handle);
extern int get_ofport_fman_and_portindex(uint32_t fm_index, uint32_t handle, uint32_t* fm_idx, uint32_t* port_idx,
			uint32_t *portid);
extern void *alloc_iface_stats(uint32_t dev_type, uint8_t *rx_offset, uint8_t *tx_offset);
extern void free_iface_stats(uint32_t dev_type, void *stats);
extern void dev_fp_stats_get_register(fp_iface_stats_get func);
extern int qman_alloc_fqid_range(u32 *result, u32 count, u32 align, 
		int partial);

struct dpa_iface_info *dpa_get_phys_iface(struct dpa_iface_info *iface_info);

#define PORTID_SHIFT_VAL	8

#ifdef DEVMAN_DEBUG
static void display_pool_info(struct port_bman_pool_info *pool_info)
{
	DPA_INFO("pool_id          \t%d\n", pool_info->pool_id);
	DPA_INFO("buffer size      \t%d\n", pool_info->buf_size);
	DPA_INFO("buffer count     \t%d\n", pool_info->count);
	DPA_INFO("buffer base      \t%llx\n\n", pool_info->base_addr);
}

static void display_eth_port_info(struct eth_iface_info *port_info)
{
	uint32_t ii;

	DPA_INFO("net dev 	   \t%p\n", port_info->net_dev);
	DPA_INFO("fman_idx         \t%d\n", port_info->fman_idx);
	DPA_INFO("port_idx         \t%d\n", port_info->port_idx);
	DPA_INFO("portid           \t%d\n", port_info->portid);
	DPA_INFO("speed        	   \t%d\n", port_info->speed);
	DPA_INFO("rx channel       \t%d\n", port_info->rx_channel_id);
	DPA_INFO("tx channel       \t%d\n", port_info->tx_channel_id);
	DPA_INFO("tx wq		   \t%d\n", port_info->tx_wq);
	DPA_INFO("rx pcd wq	   \t%d\n", port_info->rx_pcd_wq);
	DPA_INFO("dqrr cb	   \t%p\n", port_info->dqrr);
	DPA_INFO("mac addr         \t");
	for (ii = 0; ii < ETH_ALEN; ii++) {
		if (ii == (ETH_ALEN - 1)) {
			printk("%02x\n", port_info->mac_addr[ii]);
		} else {
			printk("%02x:", port_info->mac_addr[ii]);
		}
	}
	DPA_INFO("receive frame que info\n");
	DPA_INFO("Error FQ         \t%x\n", 
				port_info->fqinfo[RX_ERR_FQ].fq_base);
	DPA_INFO("Default FQ  	\t%x\n", 
				port_info->fqinfo[RX_DEFA_FQ].fq_base);
	DPA_INFO("transmit frame que info\n");
	DPA_INFO("Error FQ         \t%d\n", 
				port_info->fqinfo[TX_ERR_FQ].fq_base);
	DPA_INFO("Confirmation FQ  \t%x\n", 
				port_info->fqinfo[TX_CFM_FQ].fq_base);
	DPA_INFO("Transmit Fqs\n");
	for (ii = 0; ii < DPAA_ETH_TX_QUEUES; ii++) {
		if (!(ii % 16)) 
			printk("\n\t");
		printk("%x ", port_info->eth_tx_fqinfo[ii].fq_base);
	}
	printk("\n");
	for (ii = 0; ii < DPAA_FWD_TX_QUEUES; ii++) {
		if (!(ii % 16)) 
			printk("\n\t");
		printk("%x ", port_info->fwd_tx_fqinfo[ii].fqid);
	}
	printk("\n");
	if (port_info->max_dist) {
		struct cdx_dist_info *dist_info;
		DPA_INFO("PCD Fqs\n");
		dist_info = port_info->dist_info;
		for (ii = 0; ii < port_info->max_dist; ii++) {
			printk("fq_base         \t%x(%d)\n", dist_info->base_fqid,
					dist_info->base_fqid);
                        printk("fq_count        \t%d\n", dist_info->count);
			dist_info++;
		}
	}
	DPA_INFO("\nbuffer pool info, pools %d\n", port_info->num_pools);
	for (ii = 0; ii < port_info->num_pools; ii++)
		display_pool_info(&port_info->pool_info[ii]);
}

static void display_vlan_info(struct vlan_iface_info *vlan_info)
{
#ifdef VLAN_IF_SUPPORT
	DPA_INFO("vlan_id		\t%d\n", vlan_info->vlan_id);
	DPA_INFO("parent		\t%s\n",
			vlan_info->parent->name);
#ifdef INCLUDE_VLAN_IFSTATS
	if (vlan_info->stats) {
		DPA_INFO("vlan stats		\t%x\n", vlan_info->stats);
		DPA_INFO("vlan stats idx	\t%d\n", vlan_info->stats_index);
		DPA_INFO("vlan rxpkts		\t%ld\n", 
			cpu_to_be64(vlan_info->stats->rxstats.pkts));
		DPA_INFO("vlan rxbytes		\t%ld\n", 
			cpu_to_be64(vlan_info->stats->rxstats.bytes));
		DPA_INFO("vlan txpkts		\t%ld\n", 
			cpu_to_be64(vlan_info->stats->txstats.pkts));
		DPA_INFO("vlan txbytes		\t%ld\n", 
			cpu_to_be64(vlan_info->stats->txstats.bytes));
	}
#else
	DPA_INFO("vlan iface stats disabled\n");
#endif
#endif
}

static void display_pppoe_info(struct pppoe_iface_info *pppoe_info)
{
#ifdef PPPoE_IF_SUPPORT
	uint32_t ii;

	DPA_INFO("session_id		\t%d\n", pppoe_info->session_id);
	DPA_INFO("dest mac address	\t:");
	for (ii = 0; ii < ETH_ALEN; ii++) {
                if (ii == (ETH_ALEN - 1)) {
                        printk("%02x\n", pppoe_info->mac_addr[ii]);
                } else {
                        printk("%02x:", pppoe_info->mac_addr[ii]);
                }
        }
	DPA_INFO("session id		\t%d\n",
			pppoe_info->session_id);
	DPA_INFO("parent		\t%s\n",
			pppoe_info->parent->name);
#ifdef INCLUDE_PPPoE_IFSTATS
	if (pppoe_info->stats) {
		DPA_INFO("pppoe stats		\t%x\n", pppoe_info->stats);
		DPA_INFO("pppoe stats idx	\t%d\n", pppoe_info->stats_index);
		DPA_INFO("pppoe rx_pkts		\t%ld\n", 	
			cpu_to_be64(pppoe_info->stats->rxstats.pkts));
		DPA_INFO("pppoe rx_bytes	\t%ld\n", 
			cpu_to_be64(pppoe_info->stats->rxstats.bytes));
		DPA_INFO("pppoe rx_timestamp	\t%ld\n", 
			cpu_to_be64(pppoe_info->stats->rxstats.timestamp));
		DPA_INFO("pppoe tx_pkts		\t%ld\n", 
			cpu_to_be64(pppoe_info->stats->txstats.pkts));
		DPA_INFO("pppoe tx_bytes	\t%ld\n", 
			cpu_to_be64(pppoe_info->stats->rxstats.bytes));
		DPA_INFO("pppoe tx_timestamp	\t%ld\n", 
			cpu_to_be64(pppoe_info->stats->txstats.timestamp));
	}
#else
	DPA_INFO("pppoe ifstats disabled\n");
#endif
#endif
}

static void display_tunnel_info(struct tunnel_iface_info *tunnel_info) 
{
#ifdef TUNNEL_IF_SUPPORT

	DPA_INFO("mode		\t%d\n", tunnel_info->mode);
	DPA_INFO("proto		\t%d\n", tunnel_info->proto);
	DPA_INFO("parent	\t%s\n", tunnel_info->parent->name);
	DPA_INFO("local ip::");
	display_ipv4_addr(tunnel_info->local_ip);
	DPA_INFO("remote ip::");
	display_ipv4_addr(tunnel_info->remote_ip);
	DPA_INFO("dest mac::");
	display_mac_addr(tunnel_info->dstmac);
	DPA_INFO("tunnel header - len %d ::\n", tunnel_info->header_size);
	display_buff_data(tunnel_info->header, tunnel_info->header_size);
#ifdef INCLUDE_TUNNEL_IFSTATS
	if (tunnel_info->stats) {
		DPA_INFO("tunnel stats		\t%x\n", tunnel_info->stats);
		DPA_INFO("tunnel stats idx	\t%d\n", tunnel_info->stats_index);
		DPA_INFO("tunnel rxpkts		\t%ld\n", 
			cpu_to_be64(tunnel_info->stats->rxstats.pkts));
		DPA_INFO("tunnel rxbytes	\t%ld\n", 
			cpu_to_be64(tunnel_info->stats->rxstats.bytes));
		DPA_INFO("tunnel txpkts		\t%ld\n", 
			cpu_to_be64(tunnel_info->stats->txstats.pkts));
		DPA_INFO("tunnel txbytes	\t%ld\n", 
			cpu_to_be64(tunnel_info->stats->txstats.bytes));
	}
#else
	DPA_INFO("tunnel ifstats disabled\n");
#endif
#endif
}
#endif



#ifdef DEVMAN_DEBUG
void display_iface_info(struct dpa_iface_info *iface_info)
{

	DPA_INFO(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	DPA_INFO("port             \t%s\n", iface_info->name);
	DPA_INFO("osindex          \t%d\n", iface_info->osid);
	DPA_INFO("mtu         	 \t%d\n", iface_info->mtu);
	if (iface_info->if_flags & IF_TYPE_ETHERNET) {
		display_eth_port_info(&iface_info->eth_info);
		return;
	}
	if (iface_info->if_flags & IF_TYPE_VLAN) {
		display_vlan_info(&iface_info->vlan_info);
		return;
	}
	if (iface_info->if_flags & IF_TYPE_PPPOE) {
		display_pppoe_info(&iface_info->pppoe_info);
		return;
	}
	if (iface_info->if_flags & IF_TYPE_TUNNEL) {
		display_tunnel_info(&iface_info->tunnel_info);
		return;
	}
	if (iface_info->if_flags & IF_TYPE_OFPORT) {
		display_ohport_info(&iface_info->oh_info);
		return;
	}
	DPA_INFO("%s::unsupported iface type flags %x\n",
		__FUNCTION__, iface_info->if_flags);
}
#else
#define display_iface_info(x)
#endif


//create frame queues for the port used to transmit packets from ENQ action
static int create_fwd_tx_fqs(struct eth_iface_info *eth_info)
{
	uint32_t ii;
        struct qman_fq *fq;
        struct qm_mcc_initfq opts;

	fq = &eth_info->fwd_tx_fqinfo[0];
	for (ii = 0; ii < DPAA_FWD_TX_QUEUES; ii++) {
		memset(fq, 0, sizeof(struct qman_fq));
		//FQ for egress
		if (qman_create_fq(0, 
			(QMAN_FQ_FLAG_DYNAMIC_FQID | QMAN_FQ_FLAG_TO_DCPORTAL),
				 fq)) {
			DPA_ERROR("%s::unable to create fq at index %d\n",
					__FUNCTION__, ii);
			return -1;
		}
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
        	opts.fqid = fq->fqid;
		opts.count = 1;
		opts.we_mask = (QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_DESTWQ |
				QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
        	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
        	opts.fqd.dest.channel = eth_info->tx_channel_id;
        	opts.fqd.dest.wq = eth_info->tx_wq;
                        //OVFQ=1 - override FQ in tree
                        //A2V=1 - contextA A2 field is valid
                        //A0V=1 - contextA A0 field is valid
                        //B0V=0 - contextB field is not valid
                        //OVOM=1 - use contextA2 bits instead of ICAD
                        //EBD=1 - deallocate buffers inside FMan

		opts.fqd.context_a.hi = 0x9a000000; 
		opts.fqd.context_a.lo = 0xC0000000;
        	if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
        	        DPA_ERROR("%s::qman_init_fq failed for fqid %d\n",
                	        __FUNCTION__, fq->fqid);
                	qman_destroy_fq(fq, 0);
                	return -1;
        	}
#ifdef DEVMAN_DEBUG
		DPA_INFO("%s::created fq 0x%x chnl id 0x%x\n", 
				__FUNCTION__, fq->fqid, eth_info->tx_channel_id);
#endif
		fq++;
	}
	return 0;
}

struct net_device *find_osdev_by_fman_params(uint32_t fm_idx, uint32_t port_idx,
				uint32_t speed)
{
	struct net_device *device;
	struct dpa_priv_s *priv;	
	struct mac_device *macdev;

	device = first_net_device(&init_net);
	while(1) {
		if (!device) 
			break;
		if (device->type == ARPHRD_ETHER) {
			t_LnxWrpFmDev *p_LnxWrpFmDev;
			priv = netdev_priv(device);
			macdev = priv->mac_dev;
			if (macdev) {
				p_LnxWrpFmDev = (t_LnxWrpFmDev*)macdev->fm;
				if (speed == 10) {
					//10 gig interfaces upports only SUPPORTED_10000baseT_Full
					/*DGW board has 2 fixed-link interfaces 
					1 - (eth2)(xDSL)1G Fixed link interface linked to rgmii-txid
					2 - eth5(G.fast)- 1G Fixed link interface linked to sgmii and
					connected to 10G link of the board.
					sgmii - considered as 1000baseT_Full and this has cell_index = 0*/

					if ( (!macdev->fixed_link) && (macdev->if_support != SUPPORTED_10000baseT_Full) )
						goto next_device; 
				}
				if ((fm_idx == p_LnxWrpFmDev->id) && 
					(port_idx == macdev->cell_index))
					return device;
			}
		}
next_device:
		device = next_net_device(device);
	}
	return device;
}


//get interface information from OS device priv structure
static int get_eth_iface_info(struct dpa_iface_info *iface_info,
			char *name)
{
	struct net_device *device;
	struct eth_iface_info *eth_info;
	struct dpa_priv_s *priv;
	struct dpa_fq *dpa_fq;
	struct dpa_fq *tmp;
	struct dpa_bp *bp;
	int ii;
	
	device = dev_get_by_name(&init_net, name);	
	if (!device) {
		DPA_ERROR("%s::could not find device %s\n", __FUNCTION__, name);
		return FAILURE;
	}
	priv = netdev_priv(device);
	//set as ethernet interface
	iface_info->if_flags = (IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
	//copy name
	strncpy(iface_info->name, name, IF_NAME_SIZE);
	//iface mtu
	iface_info->mtu = device->mtu;
	//os interface id
	iface_info->osid = device->ifindex;
	eth_info = &iface_info->eth_info;
	//save netdev
	eth_info->net_dev = device;
	//copy iface mac address 
	memcpy(eth_info->mac_addr, device->perm_addr, ETH_ALEN);
	//copy speed, mtu and others
	eth_info->speed = priv->mac_dev->max_speed;
	eth_info->rx_channel_id = priv->channel;
	//get fq info
	list_for_each_entry_safe(dpa_fq, tmp, &priv->dpa_fq_list, list) {
		{
#ifdef DEVMAN_DEBUG
			DPA_INFO("%s::iface %s, fqid %d, channel %d, wq %d, type %d\n",
				__FUNCTION__, iface_info->name, 
				dpa_fq->fqid, dpa_fq->channel, dpa_fq->wq,
				dpa_fq->fq_type);
#endif
			switch(dpa_fq->fq_type) {
				case FQ_TYPE_RX_DEFAULT:
					eth_info->fqinfo[RX_DEFA_FQ].fq_base
						 = dpa_fq->fqid;
					eth_info->fqinfo[RX_DEFA_FQ].num_fqs 
						= 1;
					eth_info->defa_rx_dpa_fq = dpa_fq;
					break;
				case FQ_TYPE_RX_ERROR:
					eth_info->fqinfo[RX_ERR_FQ].fq_base
						 = dpa_fq->fqid;
					eth_info->fqinfo[RX_ERR_FQ].num_fqs 
						= 1;
					eth_info->err_rx_dpa_fq = dpa_fq;
					break;
				case FQ_TYPE_TX_CONFIRM:
					eth_info->fqinfo[TX_CFM_FQ].fq_base
						 = dpa_fq->fqid;
					eth_info->fqinfo[TX_CFM_FQ].num_fqs 
						= 1;
					break;
				case FQ_TYPE_TX_ERROR:
					eth_info->fqinfo[TX_ERR_FQ].fq_base
						 = dpa_fq->fqid;
					eth_info->fqinfo[TX_ERR_FQ].num_fqs 
						= 1;
					break;
				case FQ_TYPE_RX_PCD:
					if (!eth_info->rx_pcd_wq) {
						eth_info->rx_pcd_wq = dpa_fq->wq;
						eth_info->dqrr = dpa_fq->fq_base.cb.dqrr;
					}
					break;
				default:
					break;
			}
		}
	}
	//get buffer pool info
	//number of buffer pools in use by this port
	eth_info->num_pools = (int)priv->bp_count;
	if (eth_info->num_pools > MAX_PORT_BMAN_POOLS) {
		DPA_ERROR("%s::invalid num pools value\n", __FUNCTION__);
		return FAILURE;
	}
	bp = priv->dpa_bp;
	for (ii = 0; ii < eth_info->num_pools; ii++) {
		eth_info->pool_info[ii].pool_id = bp->bpid ;
		eth_info->pool_info[ii].buf_size = bp->size; 
		eth_info->pool_info[ii].count = bp->config_count;
		eth_info->pool_info[ii].base_addr = bp->paddr;
		bp++;
	}
	//get egress FQ info
	for (ii = 0; ii < DPAA_ETH_TX_QUEUES; ii++) {
		eth_info->eth_tx_fqinfo[ii].fq_base = priv->egress_fqs[ii]->fqid;
		eth_info->eth_tx_fqinfo[ii].num_fqs = 1;
	}
	//get channel and workqueue to be use for transmit
	if (dpa_get_tx_chnl_info(eth_info->eth_tx_fqinfo[0].fq_base, 
				&eth_info->tx_channel_id, 
				&eth_info->tx_wq)) {
		DPA_ERROR("%s::dpa_get_tx_chnl_info failed\n", 
				__FUNCTION__);
		return FAILURE;
	}
	if (create_fwd_tx_fqs(eth_info)) {
		DPA_ERROR("%s::create_fwd_tx_fqs failed\n", 
				__FUNCTION__);
		return FAILURE;
	}
	return SUCCESS;
}


//add port info to linked list
int dpa_add_port_to_list(struct dpa_iface_info *iface_info)
{
	spin_lock(&dpa_devlist_lock);
	if (dpa_interface_info) 
		iface_info->next = dpa_interface_info;
	dpa_interface_info = iface_info;
	spin_unlock(&dpa_devlist_lock);
	return SUCCESS;
}

//get dpa_info by itf id
struct dpa_iface_info *dpa_get_ifinfo_by_itfid(uint32_t itf_id)
{
        struct dpa_iface_info *iface_info;

        iface_info = dpa_interface_info;
        while (iface_info) {
		//search list for matching id
		if (iface_info->itf_id == itf_id) 
			break;
                iface_info = iface_info->next;
        }
        return iface_info;
}

int cdx_check_rx_iface_type_vlan(struct _itf *input_itf)
{
        struct dpa_iface_info *iface_info, *parent;
	int num_vlan_entries =0;

        iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index){
			if (iface_info->if_flags & IF_TYPE_VLAN)
			{
				num_vlan_entries ++;
                        	parent = iface_info->vlan_info.parent;
				while (parent)
				{
					if (parent->if_flags & IF_TYPE_VLAN)
					{
						num_vlan_entries ++;
                        			parent = parent->vlan_info.parent;
					}
					else
						return num_vlan_entries;
				}
				return num_vlan_entries;
			}
			else
				return 0;
		}
		iface_info = iface_info->next;
	}
	return 0;
}
			
static int dpa_check_for_logical_iface_types(struct _itf *input_itf, 
			struct _itf *underlying_input_itf,
			struct dpa_l2hdr_info *l2_info,
			struct dpa_l3hdr_info *l3_info)
{
        struct dpa_iface_info *iface_info;

	l2_info->vlan_present = 0;
	l2_info->pppoe_present = 0;
        iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index){
check_parent:
			if (iface_info->if_flags & IF_TYPE_ETHERNET)
				return SUCCESS;
			if (iface_info->if_flags & IF_TYPE_WLAN)
		            	return SUCCESS;
			if (iface_info->if_flags & IF_TYPE_VLAN)
			{
				l2_info->vlan_present = 1;
				iface_info = iface_info->vlan_info.parent;
				goto check_parent;
			}
			if (iface_info->if_flags & IF_TYPE_PPPOE)
			{
				l2_info->pppoe_present = 1;
				l2_info->pppoe_sess_id =
					iface_info->pppoe_info.session_id;
				memcpy(&l2_info->ac_mac_addr[0], 
					&iface_info->pppoe_info.mac_addr,
					ETH_ALEN);
				iface_info = iface_info->pppoe_info.parent;
				goto check_parent;
			}
 			if (iface_info->if_flags & IF_TYPE_TUNNEL)
			{
 				l3_info->tnl_header_present = 1;
 				l3_info->header_size = iface_info->tunnel_info.header_size;
 				l3_info->proto = iface_info->tunnel_info.proto;
 				l3_info->mode = iface_info->tunnel_info.mode;
 				memcpy(l3_info->local_ip, iface_info->tunnel_info.local_ip, IPV6_ADDRESS_LENGTH);
 				memcpy(l3_info->remote_ip, iface_info->tunnel_info.remote_ip, IPV6_ADDRESS_LENGTH);
 				iface_info = dpa_get_ifinfo_by_itfid(underlying_input_itf->index);
 				if(!iface_info)
 					return FAILURE;
  				goto check_parent;	

			}
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__FUNCTION__, iface_info->if_flags);
			break;
		} 
		iface_info = iface_info->next;
	}
	return FAILURE;
}

int dpa_check_in_logical_iface_types(struct _itf *input_itf, 
			struct _itf *underlying_input_itf,
			struct dpa_l2hdr_info *l2_info,
			struct dpa_l3hdr_info *l3_info)
{
        struct dpa_iface_info *iface_info;

	l2_info->vlan_present = 0;
	l2_info->pppoe_present = 0;
        iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index){
check_parent:
			if (iface_info->if_flags & IF_TYPE_ETHERNET)
				return SUCCESS;
			if (iface_info->if_flags & IF_TYPE_VLAN)
			{
				l2_info->vlan_present = 1;
				iface_info = iface_info->vlan_info.parent;
				goto check_parent;
			}
			if (iface_info->if_flags & IF_TYPE_PPPOE)
			{
				l2_info->pppoe_present = 1;
				l2_info->pppoe_sess_id =
					iface_info->pppoe_info.session_id;
				memcpy(&l2_info->ac_mac_addr[0], 
					&iface_info->pppoe_info.mac_addr,
					ETH_ALEN);
				iface_info = iface_info->pppoe_info.parent;
				goto check_parent;
			}
 			if (iface_info->if_flags & IF_TYPE_TUNNEL)
			{
 				l3_info->tnl_header_present = 1;
 				l3_info->header_size = iface_info->tunnel_info.header_size;
 				l3_info->proto = iface_info->tunnel_info.proto;
 				l3_info->mode = iface_info->tunnel_info.mode;
 				memcpy(l3_info->local_ip, iface_info->tunnel_info.local_ip, IPV6_ADDRESS_LENGTH);
 				memcpy(l3_info->remote_ip, iface_info->tunnel_info.remote_ip, IPV6_ADDRESS_LENGTH);
 				iface_info = dpa_get_ifinfo_by_itfid(underlying_input_itf->index);
 				if(!iface_info)
 					return FAILURE;
  				goto check_parent;	

			}
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__FUNCTION__, iface_info->if_flags);
			break;
		} 
		iface_info = iface_info->next;
	}
	return FAILURE;
}

int dpa_get_iface_info_by_ipaddress(int sa_family, uint32_t  *daddr, uint32_t * tx_fqid,
					uint32_t * itf_id, uint32_t * portid , void **netdev)
{
        struct dpa_iface_info *iface_info;

	spin_lock(&dpa_devlist_lock);
        iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->if_flags & IF_TYPE_ETHERNET){
			struct net_device* device;

  			device = iface_info->eth_info.net_dev;
                        if(sa_family ==PROTO_IPV4 )
                        {
  				struct in_device  *in_dev;
  				struct in_ifaddr *if_info;
				rcu_read_lock();
  				in_dev = (struct in_device *)(device->ip_ptr);
                                if(in_dev)
				{
  					if_info = in_dev->ifa_list;
					for (;if_info;if_info= (struct in_ifaddr*)(if_info->ifa_next))
					{
						if (if_info->ifa_address == *daddr)
						{
                					struct eth_iface_info *eth_info;
                        				eth_info = &iface_info->eth_info;
							if(portid )
								*portid = eth_info->portid;
                                                        if(netdev)
                                                        	*netdev = (void*)device;
							if(tx_fqid)
							{
#ifdef USE_MULTIPLE_TX_FQS
                        					//spread it among the TX FQs
                        					if (eth_info->tx_index ==
                                					(DPAA_FWD_TX_QUEUES - 1))
	                        					eth_info->tx_index = 0;
        	        					else
                							eth_info->tx_index++;
								*tx_fqid =
				  					eth_info->fwd_tx_fqinfo[eth_info->tx_index].fqid;
#else
								*tx_fqid =
									eth_info->fwd_tx_fqinfo[0].fqid;
#endif
							}
							if(itf_id)
								*itf_id = iface_info->itf_id; 
							rcu_read_unlock();
        						spin_unlock(&dpa_devlist_lock);
							return SUCCESS;
						}
					}
				}
				rcu_read_unlock();
			} else {
				struct inet6_dev * inet6_device;
				struct inet6_ifaddr *ifp;
				rcu_read_lock();
				inet6_device = (struct inet6_dev *) device->ip6_ptr;
                                if(inet6_device)
				{
					read_lock_bh(&inet6_device->lock);
                                        list_for_each_entry(ifp, &inet6_device->addr_list, if_list) {
						if (!(memcmp(&ifp->addr, daddr,16 )))
                                                {
                					struct eth_iface_info *eth_info;
                        				eth_info = &iface_info->eth_info;
							if(portid )
								*portid = eth_info->portid;
                                                        if(netdev)
                                                        	*netdev = (void*)device;
							if(tx_fqid)
							{
#ifdef USE_MULTIPLE_TX_FQS
                        					//spread it among the TX FQs
                        					if (eth_info->tx_index ==
                                					(DPAA_FWD_TX_QUEUES - 1))
	                        					eth_info->tx_index = 0;
        	        					else
                							eth_info->tx_index++;
								*tx_fqid =
				  					eth_info->fwd_tx_fqinfo[eth_info->tx_index].fqid;
#else
								*tx_fqid =
									eth_info->fwd_tx_fqinfo[0].fqid;
#endif
							}
							read_unlock_bh(&inet6_device->lock);
							rcu_read_unlock();
        						spin_unlock(&dpa_devlist_lock);
                                                        return SUCCESS;
                                                }

                			}

				}
				read_unlock_bh(&inet6_device->lock);
				rcu_read_unlock();
			}
		}
		iface_info = iface_info->next;
	}
        spin_unlock(&dpa_devlist_lock);
	return FAILURE;
}
int dpa_get_in_tx_info_by_itf_id(uint32_t itf_id, 
				struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info, uint32_t * portid)
{

        struct dpa_iface_info *iface_info;
	int retval = FAILURE;
	memset(l2_info, 0, sizeof(struct dpa_l2hdr_info));
	memset(l3_info, 0, sizeof(struct dpa_l2hdr_info));
	
	spin_lock(&dpa_devlist_lock);
	if(portid)
		 *portid = 0;  
	iface_info = dpa_get_ifinfo_by_itfid(itf_id);
        while (1) {
                if (!iface_info)
                        break;
                //search list for matching id
                if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			if(portid && (*portid == 0))
				*portid = iface_info->eth_info.portid;
			l2_info->mtu = iface_info->mtu;
#ifdef INCLUDE_ETHER_IFSTATS
			l2_info->ether_stats_offset = 
				iface_info->txstats_index;
#endif
	 		retval = SUCCESS;
                        break;
                } 
	        if (iface_info->if_flags & IF_TYPE_VLAN) {
			l2_info->vlan_present = 1;
                        //move to parent interface
			iface_info = iface_info->vlan_info.parent;
                        continue;
               } 

	        if (iface_info->if_flags & IF_TYPE_PPPOE) {
			l2_info->pppoe_present = 1;
			l2_info->pppoe_sess_id =
					iface_info->pppoe_info.session_id;
			memcpy(&l2_info->ac_mac_addr[0], 
				&iface_info->pppoe_info.mac_addr,
				ETH_ALEN);
			//move to parent interface
			iface_info = iface_info->pppoe_info.parent;
                        continue;
		}
	        if (iface_info->if_flags & IF_TYPE_TUNNEL) {
 				l3_info->tnl_header_present = 1;
 				l3_info->header_size = iface_info->tunnel_info.header_size;
 				l3_info->proto = iface_info->tunnel_info.proto;
 				l3_info->mode = iface_info->tunnel_info.mode;
 				memcpy(l3_info->local_ip, iface_info->tunnel_info.local_ip, IPV6_ADDRESS_LENGTH);
 				memcpy(l3_info->remote_ip, iface_info->tunnel_info.remote_ip, IPV6_ADDRESS_LENGTH);
				iface_info = iface_info->tunnel_info.parent;
			continue;

		} else {
               		DPA_INFO("%s::iface type %x not "
                                        "supported \n",
                                        __FUNCTION__, iface_info->if_flags);
			break;
               }
	}
        spin_unlock(&dpa_devlist_lock);
        return retval;
}

int dpa_get_out_tx_info_by_itf_id(PRouteEntry rt_entry , 
				struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info)
{

        uint32_t index;
        struct dpa_iface_info *iface_info;
        struct dpa_iface_info *parent;
	int retval = FAILURE;
	uint32_t itf_id;

	memset(l2_info, 0, sizeof(struct dpa_l2hdr_info));
	memset(l3_info, 0, sizeof(struct dpa_l2hdr_info));
	
	if(!rt_entry)
	{
		DPA_ERROR("%s::NULL Route \n",
                        __FUNCTION__);
        	return retval;
	}
	itf_id = rt_entry->itf->index;
	l2_info->mtu = rt_entry->mtu;
	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_get_ifinfo_by_itfid(itf_id);
        while (1) {
                if (!iface_info)
                        break;
                //search list for matching id
                if (iface_info->if_flags & IF_TYPE_ETHERNET) {
                	struct eth_iface_info *eth_info;

                        eth_info = &iface_info->eth_info;

			if(!(NULL_MAC_ADDR(l2_info->l2hdr)))
				memcpy(&l2_info->l2hdr[0], rt_entry->dstmac,
						ETHER_ADDR_LEN);
			memcpy(&l2_info->l2hdr[ETHER_ADDR_LEN], 
					eth_info->mac_addr,
					ETHER_ADDR_LEN);
			index = eth_info->tx_index;
#ifdef USE_MULTIPLE_TX_FQS
                        //spread it among the TX FQs
                        if (eth_info->tx_index ==
                                	(DPAA_FWD_TX_QUEUES - 1))
	                        eth_info->tx_index = 0;
        	        else
                		eth_info->tx_index++;
                        l2_info->fqid = 
				  eth_info->fwd_tx_fqinfo[eth_info->tx_index].fqid;
#else
                        l2_info->fqid = 
				eth_info->fwd_tx_fqinfo[0].fqid;
#endif
#ifdef INCLUDE_ETHER_IFSTATS
			l2_info->ether_stats_offset = 
				iface_info->txstats_index;
#endif
        		retval = SUCCESS;
                        break;
                } 
	        if (iface_info->if_flags & IF_TYPE_VLAN) {
			if (l2_info->num_egress_vlan_hdrs ==
					DPA_CLS_HM_MAX_VLANs) {
                        	DPA_INFO("%s::too many vlan "
                                        	"headers \n",
                                        	__FUNCTION__); 
				break;
			}
                        //move to parent interface
                        parent = iface_info->vlan_info.parent;
#ifdef DEVMAN_DEBUG
                        DPA_INFO("%s::moving to parent "
                                	"iface %s id %d\n",
                                        __FUNCTION__, parent->name,
                                        parent->itf_id);
#endif
			l2_info->egress_vlan_hdrs[l2_info->num_egress_vlan_hdrs].tpid = 0x8100;
			l2_info->egress_vlan_hdrs[l2_info->num_egress_vlan_hdrs].tci = iface_info->vlan_info.vlan_id;
			l2_info->num_egress_vlan_hdrs++;
			iface_info = parent;
                        continue;
               } 

	        if (iface_info->if_flags & IF_TYPE_PPPOE) {
			//move to parent interface
                        parent = iface_info->pppoe_info.parent;
#ifdef DEVMAN_DEBUG
                        DPA_INFO("%s::moving to parent "
                                        "iface %s id %d\n",
                                        __FUNCTION__, parent->name,
                                        parent->itf_id);
#endif
                        l2_info->pppoe_sess_id = 
				iface_info->pppoe_info.session_id;
			l2_info->add_pppoe_hdr = 1;
			memcpy(&l2_info->ac_mac_addr[0], 
				iface_info->pppoe_info.mac_addr, ETH_ALEN);
                        iface_info = parent;
                        continue;
		}
	        if (iface_info->if_flags & IF_TYPE_TUNNEL) {
			if(iface_info->tunnel_info.parent)
				parent = iface_info->tunnel_info.parent;
			else
				break; // If and When more tunnels are introduced, the parent needs to be used for on floating tunnels.
                        DPA_INFO("%s::moving to parent "
                                        "iface %s id %d\n",
                                        __FUNCTION__, parent->name,
                                        parent->itf_id);
			l3_info->add_tnl_header = 1;
			l3_info->header_size = iface_info->tunnel_info.header_size;
			l3_info->proto = iface_info->tunnel_info.proto;
			l3_info->mode = iface_info->tunnel_info.mode;
			memcpy(l3_info->header, iface_info->tunnel_info.header, l3_info->header_size);
			memcpy(l3_info->local_ip, iface_info->tunnel_info.local_ip, IPV6_ADDRESS_LENGTH);
			memcpy(l3_info->remote_ip, iface_info->tunnel_info.remote_ip, IPV6_ADDRESS_LENGTH);
			if(iface_info->tunnel_info.mode == TNL_MODE_4O6)
			{
				//if(is_ipv6_addr_any(l3_info->remote_ip))
					//memcpy(&l3_info->header_v6.DestinationAddress, tnl_rt_entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
			}
/*
			else if (iface_info->tunnel_info.mode == TNL_MODE_6O4)
			{
				if(!l3_info->remote_ip[0]) // Remote address ANY
					memcpy(&l3_info->header_v4.DestinationAddress, &tnl_rt_entry->Daddr_v4, sizeof(unsigned int));

			}
*/
/*
			if(tnl_rt_entry) // Floating tunnel, tunnel route part of per connection information
				memcpy(&l2_info->l2hdr[0], tnl_rt_entry->dstmac,
					ETHER_ADDR_LEN);
			else // Static tunnel, tunnel route part of the tunnel when created
*/
				memcpy(&l2_info->l2hdr[0], iface_info->tunnel_info.dstmac,
					ETHER_ADDR_LEN);
                        iface_info = parent;
			continue;

		} else {
               		DPA_INFO("%s::iface type %x not "
                                        "supported \n",
                                        __FUNCTION__, iface_info->if_flags);
			break;
               }
	}
        spin_unlock(&dpa_devlist_lock);
        return retval;
}

int dpa_get_vlan_iface_stats_entries(struct _itf *input_itf, struct _itf *underlying_input_itf,
                                        uint8_t *offsets, uint32_t type)
{
        struct dpa_iface_info *iface_info;

        iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index){
check_parent:
			if (iface_info->if_flags & IF_TYPE_ETHERNET) {
#ifdef DEVMAN_DEBUG
				printk("%s::eth if, ptr %p\n", __FUNCTION__, offsets);
#endif
				return SUCCESS;
			}
			if (iface_info->if_flags & IF_TYPE_WLAN) {
#ifdef DEVMAN_DEBUG
				printk("%s::wlan if, ptr %p\n", __FUNCTION__, offsets);
#endif
                                return SUCCESS;		
			}
			if (iface_info->if_flags & IF_TYPE_VLAN)
			{
				if (type == TX_IFSTATS) {
					*offsets = iface_info->txstats_index;
#ifdef DEVMAN_DEBUG
					printk("%s::filled offset %d at %p\n", 
						__FUNCTION__, *offsets, offsets);
#endif
					offsets--;
				} else {
					*offsets = iface_info->rxstats_index;
#ifdef DEVMAN_DEBUG
					printk("%s::filled offset %d at %p\n", 
						__FUNCTION__, *offsets, offsets);
#endif
					offsets++;
				}
				iface_info = iface_info->vlan_info.parent;
				goto check_parent;
			}
			if (iface_info->if_flags & IF_TYPE_PPPOE)
			{
#ifdef DEVMAN_DEBUG
				printk("%s::pppoe if\n", __FUNCTION__);
#endif
				iface_info = iface_info->pppoe_info.parent;
				goto check_parent;
			}
 			if (iface_info->if_flags & IF_TYPE_TUNNEL)
			{
#ifdef DEVMAN_DEBUG
				printk("%s::tunnel if\n", __FUNCTION__);
#endif
 				iface_info = dpa_get_ifinfo_by_itfid(underlying_input_itf->index);
 				if(!iface_info)
 					return FAILURE;
  				goto check_parent;	
			}
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__FUNCTION__, iface_info->if_flags);
			break;
		} 
		iface_info = iface_info->next;
	}
	return FAILURE;
}

int dpa_get_num_vlan_iface_stats_entries(struct _itf *input_itf, struct _itf *underlying_input_itf,
					uint32_t *num_entries)
{
        struct dpa_iface_info *iface_info;
	uint32_t max_stats;

        iface_info = dpa_interface_info;
	max_stats = 0;
	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index) {
check_parent:
			if (iface_info->if_flags & IF_TYPE_ETHERNET) {
				*num_entries = max_stats;
#ifdef DEVMAN_DEBUG
				printk("%s::eth if, max %d\n", __FUNCTION__, max_stats);
#endif
				return SUCCESS;
			}
			if (iface_info->if_flags & IF_TYPE_WLAN) {
#ifdef DEVMAN_DEBUG
				printk("%s::wlan if, max %d\n", __FUNCTION__, max_stats);
#endif
				*num_entries = max_stats;
                                return SUCCESS;		
			}
			if (iface_info->if_flags & IF_TYPE_VLAN)
			{
#ifdef DEVMAN_DEBUG
				printk("%s::vlan if, max %d\n", __FUNCTION__, max_stats);
#endif
				max_stats++;
				iface_info = iface_info->vlan_info.parent;
				goto check_parent;
			}
			if (iface_info->if_flags & IF_TYPE_PPPOE)
			{
#ifdef DEVMAN_DEBUG
				printk("%s::pppoe if\n", __FUNCTION__);
#endif
				iface_info = iface_info->pppoe_info.parent;
				goto check_parent;
			}
 			if (iface_info->if_flags & IF_TYPE_TUNNEL)
			{
#ifdef DEVMAN_DEBUG
				printk("%s::tunnel if\n", __FUNCTION__);
#endif
 				iface_info = dpa_get_ifinfo_by_itfid(underlying_input_itf->index);
 				if(!iface_info)
 					return FAILURE;
  				goto check_parent;	
			}
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__FUNCTION__, iface_info->if_flags);
			break;
		} 
		iface_info = iface_info->next;
	}
	return FAILURE;
}

int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info, PRouteEntry tnl_rt_entry,
                                uint32_t queue_no)
{

        uint32_t index;
        uint32_t itf_id;
        struct dpa_iface_info *iface_info;
        struct dpa_iface_info *parent;
	int retval = FAILURE;

	memset(l2_info, 0, sizeof(struct dpa_l2hdr_info));
	memset(l3_info, 0, sizeof(struct dpa_l3hdr_info));
	//decide if vlan strip hm is required
	spin_lock(&dpa_devlist_lock);
	if(!rt_entry->input_itf || !rt_entry->underlying_input_itf)
	{
		DPA_ERROR("%s::NULL Input interface \n",
                        __FUNCTION__);
        goto err_ret;
	}

	if (dpa_check_for_logical_iface_types(rt_entry->input_itf, rt_entry->underlying_input_itf, 
			l2_info, l3_info)) {
		DPA_ERROR("%s::get_iface_type failed iface %d\n", 
			__FUNCTION__,  rt_entry->input_itf->index);
		goto err_ret;
	} 
	itf_id = rt_entry->itf->index;
	iface_info = dpa_get_ifinfo_by_itfid(itf_id);
	l2_info->mtu = rt_entry->mtu;
        while (1) {
                if (!iface_info)
                        break;

		if (iface_info->if_flags & IF_TYPE_WLAN) {
			POnifDesc wlan_onif;
			struct physical_port* itf = NULL;
			
			wlan_onif = get_onif_by_index(rt_entry->onif_index);
			if(wlan_onif)
			{
				itf = (struct physical_port*) wlan_onif->itf;
				if (!itf)
				{
					goto err_ret;
				}
			}

                        if(!(NULL_MAC_ADDR(l2_info->l2hdr)))
                                memcpy(&l2_info->l2hdr[0], rt_entry->dstmac,
                                                ETHER_ADDR_LEN);
                        memcpy(&l2_info->l2hdr[ETHER_ADDR_LEN],
                                        itf->mac_addr,
                                        ETHER_ADDR_LEN);
                        dpaa_get_vap_fwd_fq(iface_info->wlan_info.vap_id, &l2_info->fqid);

                        retval = SUCCESS;
                        break;
                }

                //search list for matching id
                if (iface_info->if_flags & IF_TYPE_ETHERNET) {
                	struct eth_iface_info *eth_info;

                        eth_info = &iface_info->eth_info;
#ifdef INCLUDE_ETHER_IFSTATS
			l2_info->ether_stats_offset = 
				iface_info->txstats_index;
#endif

			if(!(NULL_MAC_ADDR(l2_info->l2hdr)))
				memcpy(&l2_info->l2hdr[0], rt_entry->dstmac,
						ETHER_ADDR_LEN);
			memcpy(&l2_info->l2hdr[ETHER_ADDR_LEN], 
					eth_info->mac_addr,
					ETHER_ADDR_LEN);
			index = eth_info->tx_index;
                        if(cdx_ceetm_IsShaperEnabled(eth_info->fman_idx, eth_info->port_idx))
                        {
                          l2_info->fqid = cdx_ceetm_get_lfqid(eth_info->fman_idx,eth_info->port_idx,queue_no);
#ifdef DEVMAN_DEBUG
                          printk("%s::%d FQID:%d \r\n",__FUNCTION__, __LINE__, l2_info->fqid );
#endif
                          retval = SUCCESS;
                          break;
                        }
#ifdef USE_MULTIPLE_TX_FQS
                        //spread it among the TX FQs
                        if (eth_info->tx_index ==
                                	(DPAA_FWD_TX_QUEUES - 1))
	                        eth_info->tx_index = 0;
        	        else
                		eth_info->tx_index++;
                        l2_info->fqid = 
				  eth_info->fwd_tx_fqinfo[eth_info->tx_index].fqid;
#else
                        l2_info->fqid = 
				eth_info->fwd_tx_fqinfo[0].fqid;
#endif
        		retval = SUCCESS;
                        break;
                } 
	        if (iface_info->if_flags & IF_TYPE_VLAN) {
			if (l2_info->num_egress_vlan_hdrs ==
					DPA_CLS_HM_MAX_VLANs) {
                        	DPA_INFO("%s::too many vlan "
                                        	"headers \n",
                                        	__FUNCTION__); 
				break;
			}
                        //move to parent interface
                        parent = iface_info->vlan_info.parent;
#ifdef DEVMAN_DEBUG
                        DPA_INFO("%s::moving to parent "
                                	"iface %s id %d\n",
                                        __FUNCTION__, parent->name,
                                        parent->itf_id);
#endif
			l2_info->egress_vlan_hdrs[l2_info->num_egress_vlan_hdrs].tpid = 0x8100;
			l2_info->egress_vlan_hdrs[l2_info->num_egress_vlan_hdrs].tci = 
				iface_info->vlan_info.vlan_id;
#ifdef INCLUDE_VLAN_IFSTATS
			//get stats index also
			l2_info->vlan_stats_offsets[l2_info->num_egress_vlan_hdrs] = 
				iface_info->txstats_index;	
#ifdef DEVMAN_DEBUG
			printk("%s::vlan tx stats offset %d\n", __FUNCTION__,
				iface_info->txstats_index);
#endif
#endif
			l2_info->num_egress_vlan_hdrs++;
			iface_info = parent;
                        continue;
               } 

	        if (iface_info->if_flags & IF_TYPE_PPPOE) {
			//move to parent interface
                        parent = iface_info->pppoe_info.parent;
#ifdef DEVMAN_DEBUG
                        DPA_INFO("%s::moving to parent "
                                        "iface %s id %d\n",
                                        __FUNCTION__, parent->name,
                                        parent->itf_id);
#endif
                        l2_info->pppoe_sess_id = 
				iface_info->pppoe_info.session_id;
			l2_info->add_pppoe_hdr = 1;
			memcpy(&l2_info->ac_mac_addr[0], 
				iface_info->pppoe_info.mac_addr, ETH_ALEN);
#ifdef INCLUDE_VLAN_IFSTATS
			//save index for tx stats
			l2_info->pppoe_stats_offset = iface_info->txstats_index;
#endif
                        iface_info = parent;
                        continue;
		}
	        if (iface_info->if_flags & IF_TYPE_TUNNEL) {
			if(tnl_rt_entry)
				parent = dpa_get_ifinfo_by_itfid(tnl_rt_entry->itf->index);
			else if(iface_info->tunnel_info.parent)
				parent = iface_info->tunnel_info.parent;
			else
				break; // If and When more tunnels are introduced, the parent needs to be used for on floating tunnels.
#ifdef DEVMAN_DEBUG
                        DPA_INFO("%s::moving to parent "
                                        "iface %s id %d\n",
                                        __FUNCTION__, parent->name,
                                        parent->itf_id);
#endif
			l3_info->add_tnl_header = 1;
			l3_info->header_size = iface_info->tunnel_info.header_size;
			l3_info->proto = iface_info->tunnel_info.proto;
			l3_info->mode = iface_info->tunnel_info.mode;
			memcpy(l3_info->header, iface_info->tunnel_info.header, l3_info->header_size);
			memcpy(l3_info->local_ip, iface_info->tunnel_info.local_ip, IPV6_ADDRESS_LENGTH);
			memcpy(l3_info->remote_ip, iface_info->tunnel_info.remote_ip, IPV6_ADDRESS_LENGTH);
			if(iface_info->tunnel_info.mode == TNL_MODE_4O6)
			{
				if(is_ipv6_addr_any(l3_info->remote_ip))
					memcpy(&l3_info->header_v6.DestinationAddress, tnl_rt_entry->Daddr_v6, IPV6_ADDRESS_LENGTH);
			}
			else if (iface_info->tunnel_info.mode == TNL_MODE_6O4)
			{
				if(!l3_info->remote_ip[0]) // Remote address ANY
					memcpy(&l3_info->header_v4.DestinationAddress, &tnl_rt_entry->Daddr_v4, sizeof(unsigned int));
			}
			if(tnl_rt_entry) // Floating tunnel, tunnel route part of per connection information
				memcpy(&l2_info->l2hdr[0], tnl_rt_entry->dstmac,
					ETHER_ADDR_LEN);
			else // Static tunnel, tunnel route part of the tunnel when created
				memcpy(&l2_info->l2hdr[0], iface_info->tunnel_info.dstmac,
					ETHER_ADDR_LEN);
                        iface_info = parent;
			continue;

		} else {
               		DPA_INFO("%s::iface type %x not "
                                        "supported \n",
                                        __FUNCTION__, iface_info->if_flags);
			break;
               }
	}
err_ret:
        spin_unlock(&dpa_devlist_lock);
        return retval;
}

int dpa_get_tx_fqid_by_name(char *name, uint32_t *fqid)
{
        struct dpa_iface_info *iface_info;
	spin_lock(&dpa_devlist_lock);
        iface_info = dpa_interface_info;
	while(1) {
		if (!iface_info)
			break;
		if (strcmp(name, iface_info->name) == 0)
		{
                	struct eth_iface_info *eth_info;

			iface_info =  dpa_get_phys_iface(iface_info);
			if (!iface_info) {
				DPA_INFO("%s:: iface info null\n", __FUNCTION__);
				break;
			}

			if (!(iface_info->if_flags & IF_TYPE_ETHERNET) && !(iface_info->if_flags & IF_TYPE_WLAN))
				break;
			if (iface_info->if_flags & IF_TYPE_WLAN)
			{
				dpaa_get_vap_fwd_fq(iface_info->wlan_info.vap_id, fqid);
#ifdef DEVMAN_DEBUG
				DPA_INFO("%s:: wlan tx fqid :%d: %x\n", __func__, *fqid, *fqid);
#endif
			}
			else
			{
				eth_info = &iface_info->eth_info;
				*fqid = eth_info->fwd_tx_fqinfo[eth_info->tx_index].fqid;
			}
			spin_unlock(&dpa_devlist_lock);
			return 0;
		}
		iface_info = iface_info->next;
	}
        spin_unlock(&dpa_devlist_lock);
	return -1;
}

int dpa_get_ifstatsinfo_by_name(char *name, uint32_t *rxstats_index, 
		uint32_t *txstats_index)
{
#ifdef INCLUDE_IFSTATS_SUPPORT
	struct dpa_iface_info *iface_info;
	int retval;

	retval = -1;	
	spin_lock(&dpa_devlist_lock);
        iface_info = dpa_interface_info;
	while (1) {
                if (!iface_info)
                        break;	
		if (strcmp (iface_info->name, name) == 0) {
			*rxstats_index = iface_info->rxstats_index;	
			*txstats_index = iface_info->txstats_index;		
			retval = 0;
			break;
		}
		iface_info = iface_info->next;
        }
        spin_unlock(&dpa_devlist_lock);
        return retval;
#else
	return -1;
#endif
}


struct dpa_iface_info *dpa_get_phys_iface(struct dpa_iface_info *iface_info)
{
	while (1) {
		if (!iface_info)
			break;
		if ((iface_info->if_flags & IF_TYPE_ETHERNET) || (iface_info->if_flags & IF_TYPE_WLAN))
			break;
		else if (iface_info->if_flags & IF_TYPE_VLAN)
			iface_info = iface_info->vlan_info.parent;
		else if (iface_info->if_flags & IF_TYPE_PPPOE)
			iface_info = iface_info->pppoe_info.parent;
		else
			return NULL;
	}
	return iface_info;
}


//get interface mac address and transmit fqid based on itf_id
int dpa_get_tx_param_by_itf(uint32_t itf_id, uint32_t *fqid, uint8_t *mac_addr)
{
        int retval;
	uint32_t index;
        struct dpa_iface_info *iface_info;

        spin_lock(&dpa_devlist_lock);
        iface_info = dpa_interface_info;
        retval = FAILURE;
        while (1) {
		if (!iface_info)
			break;
		//search list for matching id
		if (iface_info->itf_id == itf_id) {
                        if (iface_info->if_flags & IF_TYPE_ETHERNET) {
                                struct eth_iface_info *eth_info;
                                eth_info = &iface_info->eth_info;
				index = eth_info->tx_index;
				//spread it among the TX FQs
#if 0
				if (eth_info->tx_index == 
					(DPAA_FWD_TX_QUEUES - 1))
					eth_info->tx_index = 0;
				else
					eth_info->tx_index++;
#endif
                                *fqid = eth_info->fwd_tx_fqinfo[index].fqid;
				memcpy(mac_addr, eth_info->mac_addr,
                                        ETH_ALEN);
                                retval = SUCCESS;
				break;
                        } 
			else if (iface_info->if_flags & IF_TYPE_WLAN)
			{
				dpaa_get_vap_fwd_fq(iface_info->wlan_info.vap_id, fqid);
				memcpy(mac_addr, iface_info->wlan_info.mac_addr, ETH_ALEN);
			}
			else {
				if (iface_info->if_flags & IF_TYPE_VLAN) {
					struct dpa_iface_info *parent;

					//move to parent interface
					parent = iface_info->vlan_info.parent;
					itf_id = parent->itf_id;
					iface_info = dpa_interface_info;
#ifdef DEVMAN_DEBUG
					DPA_INFO("%s::moving to parent "
						"iface %s id %d\n",
						__FUNCTION__, parent->name,
						itf_id);
#endif
					continue;
				} else {
					DPA_INFO("%s::iface type %x not "
					"supported \n",
					__FUNCTION__, iface_info->if_flags);
					break;
				}
                        }
                }
                iface_info = iface_info->next;
        }
        spin_unlock(&dpa_devlist_lock);
        return retval;
}

int dpa_get_pppoe_iface_stats_entries(struct _itf *input_itf,
			uint8_t *offset, uint8_t type)
{
        struct dpa_iface_info *iface_info;
        iface_info = dpa_interface_info;

	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index) {
			if (iface_info->if_flags & IF_TYPE_PPPOE)
			{
				if (type == TX_IFSTATS) {
					*offset = iface_info->txstats_index;
#ifdef DEVMAN_DEBUG 
					DPA_INFO("%s::tx offset %d\n", 
						__FUNCTION__, *offset);
#endif
				} else {
					*offset = iface_info->rxstats_index;
#ifdef DEVMAN_DEBUG 
					DPA_INFO("%s::rx offset %d\n", 
						__FUNCTION__, *offset);
#endif
				}
				
				return SUCCESS;
			}
		}
		iface_info = iface_info->next;
	}
	return FAILURE;
}

int dpa_get_tunnel_iface_stats_entries(struct _itf *input_itf,
			uint8_t *offset, uint8_t type)
{
        struct dpa_iface_info *iface_info;
        iface_info = dpa_interface_info;

	while(iface_info) {
		if (iface_info->itf_id  == input_itf->index) {
			if (iface_info->if_flags & IF_TYPE_TUNNEL)
			{
				if (type == TX_IFSTATS) {
					*offset = iface_info->txstats_index;
#ifdef DEVMAN_DEBUG
					DPA_INFO("%s::tx offset %d\n", 
						__FUNCTION__, *offset);
#endif
				} else {
					*offset = iface_info->rxstats_index;
#ifdef DEVMAN_DEBUG
					DPA_INFO("%s::rx offset %d\n", 
						__FUNCTION__, *offset);
#endif
				}
				
				return SUCCESS;
			}
		}
		iface_info = iface_info->next;
	}
	return FAILURE;
}

int dpa_get_ether_iface_stats_entries(struct _itf *input_itf,
			struct _itf *underlying_input_itf,
			uint8_t *offset, uint8_t type)
{

        struct dpa_iface_info *iface_info;

        iface_info = dpa_interface_info;
	while(iface_info) {
		if (iface_info->itf_id == input_itf->index) {
check_parent:
			if (iface_info->if_flags & (IF_TYPE_ETHERNET | IF_TYPE_WLAN)) {
				if (type == TX_IFSTATS) {
					*offset = iface_info->txstats_index;
#ifdef DEVMAN_DEBUG
					DPA_INFO("%s::filled offset %d\n", 
						__FUNCTION__, *offset);
#endif
				} else {
					*offset = iface_info->rxstats_index;
#ifdef DEVMAN_DEBUG
					DPA_INFO("%s::filled offset %d\n", 
						__FUNCTION__, *offset);
#endif
				}
				return SUCCESS;
			}
			if (iface_info->if_flags & IF_TYPE_VLAN)
			{
				iface_info = iface_info->vlan_info.parent;
				goto check_parent;
			}
			if (iface_info->if_flags & IF_TYPE_PPPOE)
			{
				iface_info = iface_info->pppoe_info.parent;
				goto check_parent;
			}
 			if (iface_info->if_flags & IF_TYPE_TUNNEL)
			{
 				iface_info = dpa_get_ifinfo_by_itfid(underlying_input_itf->index);
 				if(!iface_info)
 					return FAILURE;
  				goto check_parent;	
			}
			DPA_ERROR("%s::unsupported type 0x%x\n",
					__FUNCTION__, iface_info->if_flags);
			break;
		} 
		iface_info = iface_info->next;
	}
	return FAILURE;
}


//free device resources
void dpa_release_iflist(void)
{
	struct dpa_iface_info *iface_info;
	while (dpa_interface_info) {
		iface_info = dpa_interface_info;
		dpa_interface_info = iface_info->next;
		kfree(iface_info);
	}
}


static void free_stats(struct dpa_iface_info *info)
{
	
	if(info->if_flags & IF_TYPE_PPPOE) {
		free_iface_stats(IF_TYPE_PPPOE, info->stats);
		return;
	}
	if(info->if_flags & IF_TYPE_VLAN) {
		free_iface_stats(IF_TYPE_VLAN, info->stats);
		return;
	}
	if(info->if_flags & IF_TYPE_TUNNEL) {
		free_iface_stats(IF_TYPE_TUNNEL, info->stats);
		return;
	}
	return;
}

//remove dpa interface
void dpa_release_interface(uint32_t itf_id)
{
	struct dpa_iface_info *prev_info;
	struct dpa_iface_info *curr_info;

	prev_info = NULL;
	spin_lock(&dpa_devlist_lock);
	curr_info = dpa_interface_info;
	while (curr_info) {
		if(curr_info->itf_id == itf_id) {
			if (prev_info)
				prev_info->next = curr_info->next;
			else {
				dpa_interface_info =  curr_info->next;
#ifdef DEVMAN_DEBUG
			printk("%s::removed iface %s, type %d\n",
				__FUNCTION__, curr_info->name,
				curr_info->if_flags);
#endif		
				//free stats
				free_stats(curr_info);
				//free iface structure 
				kfree(curr_info);
			}
			goto func_ret;
		}
		prev_info = curr_info;
		curr_info = curr_info->next;
	}
func_ret:
        spin_unlock(&dpa_devlist_lock);
}


//get mac address by name
int dpa_get_mac_addr(char *name, char *mac_addr)
{
	struct dpa_iface_info *iface_info;
	int retval;

	retval = -1;
	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while (iface_info) {
		//look for ethernet device
		if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			//match name
			if (strcmp (name, iface_info->name) == 0) {
				memcpy(mac_addr, iface_info->eth_info.mac_addr,
					ETH_ALEN);
				retval = 0;
				break;
			}
		}
		iface_info = iface_info->next;
	}
	spin_unlock(&dpa_devlist_lock);
	return retval;
}


int dpa_add_eth_if(char *name, struct _itf *itf, struct _itf *phys_itf) 
{
	struct dpa_iface_info *iface_info;

	//ethernet/physical iface type
	iface_info = (struct dpa_iface_info *)
			kzalloc(sizeof(struct dpa_iface_info), 0);  
	if (!iface_info) {
		DPA_ERROR("%s::no mem for eth dev info size %d\n", 
					__FUNCTION__, 
				(uint32_t)sizeof(struct dpa_iface_info));
        	return FAILURE;
	}
	memset(iface_info, 0, sizeof(struct dpa_iface_info));
	iface_info->itf_id = itf->index;
	iface_info->if_flags = itf->type;
	//get iface from os device
	if (get_eth_iface_info(iface_info, name))
		goto err_ret;
	//get rest of info from config 
	if (get_dpa_eth_iface_info(&iface_info->eth_info, name)) {
		DPA_ERROR("%s::get_dpa_eth_iface_info failed %s\n", 
					__FUNCTION__, name); 
		goto err_ret;
	}
#ifdef INCLUDE_ETHER_IFSTATS
	iface_info->stats = alloc_iface_stats(itf->type,
                                &iface_info->rxstats_index, &iface_info->txstats_index);
        if (!iface_info->stats) {
                spin_unlock(&dpa_devlist_lock);
                DPA_ERROR("%s:: alloc_iface_stats failed\n", __FUNCTION__);
                goto err_ret;
        }
        iface_info->if_flags |= IF_STATS_ENABLED;
#endif
#ifdef DEVMAN_DEBUG
	display_iface_info(iface_info);
#endif
	//add to list
	if (dpa_add_port_to_list(iface_info)) {
		DPA_ERROR("%s::get_dpa_eth_iface_info failed\n", 
					__FUNCTION__); 
		goto err_ret;
	}
	return SUCCESS;
err_ret:
	kfree(iface_info);
	return FAILURE;
}

extern int insert_entry_in_pppoe_table(int fm_idx, int port_idx,
                        uint8_t *ac_mac_addr, uint32_t sessid,
                        uint32_t ppp_pid);
#ifdef PPPoE_IF_SUPPORT
int dpa_add_pppoe_if(char *name, struct _itf *itf, struct _itf *phys_itf, 
		uint8_t *mac_addr, uint16_t session_id) 
{
	struct dpa_iface_info *iface_info;
	struct dpa_iface_info *parent;

	if (!(phys_itf)) {
		DPA_ERROR("%s::null dev for phys_itf\n", 
					__FUNCTION__); 
        	return FAILURE;
	}
	if (!(itf->phys)) {
		DPA_ERROR("%s::null dev for lower iface\n", 
					__FUNCTION__); 
        	return FAILURE;
	}

	iface_info = (struct dpa_iface_info *)
			kzalloc(sizeof(struct dpa_iface_info), 0);  
	if (!iface_info) {
		DPA_ERROR("%s::no mem for pppoe dev info size %d\n", 
					__FUNCTION__, 
				(uint32_t)sizeof(struct dpa_iface_info));
        	return FAILURE;
	}
	memset(iface_info, 0, sizeof(struct dpa_iface_info));
	iface_info->itf_id = itf->index;
	iface_info->if_flags = itf->type;
	strncpy(&iface_info->name[0], name, IF_NAME_SIZE);

	iface_info->pppoe_info.session_id = htons(session_id);
	memcpy(&iface_info->pppoe_info.mac_addr[0], mac_addr, ETH_ALEN);
        spin_lock(&dpa_devlist_lock);
	parent = dpa_get_ifinfo_by_itfid(itf->phys->index);
	if (!parent) {
		DPA_ERROR("%s::no ifinfo for dev idx %d\n", 
					__FUNCTION__, itf->index);
        	spin_unlock(&dpa_devlist_lock);
		goto err_ret;
	}
	iface_info->pppoe_info.parent = parent;
	//inherit parents mtu as default
	iface_info->mtu = parent->mtu;
#ifdef INCLUDE_PPPoE_IFSTATS
	iface_info->stats = alloc_iface_stats(itf->type, 
				&iface_info->rxstats_index, &iface_info->txstats_index);
	if (!iface_info->stats) {
        	spin_unlock(&dpa_devlist_lock);
                DPA_ERROR("%s:: alloc_iface_stats failed\n", __FUNCTION__);
                goto err_ret;
        }
	iface_info->if_flags |= IF_STATS_ENABLED;
#endif
        spin_unlock(&dpa_devlist_lock);
#ifdef DEVMAN_DEBUG
	display_iface_info(iface_info);
#endif
	//add to list
	if (dpa_add_port_to_list(iface_info)) {
		DPA_ERROR("%s::get_dpa_eth_iface_info failed\n", 
					__FUNCTION__); 
		goto err_ret;
	}
#if 0
	//add entry to pppoe table
	if (insert_entry_in_pppoe_table(parent->eth_info.fman_idx, 
		parent->eth_info.port_idx, mac_addr, session_id, PPP_IP)) {
		DPA_ERROR("%s::insert_entry_in_pppoe_table failed\n", 
					__FUNCTION__); 
		//remove it from our list
		dpa_release_interface(itf->index);
		goto err_ret;
	}
#endif
	return SUCCESS;
err_ret:
	kfree(iface_info);
	return FAILURE;
}
#else
int dpa_add_pppoe_if(char *name, struct _itf *itf, struct _itf *phys_itf, 
		uint16_t vlan_id) 
{
	DPA_ERROR("%s::pppoe iface not supported define PPPoE_IF_SUPPORT\n", 
					__FUNCTION__); 
	return FAILURE;
}
#endif

#ifdef VLAN_IF_SUPPORT
int dpa_add_vlan_if(char *name, struct _itf *itf, struct _itf *phys_itf, 
		uint16_t vlan_id) 
{
	struct dpa_iface_info *iface_info;
	struct dpa_iface_info *parent;

	if (!(phys_itf)) {
		DPA_ERROR("%s::null dev for phys_itf\n", 
					__FUNCTION__); 
        	return FAILURE;
	}
	if (!(itf->phys)) {
		DPA_ERROR("%s::null dev for lower iface\n", 
					__FUNCTION__); 
        	return FAILURE;
	}

	//ethernet/physical iface type
	iface_info = (struct dpa_iface_info *)
			kzalloc(sizeof(struct dpa_iface_info), 0);  
	if (!iface_info) {
		DPA_ERROR("%s::no mem for eth dev info size %d\n", 
					__FUNCTION__, 
				(uint32_t)sizeof(struct dpa_iface_info));
        	return FAILURE;
	}
	memset(iface_info, 0, sizeof(struct dpa_iface_info));
	iface_info->itf_id = itf->index;
	iface_info->if_flags = itf->type;
	strncpy(&iface_info->name[0], name, IF_NAME_SIZE);

	iface_info->vlan_info.vlan_id = htons(vlan_id);
        spin_lock(&dpa_devlist_lock);
	parent = dpa_get_ifinfo_by_itfid(itf->phys->index);
	if (!parent) {
		DPA_ERROR("%s::no ifinfo for dev idx %d\n", 
					__FUNCTION__, itf->index);
        	spin_unlock(&dpa_devlist_lock);
		goto err_ret;
	}
	iface_info->vlan_info.parent = parent;
	//inherit parents mtu as default
	iface_info->mtu = parent->mtu;
	//allocate interface statistics memory
#ifdef INCLUDE_VLAN_IFSTATS
	iface_info->stats = alloc_iface_stats(itf->type, 
				&iface_info->rxstats_index, &iface_info->txstats_index);
	if (!iface_info->stats) {
        	spin_unlock(&dpa_devlist_lock);
                DPA_ERROR("%s:: alloc_iface_stats failed\n", __FUNCTION__);
                goto err_ret;
        }
	iface_info->if_flags |= IF_STATS_ENABLED;
#endif
        spin_unlock(&dpa_devlist_lock);
#ifdef DEVMAN_DEBUG
	display_iface_info(iface_info);
#endif
	//add to list
	if (dpa_add_port_to_list(iface_info)) {
		DPA_ERROR("%s::get_dpa_eth_iface_info failed\n", 
					__FUNCTION__); 
		goto err_ret;
	}
	return SUCCESS;
err_ret:
	kfree(iface_info);
	return FAILURE;
}
#else
int dpa_add_vlan_if(char *name, struct _itf *itf, struct _itf *phys_itf, 
		uint16_t vlan_id) 
{
	DPA_ERROR("%s::vlan iface not supported define VLAN_IF_SUPPORT\n", 
					__FUNCTION__); 
	return FAILURE;
}
#endif

//get interface information from OS device priv structure
static int get_wlan_iface_info(struct dpa_iface_info *iface_info)
{
	struct net_device *device;
	uint32_t ohport_handle;

	device = dev_get_by_name(&init_net, iface_info->name);
	if (!device) {
		DPA_INFO("%s::could not find device %s\n", __FUNCTION__, iface_info->name);
		return FAILURE;
	}
	iface_info->mtu = device->mtu;
	dev_put(device);

	dpaa_get_wifi_ohport_handle(&ohport_handle);
	DPA_INFO("%s::OH port handle  %d\n", __FUNCTION__, ohport_handle);

	get_ofport_fman_and_portindex(FMAN_IDX, ohport_handle, &iface_info->wlan_info.fman_idx, 
		&iface_info->wlan_info.port_idx, &iface_info->wlan_info.portid);
	DPA_INFO("%s::fman_idx: %d port_idx: %d\n", __FUNCTION__, iface_info->wlan_info.fman_idx, iface_info->wlan_info.port_idx);
	return SUCCESS;
}

int dpa_add_wlan_if(char *name, struct _itf *itf, uint32_t vap_id, unsigned char* mac)
{
        struct dpa_iface_info *iface_info;

        //ethernet/physical iface type
        iface_info = (struct dpa_iface_info *)
                        kzalloc(sizeof(struct dpa_iface_info), 0);
        if (!iface_info) {
                DPA_ERROR("%s::no mem for eth dev info size %d\n",
                                        __FUNCTION__,
                                (uint32_t)sizeof(struct dpa_iface_info));
                return FAILURE;
        }
        memset(iface_info, 0, sizeof(struct dpa_iface_info));
        iface_info->itf_id = itf->index;
        iface_info->if_flags = itf->type;
        strncpy(&iface_info->name[0], name, IF_NAME_SIZE);
        iface_info->wlan_info.vap_id = vap_id;
	memcpy(&iface_info->wlan_info.mac_addr[0], mac, ETH_ALEN); 
	get_wlan_iface_info(iface_info);

#ifdef DEVMAN_DEBUG
#error fdv
        display_iface_info(iface_info);
#endif
        //add to list
        if (dpa_add_port_to_list(iface_info)) {
                DPA_ERROR("%s::get_dpa_eth_iface_info failed\n",
                                        __FUNCTION__);
                goto err_ret;
        }

        return SUCCESS;
err_ret:
        kfree(iface_info);
        return FAILURE;
}

//get fm and port index from itf_index
int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index , 
			uint32_t *fm_index, uint32_t *port_index,
			uint32_t *portid)
{
	struct dpa_iface_info *iface_info;
	struct dpa_iface_info *parent = NULL;

	iface_info = dpa_interface_info;
	while (1) {
		if (!iface_info)
			break;
		//match itf index
		if (iface_info->itf_id == itf_index) {
			if (iface_info->if_flags & IF_TYPE_ETHERNET) {
				//ensure it is ethernet and return params
				*fm_index = iface_info->eth_info.fman_idx;
				*port_index = iface_info->eth_info.port_idx;
				if (portid)
					*portid = iface_info->eth_info.portid;
				return 0;
			}
			if (iface_info->if_flags & IF_TYPE_WLAN) {
                                //ensure it is wifi and return params
                                *fm_index = iface_info->wlan_info.fman_idx;
                                *port_index = iface_info->wlan_info.port_idx;
				if (portid)
					*portid = iface_info->wlan_info.portid;
                                return 0;
                        }
			
			if (iface_info->if_flags & (IF_TYPE_VLAN | IF_TYPE_PPPOE)) {
				struct dpa_iface_info *parent;

				parent = iface_info->vlan_info.parent;
				iface_info = dpa_interface_info;
				itf_index = parent->itf_id;
#ifdef DEVMAN_DEBUG
				DPA_INFO("%s::moving to parent "
                                                "iface %s id %d\n",
                                                __FUNCTION__, parent->name,
                                                itf_index);
#endif
				continue;
			}
 			if(iface_info->if_flags & IF_TYPE_TUNNEL)  
 			{
 				if(underlying_iif_index == itf_index)
 				{
 					DPA_ERROR("%s::underlying iface info cannot be same as itf_index\n",
 							__FUNCTION__);
 					return FAILURE;
 				}
 
         			spin_lock(&dpa_devlist_lock);
 				if((parent = dpa_get_ifinfo_by_itfid(underlying_iif_index)) == NULL)
 				{
 					DPA_ERROR("%s::iface info does not exist\n",
 							__FUNCTION__);
					spin_unlock(&dpa_devlist_lock);
 					return FAILURE;
 				}
				spin_unlock(&dpa_devlist_lock);
 
 				iface_info = dpa_interface_info;
 				itf_index = parent->itf_id;

#ifdef DEVMAN_DEBUG
 				DPA_INFO("%s::moving to parent "
 						"iface %s id %d\n",
 						__FUNCTION__, parent->name,
 						itf_index);
#endif
 
 				continue;
			}  else {
				DPA_ERROR("%s::unsupported type 0x%x\n",
						__FUNCTION__, 
						iface_info->if_flags);
				break;
			}
		}
		iface_info = iface_info->next;
	}
	return -1;
}

int dpa_update_tunnel_if(itf_t *itf,  itf_t *phys_itf, PTnlEntry pTunnelEntry)
 {
#ifdef TUNNEL_IF_SUPPORT
 	struct dpa_iface_info *iface_info;	
 	struct dpa_iface_info *parent;	
 
 	if (!(itf)) {
 		DPA_ERROR("%s::null dev for tunnel _itf\n", 
 					__FUNCTION__); 
         	return FAILURE;
 	}
 
        spin_lock(&dpa_devlist_lock);
 	if((iface_info = dpa_get_ifinfo_by_itfid(itf->index)) == NULL){
 
 		DPA_ERROR("%s::iface info does not exist\n", 
 					__FUNCTION__); 
         	spin_unlock(&dpa_devlist_lock);
         	return FAILURE;
 	}
 	iface_info->tunnel_info.mode = pTunnelEntry->mode;
 	if (iface_info->tunnel_info.mode == TNL_MODE_6O4)
 		iface_info->tunnel_info.proto = PROTO_IPV4; 
 	if (iface_info->tunnel_info.mode == TNL_MODE_4O6)
 		iface_info->tunnel_info.proto = PROTO_IPV6; 
 	iface_info->tunnel_info.header_size = pTunnelEntry->header_size;
 	memcpy(&iface_info->tunnel_info.local_ip, pTunnelEntry->local, IPV6_ADDRESS_LENGTH);
 	memcpy(&iface_info->tunnel_info.remote_ip, pTunnelEntry->remote, IPV6_ADDRESS_LENGTH);
 	memcpy(&iface_info->tunnel_info.header, pTunnelEntry->header, pTunnelEntry->header_size);
 	if(phys_itf)
 	{
 		parent = dpa_get_ifinfo_by_itfid(phys_itf->index);
 		if (!parent) {
 			DPA_ERROR("%s::no ifinfo for dev idx %d\n", 
 					__FUNCTION__, pTunnelEntry->itf.phys->index);
 			spin_unlock(&dpa_devlist_lock);
 			return FAILURE;
 		}
 		iface_info->tunnel_info.parent = parent;
 		//inherit parents mtu as default
 		iface_info->mtu = parent->mtu;
 
 		if(pTunnelEntry->pRtEntry)
 			memcpy(&iface_info->tunnel_info.dstmac,
 					pTunnelEntry->pRtEntry->dstmac, ETH_ALEN);
 	}
 	else
 	{
 		iface_info->tunnel_info.parent = NULL;
 		iface_info->mtu = pTunnelEntry->tnl_mtu;
 	}
 
         spin_unlock(&dpa_devlist_lock);
         return SUCCESS;
#else
 	DPA_ERROR("%s::tunnel interfaces not supported\n", __FUNCTION__); 
 	return FAILURE;
#endif
}
 
int dpa_add_tunnel_if(itf_t *itf, itf_t *phys_itf, PTnlEntry pTunnelEntry)
{
#ifdef TUNNEL_IF_SUPPORT
 	struct dpa_iface_info *iface_info;	
 	struct dpa_iface_info *parent;	
 
 
 	if (!(itf)) {
 		DPA_ERROR("%s::null dev for tunnel _itf\n", 
 					__FUNCTION__); 
         	return FAILURE;
 	}
#if 0 
 	if (!(phys_itf)) {
 		DPA_ERROR("%s::null dev for phys_itf\n", 
 					__FUNCTION__); 
         	return FAILURE;
 	}
#endif
 	iface_info = (struct dpa_iface_info *)
 			kzalloc(sizeof(struct dpa_iface_info), 0);  
 	if (!iface_info) {
 		DPA_ERROR("%s::no mem for tunnel dev info size %d\n", 
 					__FUNCTION__, 
 				(uint32_t)sizeof(struct dpa_iface_info));
         	return FAILURE;
 	}
 	memset(iface_info, 0, sizeof(struct dpa_iface_info));
 	iface_info->itf_id = itf->index;
 	iface_info->if_flags = itf->type;
 	strncpy(iface_info->name, pTunnelEntry->tnl_name, IF_NAME_SIZE);
 
 	iface_info->tunnel_info.mode = pTunnelEntry->mode;
 	if (iface_info->tunnel_info.mode == TNL_MODE_6O4)
 		iface_info->tunnel_info.proto = PROTO_IPV4; 
 	if (iface_info->tunnel_info.mode == TNL_MODE_4O6)
 		iface_info->tunnel_info.proto = PROTO_IPV6; 
 	iface_info->tunnel_info.header_size = pTunnelEntry->header_size;
 	memcpy(&iface_info->tunnel_info.local_ip, pTunnelEntry->local, IPV6_ADDRESS_LENGTH);
 	memcpy(&iface_info->tunnel_info.remote_ip, pTunnelEntry->remote, IPV6_ADDRESS_LENGTH);
 	memcpy(&iface_info->tunnel_info.header, pTunnelEntry->header, pTunnelEntry->header_size);
        spin_lock(&dpa_devlist_lock);
 	if(phys_itf)
 	{
 		parent = dpa_get_ifinfo_by_itfid(phys_itf->index);
 		if (!parent) {
 			DPA_ERROR("%s::no ifinfo for dev idx %d\n", 
 					__FUNCTION__, pTunnelEntry->itf.phys->index);
 			spin_unlock(&dpa_devlist_lock);
 			goto err_ret;
 		}
 		iface_info->tunnel_info.parent = parent;
 		//inherit parents mtu as default
 		iface_info->mtu = parent->mtu;
 
 		if(pTunnelEntry->pRtEntry)
 				memcpy(&iface_info->tunnel_info.dstmac, 
 					pTunnelEntry->pRtEntry->dstmac, ETH_ALEN);
 	}
 	else
 	{
 		iface_info->tunnel_info.parent = NULL;
 		iface_info->mtu = pTunnelEntry->tnl_mtu;
 	}
#ifdef INCLUDE_TUNNEL_IFSTATS
	iface_info->stats = alloc_iface_stats(itf->type, 
				&iface_info->rxstats_index, &iface_info->txstats_index);
	if (!iface_info->stats) {
         	spin_unlock(&dpa_devlist_lock);
                DPA_ERROR("%s:: alloc_iface_stats failed\n", __FUNCTION__);
                goto err_ret;
        }
	iface_info->if_flags |= IF_STATS_ENABLED;
#endif
         spin_unlock(&dpa_devlist_lock);
#ifdef DEVMAN_DEBUG
 	display_iface_info(iface_info);
#endif
 	//add to list
 	if (dpa_add_port_to_list(iface_info)) {
 		DPA_ERROR("%s::get_dpa_eth_iface_info failed\n", 
 					__FUNCTION__); 
 		goto err_ret;
 	}
 	return SUCCESS;
err_ret:
 	kfree(iface_info);
 	return FAILURE;
#else
 	DPA_ERROR("%s::tunnel interfaces not supported\n", __FUNCTION__); 
 	return FAILURE;
#endif
}
 
void dpa_update_timestamp(uint32_t ts)
{
	FM_PCD_UpdateExtTimeStamp(EXTERNAL_TIMESTAMP_TIMERID, cpu_to_be32(ts));
}

uint32_t dpa_get_timestamp_addr(uint32_t id)
{
	return(FM_PCD_GetExtTimeStampAddr(id));
}


int cdx_copy_eth_rx_channel_info(uint32_t fman_idx, struct dpa_fq *dpa_fq)
{
        struct dpa_iface_info *iface_info;

        iface_info = dpa_interface_info;
        while(1) {
                 if (!iface_info)
                        break;
                if (iface_info->if_flags & IF_TYPE_ETHERNET) {
                        if (iface_info->eth_info.fman_idx == fman_idx) {
                                dpa_fq->channel = iface_info->eth_info.rx_channel_id;
                                return 0;
                        }
                }
                iface_info = iface_info->next;
        }
        return -1;
}

//create pcd
int cdx_create_fq(struct dpa_fq *dpa_fq, uint32_t flags)
{
        struct qman_fq *fq;
        struct qm_mcc_initfq opts;

        fq = &dpa_fq->fq_base;
        if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
                DPA_ERROR("%s::qman_create_fq failed for fqid %d\n",
                        __FUNCTION__, dpa_fq->fqid);
                return -1;
        }
        memset(&opts, 0, sizeof(struct qm_mcc_initfq));
	if (flags & QMAN_FQ_FLAG_DYNAMIC_FQID)
		dpa_fq->fqid = fq->fqid;
        opts.fqid = dpa_fq->fqid;
        opts.count = 1;
        opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
                                QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
        //opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
        opts.fqd.dest.channel = dpa_fq->channel;
        opts.fqd.dest.wq = dpa_fq->wq;
        opts.fqd.context_a.stashing.exclusive =
                (QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
        opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
        opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
        if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
                DPA_ERROR("%s::qman_init_fq failed for fqid %d\n",
                        __FUNCTION__, dpa_fq->fqid);
                qman_destroy_fq(fq, 0);
                return -1;
        }
#ifdef DEVMAN_DEBUG
        DPA_INFO("%s::created fq 0x%x channel 0x%x\n", __FUNCTION__, 
		dpa_fq->fqid, dpa_fq->channel);
#endif
        return 0;
}


//routine to create all FQs required by distribution in xml file
static int cdxdrv_create_pcd_fqs(struct eth_iface_info *iface_info)
{
	uint32_t ii;
	uint32_t jj;
	struct dpa_fq *dpa_fq;
	uint32_t fqid;	
	uint32_t max_dist;
	struct cdx_dist_info *dist_info;
	uint32_t portal_channel[NR_CPUS];
	uint32_t num_portals;
	uint32_t next_portal_ch_idx;
	const cpumask_t *affine_cpus;

	max_dist = iface_info->max_dist;
	dist_info = iface_info->dist_info;

	num_portals = 0;
	next_portal_ch_idx = 0;
 	affine_cpus = qman_affine_cpus();
	/* get channel used by portals affined to each cpu */
        for_each_cpu(ii, affine_cpus) {
                portal_channel[num_portals] = qman_affine_channel(ii);
		num_portals++;
	}
        if (!num_portals) {
		DPA_ERROR("%s::unable to get affined portal info\n",
						__FUNCTION__);
		return -1;
	}
#ifdef DEVMAN_DEBUG
	DPA_INFO("%s::num_portals %d ::", __FUNCTION__, num_portals);
	for (ii = 0; ii < num_portals; ii++)
		DPA_INFO("%d ", portal_channel[ii]);
	DPA_INFO("\n");
#endif

#ifdef DEVMAN_DEBUG
	DPA_INFO("%s::max dist %d\n", __FUNCTION__, max_dist);	
#endif
	for (ii = 0; ii < max_dist; ii++) {
		fqid = (dist_info->base_fqid + 
			(iface_info->portid << PORTID_SHIFT_VAL));
#ifdef DEVMAN_DEBUG
		DPA_INFO("%s::dist %d, count %d, base %x(%d) fqid %x(%d)\n",
			__FUNCTION__, ii, dist_info->count, 
			dist_info->base_fqid, dist_info->base_fqid,
			fqid, fqid);
#endif
		for (jj = 0; jj < dist_info->count; jj++) {
			if (find_pcd_fq_info(fqid)) {
				dpa_fq = kzalloc(sizeof(struct dpa_fq), 0);
				if (!dpa_fq) {
					DPA_ERROR("%s::unable to alloc mem for fqid %d\n",
						__FUNCTION__, fqid);
					return -1;
				}
				memset(dpa_fq, 0, sizeof(struct dpa_fq));
#ifdef DEVMAN_DEBUG
				DPA_INFO("%s::net dev %p\n", __FUNCTION__,
					iface_info->net_dev);
#endif
				dpa_fq->net_dev = iface_info->net_dev;
				dpa_fq->fqid = fqid;
				dpa_fq->fq_type = FQ_TYPE_RX_PCD;
				//round robin channel ids
				dpa_fq->channel = portal_channel[next_portal_ch_idx];
				if (next_portal_ch_idx == (num_portals - 1))
					next_portal_ch_idx = 0;
				else
					next_portal_ch_idx++;
				//use same wq used by ethernet RX PCD FQs for port
                               	dpa_fq->wq = iface_info->rx_pcd_wq;
                                //use same callback used by ethernet driver 
                                dpa_fq->fq_base.cb.dqrr = iface_info->dqrr;
				//create PCD FQ
				if (cdx_create_fq(dpa_fq, 0)) {
					DPA_ERROR("%s::cdx_create_fq failed for fqid %d\n",
					__FUNCTION__, fqid);
					kfree(dpa_fq);
					return -1;
				}
				add_pcd_fq_info(dpa_fq);
#ifdef DEVMAN_DEBUG
				DPA_INFO("%s::netdev %s fqid 0x%x created chnl 0x%x\n", 
					__FUNCTION__, dpa_fq->net_dev->name, fqid, dpa_fq->channel);
#endif
			} 
#ifdef DEVMAN_DEBUG
			else {
				DPA_INFO("%s::fqid 0x%x already created\n", 
					__FUNCTION__, fqid);
			}
#endif
			fqid++;
		}
		dist_info++;	
	}
	return 0;
}


int cdx_create_port_fqs(void)
{
        struct dpa_iface_info *iface_info;

        iface_info = dpa_interface_info;
        while(1) {
                if (!iface_info)
                        break;
#ifdef DEVMAN_DEBUG
                printk("%s::%s type %x\n", __FUNCTION__,
                        iface_info->name, iface_info->if_flags);
#endif
                if (iface_info->if_flags & IF_TYPE_ETHERNET) {
                        if (cdxdrv_create_pcd_fqs(&iface_info->eth_info)) {
                                DPA_ERROR("%s::create pcd fq for %s failed\n",
                                        __FUNCTION__, iface_info->name);
                                return -1;
                        }
                } else {
                        if (iface_info->if_flags & IF_TYPE_OFPORT) {
                                if (cdxdrv_create_of_fqs(&iface_info->oh_info)) {
                                        DPA_ERROR("%s::create of fq for %s failed\n",
                                                __FUNCTION__, iface_info->name);
                                        return -1;
                                }
                        }
                }
                iface_info = iface_info->next;
        }
        return 0;
}

int get_phys_port_poolinfo_bysize(uint32_t size, struct port_bman_pool_info *pool_info)
{
        uint32_t ii;
        struct dpa_iface_info *iface_info;

        iface_info = dpa_interface_info;
        while(1) {
                if (!iface_info)
                        break;
                if (iface_info->if_flags & IF_TYPE_ETHERNET) {
                        for (ii = 0; ii < iface_info->eth_info.num_pools; ii++) {
                                if (iface_info->eth_info.pool_info[ii].buf_size >= size) {
                                        memcpy(pool_info, &iface_info->eth_info.pool_info[ii],
                                                sizeof(struct port_bman_pool_info));
                                        return 0;
                                }
                        }
                }
                iface_info = iface_info->next;
        }
        printk("%s::failed\n", __FUNCTION__);
        return -1;
}

struct dpa_priv_s* get_eth_priv(unsigned char* name)
{
        struct net_device *device;
        struct dpa_priv_s *priv;

        device = dev_get_by_name(&init_net, name);
        if (!device) {
                DPA_INFO("%s::could not find device %s\n", __FUNCTION__, name);
                return NULL;
        }
        priv = netdev_priv(device);

        return priv;
}


static void virt_iface_stats_callback(struct net_device *dev, struct rtnl_link_stats64 *storage)
{
	struct dpa_iface_info *iface_info;

	spin_lock(&dpa_devlist_lock);
	iface_info = dpa_interface_info;
	while(1)
  	{
		//more interfaces to scan?
		if (!iface_info)
			break;		
		//check if this the iface we want
    		if (strcmp(dev->name, iface_info->name)) {
    			iface_info = iface_info->next;
			continue;
		}
		//if stats is disabled on the iface do nothing
      		if (!(iface_info->if_flags & IF_STATS_ENABLED))
			break;
        	if(iface_info->if_flags & IF_TYPE_PPPOE) {
			struct en_ehash_ifstats_with_ts *stats;
			//printk("%s::returning pppoe iface stats\n", __FUNCTION__);
			stats = (struct en_ehash_ifstats_with_ts *)iface_info->stats;
			storage->rx_packets += cpu_to_be64(stats->rxstats.pkts);
			storage->rx_bytes += cpu_to_be64(stats->rxstats.bytes);
			storage->tx_packets += cpu_to_be64(stats->txstats.pkts);
			storage->tx_bytes += cpu_to_be64(stats->txstats.bytes);
			break;
		} 
        	if(iface_info->if_flags & (IF_TYPE_TUNNEL | IF_TYPE_VLAN | IF_TYPE_ETHERNET)) {
			struct en_ehash_ifstats *stats;
			//printk("%s::returning other iface stats\n", __FUNCTION__);
			stats = (struct en_ehash_ifstats *)iface_info->stats;
			storage->rx_packets += cpu_to_be64(stats->rxstats.pkts);
			storage->rx_bytes += cpu_to_be64(stats->rxstats.bytes);
			storage->tx_packets += cpu_to_be64(stats->txstats.pkts);
			storage->tx_bytes += cpu_to_be64(stats->txstats.bytes);
			break;
		}
		printk("%s::unknown iface type,no stats available\n", 
			__FUNCTION__);
    		iface_info = iface_info->next;
  	}
  	spin_unlock(&dpa_devlist_lock);
}

int devman_init_linux_stats(void)
{
	dev_fp_stats_get_register(virt_iface_stats_callback);
  	return 0; 
}

int devman_deinit_linux_stats(void)
{
	dev_fp_stats_get_register(virt_iface_stats_callback);
	return 0; 
}


int dpa_get_itfid_by_fman_params(uint32_t fman_index, uint32_t portid)
{
        struct dpa_iface_info *iface_info;

        iface_info = dpa_interface_info;
        while(1) {
                if (!iface_info)
                        break;
                if (iface_info->if_flags & IF_TYPE_ETHERNET) {
			if ((fman_index == iface_info->eth_info.fman_idx) &&
			    (portid == iface_info->eth_info.portid))
				return (iface_info->itf_id);
                }
                iface_info = iface_info->next;
        }
        printk("%s::failed\n", __FUNCTION__);
        return -1;
}
