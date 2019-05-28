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
 * @file                port_defs.h
 * @description         dpaa port/interface management module header file
 */ 

#ifndef PORT_DEFS_H
#define PORT_DEFS_H  1

#include "dpaa_eth.h"
#include "cdx_common.h"
#include "types.h"

#define ETH_ALEN		6	
#define MAX_PORT_BMAN_POOLS     8	//max bman pools per port
#define MAX_POSSIBLE_POOLS	64	//max possible bman pools on SOC
#define DPAA_FWD_TX_QUEUES	8	//max forwarding(PCD) queues per port


//fq infor associated with fman controlled ports
struct port_fq_info {
	uint32_t fq_base;		//base fq
	uint32_t num_fqs;		//num of fqs from base
};


//bman pool info
struct port_bman_pool_info
{
  uint32_t pool_id;		//pool id known to system
  uint32_t buf_size;		//size of buffers managed by pool
  uint32_t count;		//number of buffer filled into pool
  uint64_t base_addr;		//base address of buffers (phys)
};


//types of FQs 
typedef enum {	
	TX_ERR_FQ,		//transmit error FQ
	TX_CFM_FQ,		//transmit confirmation FQ
	RX_ERR_FQ,		//receive error FQ
	RX_DEFA_FQ,		//default receive FQ	
	MAX_FQ_TYPES
}fq_types;

//ethernet device information
struct eth_iface_info {
	struct net_device *net_dev;	//os device ref
	uint32_t speed;			//port speed
	uint32_t fman_idx;		//fman index within SOC
	uint32_t port_idx;		//port index within fman
	uint32_t portid;		//identification provided in xml pcd file
	uint32_t tx_index;		//transmit que to use next
	struct port_fq_info fqinfo[MAX_FQ_TYPES];	//fq info for defa types
	struct port_fq_info eth_tx_fqinfo[DPAA_ETH_TX_QUEUES];	//ethdrv TX FQs 
	struct qman_fq fwd_tx_fqinfo[DPAA_FWD_TX_QUEUES]; //cctable TX FQs 
	uint32_t rx_channel_id;		//channel id rx
	uint32_t tx_channel_id;		//channel id tx
	uint32_t tx_wq;			//tx work queue
	uint32_t rx_pcd_wq;		//wq used by ethernet driver pcd queues
	qman_cb_dqrr dqrr;
	uint32_t num_pools;	//pools used by port
	struct port_bman_pool_info pool_info[MAX_PORT_BMAN_POOLS]; //pool info
	uint8_t mac_addr[ETH_ALEN];	//mac address
	uint32_t max_dist;		//max PCD distributions
	struct cdx_dist_info *dist_info;//pointer to array of pcd dist
	struct dpa_fq *defa_rx_dpa_fq; //default rx fq pointer
	struct dpa_fq *err_rx_dpa_fq;  //rx err fq pointer
};

//offline port device information
struct oh_iface_info {
        uint32_t fman_idx;              //fman index within SOC
        uint32_t port_idx;              //port index within fman
        uint32_t portid;                //portid from xml file
        struct port_fq_info fqinfo[MAX_FQ_TYPES]; //fq info for defa types
        uint32_t channel_id;            //channel id
        uint32_t max_dist;              //max PCD distributions
        struct cdx_dist_info *dist_info;//pointer to array of pcd dist
};

//vlan device information
struct vlan_iface_info {
	struct dpa_iface_info *parent;
	uint16_t vlan_id;
};

//pppoe device information
struct pppoe_iface_info {
	struct dpa_iface_info *parent;
	uint16_t session_id;
        uint8_t mac_addr[ETH_ALEN];
};

struct wlan_iface_info {
	uint16_t vap_id;
        uint8_t mac_addr[ETH_ALEN];
	uint32_t fman_idx;
	uint32_t port_idx;
	uint32_t portid;
};


//tunnel device information
struct tunnel_iface_info {

       struct dpa_iface_info *parent;
       uint8_t mode; /*4o6/6o4/remote_any*/
       uint8_t proto;
       uint16_t header_size;
       uint32_t local_ip[4];
       uint32_t remote_ip[4];
       uint8_t dstmac[ETH_ALEN];
       union {
       	  uint8_t   header[40];
	  ipv4_hdr_t header_v4;
	  ipv6_hdr_t header_v6;
       };
};


//dpa interface structure
struct dpa_iface_info {
	struct dpa_iface_info *next; //single link to next iface
	uint32_t if_flags; 	//from itf structure
	uint32_t itf_id;	//from itf_structure
	uint32_t osid;		//linux interface id
	uint32_t mtu;		//iface mtu
	uint8_t name[IF_NAME_SIZE]; //name as seen by OS
	union {
		struct eth_iface_info eth_info; //info if iface type is eth
		struct vlan_iface_info vlan_info; //info if type is vlan
		struct pppoe_iface_info pppoe_info; //info if type is pppoe
		struct tunnel_iface_info tunnel_info; //info if type is tunnel
		struct wlan_iface_info wlan_info; //internal wlan  info
		struct oh_iface_info oh_info; //internal oh parsing port info

	};
#ifdef INCLUDE_IFSTATS_SUPPORT
	void *stats;
	uint8_t rxstats_index;
	uint8_t txstats_index;
#endif
};


//flags field values in struct oh_port_fq_td_info
#define IPV4_TBL_VALID          (1 << 0)
#define IPV6_TBL_VALID          (1 << 1)
#define ETHERNET_TBL_VALID      (1 << 2)
#define OF_FQID_VALID           (1 << 8)
#define IN_USE                  (1 << 9)
#define PORT_VALID              (1 << 16)
#define PORT_TYPE_WIFI          (1 << 12)
#define PORT_TYPE_IPSEC         (2 << 12)
#define PORT_TYPE_MASK          (3 << 12)

#endif
