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


#ifndef _DPAA_HOST_GENERIC_H_
#define _DPAA_HOST_GENERIC_H_

#include <linux/cdev.h>
#include <linux/interrupt.h>
#include "cdx_ioctl.h"
#include "portdefs.h"

#define VWD_BHR_MODE 0
#define VWD_NAS_MODE 1
#define VWD_BHR_NAS_MODE 2

#define VWD_DEBUG_STATS
#define VWD_TXQ_CNT	16
#define VWD_RXQ_CNT	3

#define VWD_MINOR               0
#define VWD_MINOR_COUNT         1
#define VWD_DRV_NAME            "vwd"
#define VWD_DEV_COUNT           1
#define VWD_RX_POLL_WEIGHT	64 - 16
#define	WIFI_TOE_PE_ID	5
#define MAX_VAP_SUPPORT		4
#define NAPI_MAX_COUNT		4
#define VWD_INFOSTR_LEN          32

#define CFG_WIFI_OFFLOAD

#define FMAN_IDX		0
#define DEFA_WQ_ID      	0
//used for PCD FQ creation
#define NUM_PKT_DATA_LINES_IN_CACHE     2
#define NUM_ANN_LINES_IN_CACHE          1

#define VAPDEV_BUFSIZE  1700
#define VAPDEV_BUFCOUNT 1024
#define VAPBUF_HEADROOM 128
#define USE_PCD_FQ	1

//values for state
#if 0
#define VAP_ST_FREE				0
#define VAP_ST_INUSE				1
#define VAP_ST_UP				2
#define VAP_ST_DOWN				3
#endif
#define VAP_ST_CLOSE            0
#define VAP_ST_OPEN             1
#define VAP_ST_CONFIGURED       2
#define VAP_ST_CONFIGURING      3

struct vap_desc_s {
	struct dpaa_vwd_priv_s			*vwd;
	struct net_device 			*wifi_dev;
	unsigned int				ifindex;
	unsigned int				state;
	int 					cpu_id;
	char  					ifname[IFNAMSIZ];
	unsigned char  				macaddr[ETH_ALEN];
	unsigned short 				vapid;
	unsigned short 				programmed;
	unsigned short 				bridged;
	unsigned short  			direct_rx_path;          /* Direct path support from offload device=>VWD */
        unsigned short  			direct_tx_path;          /* Direct path support from offload VWD=>device */
#ifdef DPAA_VWD_TX_STATS
	unsigned int 				stop_queue_total[VWD_TXQ_CNT];
	unsigned int 				stop_queue_hif[VWD_TXQ_CNT];
	unsigned int 				stop_queue_hif_client[VWD_TXQ_CNT];
	unsigned int 				clean_fail[VWD_TXQ_CNT];
	unsigned int 				was_stopped[VWD_TXQ_CNT];
#endif
	uint32_t 				channel;
	struct dpa_fq				*wlan_exception_fq;
	struct dpa_fq				*wlan_fq_to_fman;
	struct dpa_fq				*wlan_fq_from_fman;
	//struct dpa_bp 				*vap_bp;
	//struct port_bman_pool_info		parent_pool_info;
	void * td[MAX_MATCH_TABLES];


};

//action values in vap_cmd_s

#define         ADD             0
#define         REMOVE          1
#define         UPDATE          2
#define         RESET           3
#define         CONFIGURE       4

struct vap_cmd_s {
	int32_t	action;
	int32_t	ifindex;
	int16_t vapid;
	int16_t direct_rx_path;
	unsigned char 	ifname[IFNAMSIZ];
	unsigned char 	macaddr[ETH_ALEN];
};


struct dpaa_vwd_priv_s {

	unsigned char 				name[IFNAMSIZ];
	int 					vwd_major;
	struct class 				*vwd_class;
	struct device 				*vwd_device;
	struct dpa_priv_s			*eth_priv;
	struct dpa_bp 				*bp;
	struct port_bman_pool_info		parent_pool_info;
	uint32_t				oh_port_handle;
	uint32_t				expt_fq_count; /* Number of FQs created to HOST */
	unsigned int 				vap_dev_hw_features;
	unsigned int 				vap_dev_features;
	struct vap_desc_s 			vaps[MAX_VAP_SUPPORT];
	int 					vap_count;
	spinlock_t 				vaplock;
#ifdef DPAA_VWD_NAPI_STATS
	unsigned int 				napi_counters[NAPI_MAX_COUNT];
#endif
	int 					fast_path_enable;
	int 					fast_bridging_enable;
	int 					fast_routing_enable;
#ifdef VWD_DEBUG_STATS
	u32 					pkts_local_tx_sgs;
	u32 					pkts_total_local_tx;
	u32 					pkts_local_tx_csum;
	u32 					pkts_transmitted;
	//u32 					pkts_slow_forwarded[VWD_RXQ_CNT];
	u32 					pkts_slow_forwarded;
	u32 					pkts_slow_fail;
	u32 					pkts_tx_dropped;
	//u32 					pkts_rx_fast_forwarded[VWD_RXQ_CNT];
	u32 					pkts_rx_fast_forwarded[2];
	u32 					rx_skb_alloc_fail;
	//u32 					rx_csum_correct;
#endif
	u32 					msg_enable;
};



static inline void display_fd(struct qm_fd *fd)
{
        printk("fd %p\n", fd);
        printk("dd %d, eliodn_offset %x, liodn_offset %x, bpid %d\n",
                fd->dd, fd->eliodn_offset, fd->liodn_offset,
                fd->bpid);
        printk("format %d, offset %d, length %d, addr %llx cmd %x\n",
                fd->format, fd->offset, fd->length20,
                (uint64_t)fd->addr, fd->cmd);
}
int dpaa_vwd_init(void);
void dpaa_vwd_exit(void);
#endif /* _DPAA_HOST_GENERIC_H_ */
