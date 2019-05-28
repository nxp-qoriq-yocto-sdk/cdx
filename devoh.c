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
 * @file                devoh.c     
 * @description         device management routines offline ports.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/fsl_qman.h>
#include <linux/fsl_bman.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/fsl_oh_port.h>
#include "dpaa_eth_common.h"
#include "dpaa_eth.h"
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

#define DEVOH_DEBUG	1

//fq and table desc infor for all oh ports described
struct oh_port_info {
	char name[64];
	uint32_t fm_idx;
	uint32_t flags; //fqid valid and tdesc valid bits
        void *td[MAX_MATCH_TABLES];//td for tables attached to this port
	uint32_t channel;
	struct oh_iface_info *ohinfo; //iface info from config
	qman_cb_dqrr defa_rx; // app callback func for default rx
	qman_cb_dqrr err_rx; // app callback func for rx err
};

struct oh_port_type {
	char *name;
	uint32_t type;
};

static struct oh_port_type ohport_assign[] = 
{
	{"dpa-fman0-oh@3", PORT_TYPE_WIFI},
	{"dpa-fman0-oh@2", PORT_TYPE_IPSEC},
};
#define MAX_OH_PORT_ASSIGN	(sizeof(ohport_assign) / sizeof(struct oh_port_type))

static struct oh_port_info offline_port_info[MAX_FRAME_MANAGERS][MAX_OF_PORTS];

extern int get_dpa_oh_iface_info(struct oh_iface_info *iface_info, char *name);
extern int dpa_add_port_to_list(struct dpa_iface_info *iface_info);
extern void display_iface_info(struct dpa_iface_info *iface_info);
extern struct dpa_iface_info *dpa_interface_info;
extern int cdx_copy_eth_rx_channel_info(uint32_t fman_idx, struct dpa_fq *dpa_fq);
extern int cdx_create_fq(struct dpa_fq *dpa_fq, uint32_t flags);
extern void add_pcd_fq_info(struct dpa_fq *fq_info);
extern spinlock_t dpa_devlist_lock;
extern int  get_tableInfo_by_portid( int fm_index, int portid, void  **td,  int * flags) ;

void *  get_oh_port_td(uint32_t fm_index, uint32_t port_idx, uint32_t type)
{

#ifdef DEVOH_DEBUG
        DPA_INFO("%s:get td idx %d for fman %d, port %d\n",
                        __FUNCTION__, offline_port_info[fm_index][port_idx].td[type], fm_index, port_idx);
#endif
        return offline_port_info[fm_index][port_idx].td[type] ;

}


int get_ofport_fman_and_portindex(uint32_t fm_index, uint32_t handle, uint32_t* fm_idx, uint32_t* port_idx,
		uint32_t *portid)
{
	struct oh_port_info *info;
	info = &offline_port_info[fm_index][handle];

	*fm_idx = info->ohinfo->fman_idx;	
	*port_idx = info->ohinfo->port_idx;
	*portid = info->ohinfo->portid;
	
	return 0;
}

int get_ofport_portid(uint32_t fm_idx, uint32_t handle, uint32_t *portid)
{
	struct oh_port_info *info;
	
	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s::invalid fman index\n", __FUNCTION__);
		return -1;	
	}
	if (handle >= MAX_OF_PORTS) {
		DPA_ERROR("%s::invalid ofport handle %d\n",
			 __FUNCTION__, handle);
		return -1;	
	}
	info = &offline_port_info[fm_idx][handle];
	*portid = info->ohinfo->portid;
	return 0;
}

int get_ofport_info(uint32_t fm_idx, uint32_t handle, uint32_t *channel, void **td )
{
	struct oh_port_info *info;

	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s::invalid fman index\n", __FUNCTION__);
		return -1;	
	}
	if (handle >= MAX_OF_PORTS) {
		DPA_ERROR("%s::invalid ofport handle %d\n",
			 __FUNCTION__, handle);
		return -1;	
	}
	info = &offline_port_info[fm_idx][handle];
	if (info->flags & IN_USE) {
		uint32_t ii;

		*channel = info->channel;
         	get_tableInfo_by_portid(fm_idx, info->ohinfo->portid, info->td, &info->flags); 
		for (ii = 0; ii < MAX_MATCH_TABLES; ii++) {
			if (info->flags & (1 << ii))
				*(td + ii) = info->td[ii];
			else
				*(td + ii) = NULL;
		}
		return 0;
	}
	DPA_ERROR("%s::ofport handle %d not in use\n",
			 __FUNCTION__, handle);
	return -1;
}

int alloc_offline_port(uint32_t fm_idx, uint32_t type, qman_cb_dqrr defa_rx, qman_cb_dqrr err_rx)
{
	uint32_t ii;
	struct oh_port_info *info;

	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s::invalid fman index\n", __FUNCTION__);
		return -1;	
	}
	type &= PORT_TYPE_MASK;
	for (ii = 0; ii < MAX_OF_PORTS; ii++) {
		info = &offline_port_info[fm_idx][ii];
		if (info->flags & PORT_VALID) {
			printk("%s::type %x, port %s\n", __FUNCTION__,
				(info->flags & PORT_TYPE_MASK), info->name);
			if ((info->flags & PORT_TYPE_MASK) == type) {
				info->flags |= IN_USE;
				info->defa_rx = defa_rx;
				info->err_rx = err_rx;
				return ii;
			}
		}
	}
	DPA_ERROR("%s::no free of ports\n", __FUNCTION__);
	return -1;
}

int release_offline_port(uint32_t fm_idx, int handle)
{
	struct oh_port_info *info;
	
	if (fm_idx >= MAX_FRAME_MANAGERS) {
		DPA_ERROR("%s::invalid fman index\n", __FUNCTION__);
		return -1;
	}
	if (handle >= MAX_OF_PORTS) {
		DPA_ERROR("%s::invalid port index\n", __FUNCTION__);
		return -1;
	}
	info = &offline_port_info[fm_idx][handle];
	if (info->flags & IN_USE) {
		info->flags &= ~IN_USE;
		info->defa_rx = NULL;
		info->err_rx = NULL;
		return 0;
	}	
	DPA_ERROR("%s::port was not in use\n", __FUNCTION__);
	return -1;
}

#ifdef DEVOH_DEBUG
static void display_of_port_info(void) DPA_UNUSED;
static void display_of_port_info(void)
{
	uint32_t ii;
	uint32_t jj;
	struct oh_port_info *info;

	DPA_INFO("===================================================\n"
			"of port info \n"); 
	for (jj = 0; jj < MAX_FRAME_MANAGERS; jj++) {
		DPA_INFO("fm	\t%d\nmax of ports	\t%d\n", 
			jj, MAX_OF_PORTS);
		for (ii = 0; ii < MAX_OF_PORTS; ii++) {
			int kk;
			info = &offline_port_info[jj][ii];
			if (info->flags & PORT_VALID) {
				DPA_INFO("fman %d of port\t%d\n", jj, ii);
				DPA_INFO("defarx_fqid 	\t%x\n",
                                                info->ohinfo->fqinfo[RX_DEFA_FQ].fq_base);
				DPA_INFO("errrx_fqid 	\t%x\n",
                                                info->ohinfo->fqinfo[RX_ERR_FQ].fq_base);
				for( kk = 0; kk < MAX_MATCH_TABLES; kk++) {
					if (info->flags & (1 << kk))
						DPA_INFO("td for type %d	\t%d\n", 
							kk, info->td[kk]);
				}
				if (info->flags & IN_USE) 
					DPA_INFO("in use		\t\n");
			}
		}
	}
}
#else
#define display_of_port_info()
#endif

void display_ohport_info(struct oh_iface_info *ohinfo)
{
#ifdef DEVOH_DEBUG
        uint32_t ii;

        DPA_INFO("fman_idx      \t%d\n", ohinfo->fman_idx);
        DPA_INFO("port_idx      \t%d\n", ohinfo->port_idx);
        DPA_INFO("channel_id    \t%d\n", ohinfo->channel_id);
        for (ii = 0; ii < MAX_FQ_TYPES; ii++) {
                switch(ii) {
                        case TX_ERR_FQ:
                                if (ohinfo->fqinfo[ii].num_fqs)
                                        DPA_INFO("TX_ERR_FQ     \t0x%x\n", ohinfo->fqinfo[ii].fq_base);
                                break;
                        case TX_CFM_FQ:
                                if (ohinfo->fqinfo[ii].num_fqs)
                                        DPA_INFO("TX_CFM_FQ     \t0x%x\n", ohinfo->fqinfo[ii].fq_base);
                                break;
                        case RX_ERR_FQ:
                                if (ohinfo->fqinfo[ii].num_fqs)
                                        DPA_INFO("RX_ERR_FQ     \t0x%x\n", ohinfo->fqinfo[ii].fq_base);
                                break;
                        case RX_DEFA_FQ:
                                if (ohinfo->fqinfo[ii].num_fqs)
                                        DPA_INFO("RX_DEFA_FQ    \t0x%x\n", ohinfo->fqinfo[ii].fq_base);
                                break;
                }
        }
        DPA_INFO("max_dist      \t%d\n", ohinfo->max_dist);
        if (ohinfo->max_dist) {
                struct cdx_dist_info *dist_info;
                DPA_INFO("PCD Fqs\n");
                dist_info = ohinfo->dist_info;
                for (ii = 0; ii < ohinfo->max_dist; ii++) {
                        printk("fq_base         \t0x%x\n", dist_info->base_fqid);
                        printk("fq_count        \t%d\n", dist_info->count);
                        printk("dist_type       \t%d\n", dist_info->type);
                        dist_info++;
                }
        }
#endif
}

int dpa_add_oh_if(char *name)
{
        struct dpa_iface_info *iface_info;
        struct fman_offline_port_info info;
        uint32_t fman_idx;
        uint32_t port_idx;

#if 0//def DEVOH_DEBUG
	DPA_INFO("%s::ADDING OHPORT INFO for %s\n", __func__, name);
#endif

        if (sscanf(name, "dpa-fman%d-oh@%d", &fman_idx,
                        &port_idx) != 2) {
                DPA_ERROR("%s::invalid name %s\n", __FUNCTION__, name);
                return FAILURE;
        }
        strcpy(&info.port_name[0], name);

        if (oh_port_driver_get_port_info(&info)) {
                DPA_ERROR("%s::oh_port_driver_get_port_info failed\n", __FUNCTION__);
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
        strcpy(&iface_info->name[0], name);
	iface_info->if_flags = IF_TYPE_OFPORT;	
        iface_info->oh_info.channel_id = info.channel_id;
        iface_info->oh_info.fman_idx = fman_idx;
        iface_info->oh_info.port_idx = (port_idx - 1);
        iface_info->oh_info.fqinfo[RX_ERR_FQ].fq_base = info.err_fqid;
        iface_info->oh_info.fqinfo[RX_ERR_FQ].num_fqs = 1;
        iface_info->oh_info.fqinfo[RX_DEFA_FQ].fq_base = info.default_fqid;
        iface_info->oh_info.fqinfo[RX_DEFA_FQ].num_fqs = 1;
        //get info from config
        if (get_dpa_oh_iface_info(&iface_info->oh_info, name)) {
                DPA_ERROR("%s::get_dpa_oh_iface_info failed %s\n",
                                        __FUNCTION__, name);
                goto err_ret;
        }
	//add to list
	if (dpa_add_port_to_list(iface_info)) {
		DPA_ERROR("%s::dpa_add_port_to_list failed\n", 
					__FUNCTION__); 
		goto err_ret;
	}
#if 0
#ifdef DEVOH_DEBUG
        display_iface_info(iface_info);
#endif
#endif
        return SUCCESS;
err_ret:
        kfree(iface_info);
        return FAILURE;
}


int oh_port_get_channel_id(uint32_t fman_idx, uint32_t port_idx,
                        uint16_t *channel_id)
{
        struct dpa_iface_info *iface_info;

        spin_lock(&dpa_devlist_lock);
        iface_info = dpa_interface_info;
        while(1) {
                if (!iface_info)
                        break;
                if (iface_info->if_flags == IF_TYPE_OFPORT) {
#ifdef DEVOH_DEBUG
                        DPA_INFO("%s::incoming fm %d, port %d, dn fm %d, db port %d\n",
                                __FUNCTION__, iface_info->oh_info.fman_idx,
                                iface_info->oh_info.port_idx, fman_idx, port_idx);
#endif
                        if ((iface_info->oh_info.fman_idx == fman_idx) &&
                            (iface_info->oh_info.port_idx == port_idx)) {
                                *channel_id = iface_info->oh_info.channel_id;
                                spin_unlock(&dpa_devlist_lock);
                                return 0;
                        }
                }
                iface_info = iface_info->next;
        }
        spin_unlock(&dpa_devlist_lock);
        return -1;
}

#if 0
//create pcd
int cdx_oh_create_fq(struct dpa_fq *dpa_fq, uint32_t flags, uint32_t miss_fqid)
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
	opts.fqd.context_a.hi |= 0x80000000;
	opts.fqd.context_b = miss_fqid;
        if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
                DPA_ERROR("%s::qman_init_fq failed for fqid %d\n",
                        __FUNCTION__, dpa_fq->fqid);
                qman_destroy_fq(fq, 0);
                return -1;
        }
#ifdef DEVOH_DEBUG
        DPA_INFO("%s::created fq 0x%x channel 0x%x\n", __FUNCTION__,
                dpa_fq->fqid, dpa_fq->channel);
#endif
        return 0;
}
#endif


int get_oh_port_pcd_fqinfo(uint32_t fm_idx, uint32_t handle, uint32_t type,
			uint32_t *pfqid, uint32_t *count) 
{
	uint32_t ii;
	struct oh_iface_info *iface_info;
	struct cdx_dist_info *dist;
        struct oh_port_info *info;

        if (fm_idx >= MAX_FRAME_MANAGERS) {
                DPA_ERROR("%s::invalid fman index\n", __FUNCTION__);
                return -1;
        }
        if (handle >= MAX_OF_PORTS) {
                DPA_ERROR("%s::invalid ofport handle %d\n",
                         __FUNCTION__, handle);
                return -1;
        }
        info = &offline_port_info[fm_idx][handle];
        if (!(info->flags & IN_USE)) {
        	DPA_ERROR("%s::ofport handle %d not in use\n",
                         __FUNCTION__, handle);
        	return -1;
	}
	iface_info = info->ohinfo;	
	dist = iface_info->dist_info;
	for (ii = 0; ii < iface_info->max_dist; ii++) {
		if (dist->type == type) {
			*pfqid = dist->base_fqid;
			*count = dist->count;
		}
		dist++;
	}
	return 0;
}


static enum qman_cb_dqrr_result ofport_rx_defa(struct qman_portal *portal, struct qman_fq *fq,
                           const struct qm_dqrr_entry *dq)
{

	const struct qm_fd *fd;
        uint8_t *ptr;
        uint32_t len;
        
	len = dq->fd.length20;

	fd = &dq->fd;
        printk("%s::fqid %x(%d), bpid %d, len %d, offset %d  addr %llx status: %x\n", __FUNCTION__,
                dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
                dq->fd.offset, (uint64_t)dq->fd.addr, dq->fd.status);
	if(len)
	{	
        	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr));
		printk("Dispalying parse result:\n");
		display_buff_data(ptr, 0x70);
        	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);
		printk("Displaying the packet: \n");
		display_buff_data(ptr, len);
	}	
	if (dq->fd.bpid) {
		if (fd->format != qm_fd_sg) {
			struct bm_buffer bmb;
			struct dpa_bp *dpa_bp;
			dpa_bp = dpa_bpid2pool(fd->bpid);
			if (dpa_bp) {
				printk(KERN_CRIT "%s::releasing buffer to pool %d\n", 
					__FUNCTION__, fd->bpid);
				memset(&bmb, 0, sizeof(struct bm_buffer));
				bm_buffer_set64(&bmb, dq->fd.addr);
				while (bman_release(dpa_bp->pool, &bmb, 1, 0))
                			cpu_relax();
			}
		} else {
			printk(KERN_CRIT "%s::cannot handle sg buffers now\n", __FUNCTION__);
		}
	}
	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result ofport_rx_err(struct qman_portal *portal, struct qman_fq *fq,
                const struct qm_dqrr_entry *dq) 
{
	const struct qm_fd *fd;
        uint8_t *ptr;
        uint32_t len;
        
	len = dq->fd.length20;
	fd = &dq->fd;
	printk("%s::fqid %x(%d), bpid %d status %08x\n", __FUNCTION__,
		fq->fqid, fq->fqid, fd->bpid, fd->status);
	if(len)	
	{	
        	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr));
		printk("Dispalying parse result:\n");
		display_buff_data(ptr, 0x70);
        	ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);
		printk("Displaying the packet: \n");
		display_buff_data(ptr, len);
	}	
	return qman_cb_dqrr_consume;

}

//routine to create all FQs required by distribution in xml file
int cdxdrv_create_of_fqs(struct oh_iface_info *iface_info)
{
	uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct oh_port_info *port_info;

	//create default FQ, err FQ
        for (ii = 0; ii < 2; ii++) {
		struct qman_fq *fq;

                dpa_fq = kzalloc(sizeof(struct dpa_fq), 0);
                if (!dpa_fq) {
                	DPA_ERROR("%s::unable to alloc mem for defa or err fqid\n",
                                        __FUNCTION__);
                        return -1;
                }
                memset(dpa_fq, 0, sizeof(struct dpa_fq));
		//use channel and wq the same as any other ethernet port
                if (cdx_copy_eth_rx_channel_info(iface_info->fman_idx, dpa_fq)) {
                	DPA_ERROR("%s::cdx_copy_eth_rx_channel_info failed\n",
                                                __FUNCTION__);
                	kfree(dpa_fq);
                	return -1;
                }
		//get the fqid from dts copied value
		//set callback functions and que type
		fq = &dpa_fq->fq_base;
                if (!ii) {
                        dpa_fq->fqid = iface_info->fqinfo[RX_DEFA_FQ].fq_base;
                	dpa_fq->fq_type = FQ_TYPE_RX_DEFAULT;
			fq->cb.dqrr = ofport_rx_defa; 
		} else {
                        dpa_fq->fqid = iface_info->fqinfo[RX_ERR_FQ].fq_base;
                	dpa_fq->fq_type = FQ_TYPE_RX_ERROR;
			fq->cb.dqrr = ofport_rx_err;
		}
                //create FQ
                if (cdx_create_fq(dpa_fq, 0)) {
                	DPA_ERROR("%s::cdx_create_fq failed for fqid %d\n",
               			 __FUNCTION__, dpa_fq->fqid);
                	kfree(dpa_fq);
                	return -1;
                }
                add_pcd_fq_info(dpa_fq);
#ifdef DEVOH_DEBUG
                DPA_INFO("%s::%d, fqid 0x%x created chnl 0x%x\n",
 	               __FUNCTION__, ii, dpa_fq->fqid, dpa_fq->channel);
#endif
	}
	port_info = &offline_port_info[iface_info->fman_idx][iface_info->port_idx];
	//add fqid information into of port list
	port_info->fm_idx = iface_info->fman_idx; 		
	port_info->ohinfo = iface_info; 		
	port_info->channel = iface_info->channel_id;
	//save name
	sprintf(&port_info->name[0], 
		"dpa-fman%d-oh@%d", iface_info->fman_idx, (iface_info->port_idx + 1));
	//assign port to Wifi/ipsec etc based on user config
	for (ii = 0; ii < MAX_OH_PORT_ASSIGN; ii++) {
		if (strcmp(ohport_assign[ii].name, &port_info->name[0]) == 0) {
			port_info->flags |= ohport_assign[ii].type;
#ifdef DEVOH_DEBUG
			DPA_INFO("%s::port %s, type %x\n", __FUNCTION__,
				port_info->name, ohport_assign[ii].type);
#endif
			break;
		}
	} 		
	offline_port_info[iface_info->fman_idx][iface_info->port_idx].flags |=
		(OF_FQID_VALID | PORT_VALID); 
	return 0;
}

void add_oh_port_tbl_info(uint32_t fm_index, uint32_t port_idx, void * td,
			uint32_t type)
{
	uint32_t ii;

	for (ii = 0; ii < MAX_OF_PORTS; ii++) {
		if (port_idx & (1 << ii)) {
#ifdef DEVOH_DEBUG
			DPA_INFO("%s:;adding tab idx %p for fman %d, port %d\n", 
				__FUNCTION__, td, fm_index, ii);
#endif
			offline_port_info[fm_index][ii].td[type] = td;
			offline_port_info[fm_index][ii].flags |= (1 << type);
		}
	}
}

#define TEST_FMAN_INDEX 0
#define CDXPORT_INFRA_TEST 1
int cdx_ofport_infra_test(void)
{
#ifdef CDXPORT_INFRA_TEST
        uint32_t channel;
        void * ofport_td[MAX_MATCH_TABLES];
        int handle;
        uint32_t ii;
        uint32_t jj;
        uint32_t type;


        for (jj = 0; jj < 2; jj++) {
                /* Get OH port instance */
                if (!jj)
                        type = PORT_TYPE_WIFI;
                else
                        type = PORT_TYPE_IPSEC;
                handle = alloc_offline_port(TEST_FMAN_INDEX, type, NULL, NULL);
                if (handle < 0)
                {
                        DPA_ERROR("%s: Error in allocating OH port for type %x\n",
                                __FUNCTION__, type);
                        return FAILURE;
                }
                if (get_ofport_info(TEST_FMAN_INDEX, handle, &channel,
                                    &ofport_td[0])) {
                        DPA_ERROR("%s: Error in getting OH port info for type %x\n",
                                __FUNCTION__, type);
                        return FAILURE;
                }
                DPA_INFO("%s: allocated oh port for type %x - handle %d, channel %x\n",
                                __FUNCTION__, type, handle, channel);
                for (ii = 0; ii < MAX_MATCH_TABLES; ii++) {
                        if (ofport_td[ii] != NULL )
                                DPA_INFO("table type %d, td %p\n", ii, ofport_td[ii]);
                }
                release_offline_port(TEST_FMAN_INDEX, handle);
        }
#endif
        return SUCCESS;
}

