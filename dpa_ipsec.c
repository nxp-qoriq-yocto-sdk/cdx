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


#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <net/pkt_sched.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/irqnr.h>
#include <linux/ppp_defs.h>
#include <linux/highmem.h>
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
#include <net/xfrm.h>
#endif

#include <linux/spinlock.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#include "portdefs.h"
#include "dpa_ipsec.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "dpaa_eth_common.h"


//#define DPA_IPSEC_DEBUG  	1
//#define DPA_IPSEC_TEST_ENABLE	1

#define DPAIPSEC_ERROR(fmt, ...)\
{\
        printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#define DPAIPSEC_INFO(fmt, ...)\
{\
        printk(KERN_INFO fmt, ## __VA_ARGS__);\
}

#define MAX_IPSEC_SA_INFO	16
#define IPSEC_WQ_ID		2

#define FQ_FROM_SEC		0
#define FQ_TO_SEC		1	


struct dpa_ipsec_sainfo {
	void *shdesc_mem;
	struct sec_descriptor *shared_desc;
	struct dpa_fq sec_fq[2];
};

struct ipsec_info {
	uint32_t crypto_channel_id;
	int ofport_handle;
	uint32_t ofport_channel;
	uint32_t ofport_portid;
	void *ofport_td[MAX_MATCH_TABLES];
	void *wanport_td[MAX_MATCH_TABLES];
	uint32_t wanport_itf;
	uint32_t expt_fq_count ;
	struct dpa_bp *ipsec_bp;
	struct dpa_fq *pcd_fq;
	struct dpa_fq		*ipsec_exception_fq;
        struct port_bman_pool_info parent_pool_info;
};

static struct ipsec_info ipsecinfo;
extern void*  M_ipsec_get_sa_netdev( U16 handle);
#ifdef DPA_IPSEC_OFFLOAD
#error ipsec_enabled
extern int get_ofport_portid(uint32_t fm_index, uint32_t handle,uint32_t *portid);
extern int get_ofport_info(uint32_t fm_idx, uint32_t handle, uint32_t *channel, void **td);
extern int dpa_get_wan_port(uint32_t fm_index, uint32_t *port_idx);
extern void *dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type);
extern int alloc_offline_port(uint32_t fm_idx, uint32_t type, qman_cb_dqrr defa_rx, qman_cb_dqrr err_rx);
extern int get_phys_port_poolinfo_bysize(uint32_t size, struct port_bman_pool_info *pool_info);
extern int dpa_get_itfid_by_fman_params(uint32_t fman_index, uint32_t portid);
extern struct dpa_iface_info *dpa_get_ifinfo_by_itfid(uint32_t itf_id);
extern int cdx_copy_eth_rx_channel_info(uint32_t fman_idx, struct dpa_fq *dpa_fq);
extern int get_oh_port_pcd_fqinfo(uint32_t fm_idx, uint32_t handle, uint32_t type, 
				uint32_t *fqid, uint32_t *count);
extern struct dpa_priv_s* get_eth_priv(unsigned char* name);
extern int cdx_ipsec_handle_get_inbound_sagd(U32 spi, U16 * sagd );
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
extern struct xfrm_state *xfrm_state_lookup_byhandle(struct net *net, u16 handle);
#endif

struct sec_descriptor *get_shared_desc(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->shared_desc);
}

uint32_t get_fqid_to_sec(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_SEC].fqid);
}

uint32_t get_fqid_from_sec(void *handle)
{
	return (((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_FROM_SEC].fqid);
}
struct qman_fq *get_from_sec_fq(void *handle)
{
        return (struct qman_fq *)&(((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_FROM_SEC]);
} 
struct qman_fq *get_to_sec_fq(void *handle)
{
        return (struct qman_fq *)&(((struct dpa_ipsec_sainfo *)handle)->sec_fq[FQ_TO_SEC]);
} 
static void dpa_ipsec_ern_cb(struct qman_portal *qm, struct qman_fq *fq,
                           const struct qm_mr_entry *msg)
{
	DPAIPSEC_ERROR("%s::fqid %x(%d)\n", __FUNCTION__, fq->fqid, fq->fqid);
}


uint32_t ipsec_exception_pkt_cnt;
void print_ipsec_exception_pkt_cnt(void)
{
       printk("%s:: Ipsec offload slow path packet count = %d\n",__func__,ipsec_exception_pkt_cnt);

	ipsec_exception_pkt_cnt= 0;
}
static enum qman_cb_dqrr_result ipsec_exception_pkt_handler(struct qman_portal *qm,
                                        struct qman_fq *fq,
                                        const struct qm_dqrr_entry *dq)
{
        uint8_t *ptr;
        uint8_t *skb_ptr;
        uint32_t len;
        struct sk_buff *skb;
        struct net_device *net_dev;
        struct bm_buffer bmb;
        struct dpa_bp *dpa_bp;
        struct dpa_priv_s               *priv;
        struct dpa_percpu_priv_s        *percpu_priv;
	unsigned short sagd_pkt;
        unsigned short eth_type; 
#ifdef DPA_IPSEC_DEBUG
	unsigned short sagd; 
#endif
	
	//check SEC errors here

        //len = (dq->fd.length20 - 4);
        len = dq->fd.length20;
        ptr = (uint8_t *)(phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);
	/* 
	* extract sagd from the end of packet. That sagd is used for two purpose.
	* 1) After the Sec processes since a new buffer is used for decrypted input 
	*    packets, the port information on which the orginal packet reached is lost.
	*    When giving the packet to the stack this information is required. Earlier
        *    we used a hardcoded logic of identifying one of the port as WAN port  by name
	*    or adding ESP table to only one of the port in configuration file, and hard code 
	*    that port as incoming ipsec packet before submitting the packet. With this change
	*    now we store the incoing interface netdev structure in SA structure itself and 
	*    extract incoming for by using the sagd copied into the end of packet.
	*  2) We need dpa_priv pointer from the net_dev for calling dpaa_eth_napi_schedule ()
	*     We do not want the complete pkt processing happen in irq context. 
	*     dpaa_eth_napi_schedule () schdule a soft irq and ensure this function is called
	*     again soft irq. 
	*  3) We need to find xrfm state by using this sagd and put that into skb
	*     beofe submitting into stack. If the there is a coresponding inbound 
	*     ipsec policy only this packet will be allowed otherwise stack will
	*     drop the packet.   
	*/
         memcpy(&sagd_pkt,(ptr+(len-2)),2);
         net_dev = (struct net_device *) M_ipsec_get_sa_netdev(sagd_pkt );
         if(!net_dev ){
		DPAIPSEC_ERROR("%s:: Could not find inbound SA, droping pkt \n",__func__);
                goto rel_fd;
	}
	priv = netdev_priv(net_dev); 
        DPA_BUG_ON(!priv);
        /* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
        percpu_priv = raw_cpu_ptr(priv->percpu_priv);
        if (unlikely(dpaa_eth_napi_schedule(percpu_priv, qm)))
                return qman_cb_dqrr_stop;

	ipsec_exception_pkt_cnt++;
         /*  When V6 SA is applied to v4 packet and vice versa, since ether header is
          *  copied from input packet, it will be wrong. Below logic is added just 
          *  make the required correction in this case. 
          */ 
         memcpy(&eth_type,(ptr+12),2); 
         if((eth_type == htons(ETHERTYPE_IPV4)) && ((ptr[14] & 0xF0) == 0x60))
         {
              ptr[12]= 0x86;
              ptr[13] = 0xDD; 
         }  	
         if((eth_type == htons(ETHERTYPE_IPV6)) && ((ptr[14] & 0xF0) == 0x40))
         {
              ptr[12]= 0x08;
              ptr[13] = 0x00; 
         }  	
#ifdef DPA_IPSEC_DEBUG
        DPAIPSEC_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s temp_dev =%s addr %llx sts %08x\n", __FUNCTION__,
                dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
                dq->fd.offset, net_dev, net_dev->name,net_dev_temp->name, (uint64_t)dq->fd.addr, dq->fd.status);
		DPAIPSEC_INFO(" sagd extracted from packet = %d \n",sagd_pkt);
	display_buff_data(ptr, len);	
	//goto rel_fd;
#endif
        if (dq->fd.format != qm_fd_contig) {
                DPAIPSEC_ERROR("%s::TBD discarding SG frame\n", __FUNCTION__);
                goto rel_fd;
        }
        skb = dev_alloc_skb(len + dq->fd.offset + 32);
        if (!skb) {
                DPAIPSEC_ERROR("%s::skb alloc failed\n", __FUNCTION__);
                goto rel_fd;
        }
	skb_reserve(skb, dq->fd.offset);
        skb_ptr = skb_put(skb, len);
        memcpy(skb_ptr, ptr, len);
        skb->dev = net_dev;
	skb->protocol = eth_type_trans(skb, net_dev);
        *(unsigned long *)skb->head = 0xdead;

#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
	{
		struct sec_path *sp;
		struct xfrm_state *x;
		struct timespec ktime;

		sp = secpath_dup(skb->sp);

		if (!sp)
		{
#ifdef DPA_IPSEC_DEBUG
			DPAIPSEC_ERROR("No sec_path. Dropping pkt\n");
#endif
			goto pkt_drop;
		}

		skb->sp = sp;

#ifdef DPA_IPSEC_DEBUG
		/* cdx_ipsec_handle_get_inbound_sagd() return SAGD of first inbound SA 
		* To  test whether sahred descriptor copied the value correctly to 
		* end of packet. 
		* System should have only one inbound SA for this debug logic to work
		*/
		if( cdx_ipsec_handle_get_inbound_sagd(0, &sagd )){
			DPAIPSEC_ERROR("cdx_ipsec_handle_get_inbound_sagd returned error  Dropping pkt\n");
		}
		
		if(sagd != sagd_pkt)
		DPAIPSEC_INFO("cdx_ipsec_handle_get_inbound_sagd succuss sagd = %d  sagd_pkt = %d\n",sagd,sagd_pkt);
#endif

		if ((x = xfrm_state_lookup_byhandle(dev_net(skb->dev), sagd_pkt )) == NULL)
		{
			DPAIPSEC_ERROR("xfrm_state not found. Dropping pkt\n");
			goto pkt_drop;
		}

		sp->xvec[0] = x;

		if (!x->curlft.use_time)
		{
			ktime = current_kernel_time();
			x->curlft.use_time = (unsigned long)ktime.tv_sec;
		}
		sp->len = 1;
	}
#endif
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::len %d\n", __FUNCTION__, skb->len);
#endif
        //netif_receive_skb(skb);
        if(netif_rx(skb) != NET_RX_SUCCESS)
              DPAIPSEC_ERROR("%s::packet dropped\n", __FUNCTION__);
        goto rel_fd;
#if defined(CONFIG_INET_IPSEC_OFFLOAD) || defined(CONFIG_INET6_IPSEC_OFFLOAD)
pkt_drop:
#endif
	if (skb) 
        	dev_kfree_skb(skb);
rel_fd:
        bmb.bpid = dq->fd.bpid;
        bmb.addr = dq->fd.addr;
        dpa_bp = dpa_bpid2pool(dq->fd.bpid);
        while (bman_release(dpa_bp->pool, &bmb, 1, 0))
                cpu_relax();
        return qman_cb_dqrr_consume;
}


#define PORTID_SHIFT_VAL 8

static int create_ipsec_pcd_fqs(struct ipsec_info *info, uint32_t schedule)
{
        struct dpa_fq *dpa_fq;
	struct dpa_iface_info *wanif_info;
	struct net_device *net_dev;
	uint32_t fqbase;
	uint32_t fqcount;
	uint32_t portid;
	uint32_t ii;
	uint32_t portal_channel[NR_CPUS];
        uint32_t num_portals;
        uint32_t next_portal_ch_idx;
        const cpumask_t *affine_cpus;

	//get cpu portal channel info
        num_portals = 0;
        next_portal_ch_idx = 0;
        affine_cpus = qman_affine_cpus();
        /* get channel used by portals affined to each cpu */
        for_each_cpu(ii, affine_cpus) {
                portal_channel[num_portals] = qman_affine_channel(ii);
                num_portals++;
        }
        if (!num_portals) {
                DPAIPSEC_ERROR("%s::unable to get affined portal info\n",
                                                __FUNCTION__);
                return -1;
        }
#ifdef DPA_IPSEC_DEBUG
        DPAIPSEC_INFO("%s::num_portals %d ::", __FUNCTION__, num_portals);
        for (ii = 0; ii < num_portals; ii++)
                DPAIPSEC_INFO("%d ", portal_channel[ii]);
        DPAIPSEC_INFO("\n");
#endif

	//get wan port info
	wanif_info = dpa_get_ifinfo_by_itfid(info->wanport_itf);
	if (!wanif_info) {
         	DPAIPSEC_ERROR("%s::could not get wanport iface info\n", __FUNCTION__) ;
                return FAILURE;
	}
	net_dev = wanif_info->eth_info.net_dev;
	if (!net_dev) {
         	DPAIPSEC_ERROR("%s::could not get wanport iface netdev\n", __FUNCTION__) ;
                return FAILURE;
	}

	//get FQbase and count used for ethernet dist
	//with scheme sharing this is the only distribution that will be used

	if (get_oh_port_pcd_fqinfo(IPSEC_FMAN_IDX, info->ofport_handle,
			ETHERNET_DIST, &fqbase, &fqcount)) {
        	DPAIPSEC_ERROR("%s::err getting pcd fq\n", __FUNCTION__) ;
                return FAILURE;
        }
	//get port id required for FQ creation
	if (get_ofport_portid(IPSEC_FMAN_IDX, info->ofport_handle, &portid)) {
			DPAIPSEC_ERROR("%s::err getting of port id\n", __FUNCTION__) ;
			return -1;
	}
	//add port id into FQID
	fqbase |= (portid << PORTID_SHIFT_VAL);
	DPAIPSEC_INFO("%s::pcd FQ base for portid %d eth dist %x(%d), count %d\n", 
		__FUNCTION__, portid, fqbase, fqbase, fqcount);

	//create FQ for exception packets from ipsec ofline  port
	info->ipsec_exception_fq = kzalloc((sizeof(struct dpa_fq) * fqcount),1);
        if (!info->ipsec_exception_fq) {
         	DPAIPSEC_ERROR("%s::unable to alloc mem for dpa_fq\n", __FUNCTION__) ;
                return FAILURE;
        }

	//save dpa_fq base info
	dpa_fq = info->ipsec_exception_fq;
	//create all FQs
	info->expt_fq_count = 0;
	for (ii = 0; ii < fqcount; ii++) {
		struct qman_fq *fq;
		struct qm_mcc_initfq opts;
	
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		//set FQ parameters
		//use wan port as the device for this FQ 
        	dpa_fq->net_dev = net_dev;
                dpa_fq->fq_type = FQ_TYPE_RX_PCD;
                dpa_fq->fqid = fqbase;
		//set call back function pointer
                fq = &dpa_fq->fq_base;
		fq->cb.dqrr = ipsec_exception_pkt_handler;
		//round robin channel like ethernet driver does
		dpa_fq->channel = portal_channel[next_portal_ch_idx];
		if (next_portal_ch_idx == (num_portals - 1))
			next_portal_ch_idx = 0;
		else
			next_portal_ch_idx++;
		dpa_fq->wq = DEFA_WQ_ID;
		//set options similar to ethernet driver
                memset(&opts, 0, sizeof(struct qm_mcc_initfq));
                opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
                opts.fqd.context_a.stashing.exclusive =
                	(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
                opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
                opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
		//create FQ
                if (qman_create_fq(dpa_fq->fqid, 0, fq)) {
                        DPAIPSEC_ERROR("%s::qman_create_fq failed for fqid %d\n",
                                 __FUNCTION__, dpa_fq->fqid);
			goto err_ret;
                }
                opts.fqid = dpa_fq->fqid;
                opts.count = 1;
                opts.fqd.dest.channel = dpa_fq->channel;
                opts.fqd.dest.wq = dpa_fq->wq;
                opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
                                QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		if (schedule)
                        schedule = QMAN_INITFQ_FLAG_SCHED;

		//init FQ
                if (qman_init_fq(fq, schedule, &opts)) {
                        DPAIPSEC_ERROR("%s::qman_init_fq failed for fqid %d\n",
                                __FUNCTION__, dpa_fq->fqid);
                        qman_destroy_fq(fq, 0);
			goto err_ret;
                }
#ifdef DPA_IPSEC_DEBUG
                DPAIPSEC_INFO("%s::created pcd fq %x(%d) for wlan packets "
                        "channel 0x%x\n", __FUNCTION__,
                        dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
		//next FQ
		dpa_fq++;	
		fqbase++;
		info->expt_fq_count++;
	}

	return SUCCESS;
err_ret:
	/* release FQs allocated so far and mem */
        return FAILURE;
}

static int create_ipsec_fqs(struct dpa_ipsec_sainfo *ipsecsa_info, uint32_t schedule, uint32_t handle)
{
	uint32_t ii;
	struct dpa_fq *dpa_fq;
        struct qman_fq *fq;
        struct qm_mcc_initfq opts;
        int errno;

	ipsecsa_info->shdesc_mem = 
		kzalloc((sizeof(struct sec_descriptor) + PRE_HDR_ALIGN), GFP_KERNEL);
        if (!ipsecsa_info->shdesc_mem) {
        	DPAIPSEC_ERROR("%s::kzalloc failed for SEC descriptor\n",
					__FUNCTION__);
                return FAILURE;
        }
	memset(ipsecsa_info->shdesc_mem, 0, (sizeof(struct sec_descriptor)+PRE_HDR_ALIGN));
	ipsecsa_info->shared_desc = (struct sec_descriptor *)
        	PTR_ALIGN(ipsecsa_info->shdesc_mem, PRE_HDR_ALIGN);

	for (ii = 0; ii < 2; ii++) {
		uint32_t flags;

		dpa_fq = &ipsecsa_info->sec_fq[ii];
        	memset(dpa_fq, 0, sizeof(struct dpa_fq));
        	memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		flags = (QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_DYNAMIC_FQID);
		//dpa_fq->net_dev = vap->wifi_dev;
		fq = &dpa_fq->fq_base;
		switch (ii) {
			case FQ_FROM_SEC:
#ifdef DPA_IPSEC_DEBUG
				printk("%s::handle %x\n", __FUNCTION__, handle);
#endif
				dpa_fq->channel = ipsecinfo.ofport_channel;
				break;
			case FQ_TO_SEC:
				{
					uint64_t addr;
					addr = virt_to_phys(ipsecsa_info->shared_desc);
					dpa_fq->channel = ipsecinfo.crypto_channel_id; 
					dpa_fq->fq_base.cb.ern = dpa_ipsec_ern_cb;
					opts.fqd.context_b = ipsecsa_info->sec_fq[FQ_FROM_SEC].fqid; 
					opts.fqd.context_a.hi = (uint32_t) (addr >> 32);
					opts.fqd.context_a.lo = (uint32_t) (addr);
				}
				break;
		}
		dpa_fq->wq = IPSEC_WQ_ID;
        	//dpa_fq->net_dev = vap->wifi_dev;
        	if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
                	DPAIPSEC_ERROR("%s::qman_create_fq failed for fqid %d\n",
                       		 __FUNCTION__, dpa_fq->fqid);
                	return FAILURE;
        	}
        	dpa_fq->fqid = fq->fqid;
        	opts.fqid = dpa_fq->fqid;
        	opts.count = 1;
        	opts.fqd.dest.channel = dpa_fq->channel;
        	opts.fqd.dest.wq = dpa_fq->wq;
		opts.fqd.fq_ctrl = QM_FQCTRL_CPCSTASH;
        	opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
                                QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
		if(schedule)
			schedule = QMAN_INITFQ_FLAG_SCHED;
        	if((errno=qman_init_fq(fq, schedule, &opts))) {
                	DPAIPSEC_ERROR("%s::qman_init_fq failed for fqid %d errno= %d\n",
                        	__FUNCTION__, dpa_fq->fqid,errno);
                	qman_destroy_fq(fq, 0);
                	return FAILURE;
       	 	}	
#ifdef DPA_IPSEC_DEBUG
        	DPAIPSEC_INFO("%s::created fq %x(%d) for ipsec - type %d "
			"channel 0x%x\n", __FUNCTION__,
                	dpa_fq->fqid, dpa_fq->fqid, ii, dpa_fq->channel);
#endif
	}
	return SUCCESS;
}

void display_fq_info(void *handle)
{
	struct dpa_ipsec_sainfo *ipsecsa_info;
	struct dpa_fq *dpa_fq;
        struct qman_fq *fq;
	struct qm_mcr_queryfq_np *np;
	struct qm_fqd *fqd;
	uint32_t ii;

	ipsecsa_info = (struct dpa_ipsec_sainfo *)handle;
	np = kzalloc(sizeof(struct qm_mcr_queryfq_np), GFP_KERNEL);
	if (!np) {
		printk("%s::error allocating fqnp\n", __FUNCTION__);
		return;
	}
	fqd = kzalloc(sizeof(struct qm_fqd), GFP_KERNEL);
	if (!fqd) {
		printk("%s::error allocating fqd\n", __FUNCTION__);
		kfree(np);
		return;
	}

	for (ii = 0; ii < 2; ii++) {
		dpa_fq = &ipsecsa_info->sec_fq[ii];
		fq = &dpa_fq->fq_base;
		printk("===========================================\n%s::fqid %x(%d\n", __FUNCTION__, fq->fqid, fq->fqid);
		if (qman_query_fq(fq, fqd)) {
			printk("%s::error getting fq fields\n", __FUNCTION__);
			break;
		}
		printk("fqctrl\t%x\n", fqd->fq_ctrl);
		printk("channel\t%x\n", fqd->dest.channel);
		printk("Wq\t%d\n", fqd->dest.wq);
		printk("contextb\t%x\n", fqd->context_b);
		printk("contexta\t%p\n", (void *)fqd->context_a.opaque);
		if (qman_query_fq_np(fq, np)) {
			printk("%s::error getting fqnp fields\n", __FUNCTION__);
			break;
		}
		printk("state\t%d\n", np->state);
		printk("byte count\t%d\n", np->byte_cnt);
		printk("frame count\t%d\n", np->frm_cnt);
	}
	kfree(np);
	kfree(fqd);
}


static int ipsec_init_ohport(struct ipsec_info *info)
{

        /* Get OH port for this driver */
        info->ofport_handle = alloc_offline_port(IPSEC_FMAN_IDX, PORT_TYPE_IPSEC, 
			NULL, NULL);
        if (info->ofport_handle < 0)
        {
                DPAIPSEC_ERROR("%s: Error in allocating OH port Channel\n", __FUNCTION__);
		return FAILURE;
        }
#ifdef DPA_IPSEC_DEBUG
        DPAIPSEC_INFO("%s: allocated oh port %d\n", __FUNCTION__, info->ofport_handle);
#endif
	if (get_ofport_info(IPSEC_FMAN_IDX, info->ofport_handle, &info->ofport_channel, 
				&info->ofport_td[0])) {
                DPAIPSEC_ERROR("%s: Error in getting OH port info\n", __FUNCTION__);
		return FAILURE;
	}
	if (get_ofport_portid(IPSEC_FMAN_IDX, info->ofport_handle, &info->ofport_portid)) {
                DPAIPSEC_ERROR("%s: Error in getting OH port id\n", __FUNCTION__);
		return FAILURE;
	}
	printk("%s:: ipsec of port id = %d\n ", __func__, info->ofport_portid);
	return SUCCESS;
}

static int dpa_fill_wanport_info(struct ipsec_info *info)
{
	uint32_t wan_portidx;	
	void *td;
	if (dpa_get_wan_port(IPSEC_FMAN_IDX, &wan_portidx)) {
                return FAILURE;
	}
	td = dpa_get_tdinfo(IPSEC_FMAN_IDX, wan_portidx, ESP_IPV4_TABLE);
	if (td == NULL) {
                DPAIPSEC_ERROR("%s::Wan port has no IPV4 ESP table\n", __FUNCTION__);
		return FAILURE;
	}
	info->wanport_td[ESP_IPV4_TABLE] = td;
	td = dpa_get_tdinfo(IPSEC_FMAN_IDX, wan_portidx, ESP_IPV6_TABLE);
	if (td == NULL) {
                DPAIPSEC_ERROR("%s::Wan port has no IPV6 ESP table\n", __FUNCTION__);
		return FAILURE;
	}
	info->wanport_td[ESP_IPV6_TABLE] = td;
	info->wanport_itf = dpa_get_itfid_by_fman_params(IPSEC_FMAN_IDX, wan_portidx);
	if (info->wanport_itf == -1)
		return FAILURE;
	return SUCCESS;
}

void *  dpa_get_ipsec_instance(void)
{
	return &ipsecinfo; 
}
 
int dpa_ipsec_ofport_td(struct ipsec_info *info, uint32_t table_type, void **td, 
			uint32_t* portid)
{
	if (table_type > MAX_MATCH_TABLES) {
                DPAIPSEC_ERROR("%s::invalid table type %d\n", __FUNCTION__, table_type);
		return FAILURE;
	}
	*td = info->ofport_td[table_type];
	*portid = info->ofport_portid;
	return SUCCESS;
}

int cdx_dpa_ipsec_wanport_td(struct ipsec_info *info, uint32_t table_type, void **td)
{
	if ((table_type != ESP_IPV4_TABLE) && (table_type != ESP_IPV6_TABLE)) {
                DPAIPSEC_ERROR("%s::invalid table type %d\n", __FUNCTION__, table_type);
		return FAILURE;
	}
	*td = info->wanport_td[table_type];
	return SUCCESS;
}

int cdx_dpa_ipsec_wanport_itf(struct ipsec_info *info, uint32_t *itf)
{
	if (info) {
		*itf = info->wanport_itf;
		return 0;
	}
	return -1;
}

static int add_ipsec_bpool(struct ipsec_info *info)
{
	struct dpa_bp *bp,*bp_parent;
	int buffer_count = 0, ret = 0, refill_cnt ;

        bp = kzalloc(sizeof(struct dpa_bp), 0);
        if (unlikely(bp == NULL)) {
                DPAIPSEC_ERROR("%s::failed to allocate mem for bman pool for ipsec\n", 
				__FUNCTION__);
        	return -1;
	}
	bp->size = IPSEC_BUFSIZE;
	bp->config_count = IPSEC_BUFCOUNT;
	//find pools used by ethernet devices and borrow buffers from it
	if (get_phys_port_poolinfo_bysize(IPSEC_BUFSIZE, &info->parent_pool_info)) {
                DPAIPSEC_ERROR("%s::failed to locate eth bman pool for ipsec\n", 
				__FUNCTION__);
		bman_free_pool(bp->pool);
		kfree(bp);
        	return -1;
	}
	bp_parent = dpa_bpid2pool(info->parent_pool_info.pool_id);
#ifdef DPA_IPSEC_DEBUG
        DPAIPSEC_INFO("%s::parent bman pool for ipsec - bp %p, bpid %d paddr %lx vaddr %p dev %p\n", 
		__FUNCTION__, bp, info->parent_pool_info.pool_id,
		(unsigned long)bp->paddr, bp->vaddr, bp->dev);
#endif
	bp->dev = bp_parent->dev;
	if (dpa_bp_alloc(bp, bp->dev)) {
                DPAIPSEC_ERROR("%s::dpa_bp_alloc failed for ipsec\n", 
				__FUNCTION__);
		kfree(bp);
        	return -1;
	}
	DPAIPSEC_INFO("%s::bp->size :%zu\n", __FUNCTION__, bp->size);
	info->ipsec_bp = bp;


	while (buffer_count < IPSEC_BUFCOUNT)
	{
		refill_cnt = 0;
		ret = dpaa_eth_refill_bpools(bp, &refill_cnt);
		if (ret < 0)
		{
			DPAIPSEC_ERROR("%s:: Error returned for dpaa_eth_refill_bpools %d\n", __FUNCTION__,ret);
			break;
		}

		buffer_count += refill_cnt;
	}
	info->ipsec_bp->size =  bp_parent->size; 
#ifdef DPA_IPSEC_DEBUG
	DPAIPSEC_INFO("%s::%d buffers added to ipsec pool %d info size %d parent pool size %d\n", 
			__FUNCTION__, buffer_count, info->ipsec_bp->bpid,
			info->parent_pool_info.buf_size,(int) bp_parent->size);
#endif
	return 0;
}
static int release_ipsec_bpool(struct ipsec_info *info)
{
	struct dpa_bp *bp =  info->ipsec_bp ;
	bman_free_pool(bp->pool);
	kfree(bp);
	info->ipsec_bp = NULL; 
	return 0;
}

int cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size)
{
	if (!ipsecinfo.ipsec_bp) 	
		return -1;
	*bpid = ipsecinfo.ipsec_bp->bpid;
	//*buf_size =ipsecinfo.parent_pool_info.buf_size;
	*buf_size = ipsecinfo.ipsec_bp->size;
	return 0;

}

void *cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle) 
{
	struct dpa_ipsec_sainfo *sainfo;

	sainfo = (struct dpa_ipsec_sainfo *)
		kzalloc(sizeof(struct dpa_ipsec_sainfo), GFP_KERNEL);
	if (!sainfo) {
        	DPAIPSEC_ERROR("%s::Error in allocating sainfo\n", 
				__FUNCTION__);
	}	
	memset(sainfo, 0, sizeof(struct dpa_ipsec_sainfo));
	//create fqs in scheduled state
	if (create_ipsec_fqs(sainfo, 1, handle)) {
		kfree(sainfo);
	}
	return sainfo; 	
}

int cdx_dpa_ipsecsa_release(void *handle) 
{
	struct dpa_ipsec_sainfo *sainfo;
	struct dpa_fq *dpa_fq;
        struct qman_fq *fq;
	uint32_t ii;
	uint32_t flags;

	if (!handle)
		return FAILURE;
	sainfo = (struct dpa_ipsec_sainfo *)handle;
	for (ii = 0; ii < 2; ii++) {
		dpa_fq = &sainfo->sec_fq[ii];
		fq = &dpa_fq->fq_base; 
		//drain fq TODO
		//take fqs out of service
		if (qman_retire_fq(fq, &flags)) {
                	DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n", 
				__FUNCTION__, fq->fqid, fq->fqid);
                	return FAILURE;
        	}
        	if (qman_oos_fq(fq)) {
                	DPAIPSEC_ERROR("%s::Failed to retire FQ %x(%d)\n", 
					__FUNCTION__, fq->fqid, fq->fqid);
                	return FAILURE;
       		}
        	qman_destroy_fq(fq, 0);
	}
	kfree(sainfo);
	return SUCCESS;
}

#ifdef DPA_IPSEC_TEST_ENABLE
void dpa_ipsec_test(struct ipsec_info *info)
{
	void *handle;	
	struct sec_descriptor *sh_desc;
	uint32_t tosec_fqid;
	uint32_t fromsec_fqid;
	uint32_t portid;
	void *td;
	
	if (cdx_dpa_ipsec_wanport_td(info, ESP_IPV4_TABLE, &td)) {
		return;
	}	
	DPAIPSEC_INFO("%s::WAN ESP_IPV4_TABLE %p\n", __FUNCTION__, td);

	if (cdx_dpa_ipsec_wanport_td(info, ESP_IPV6_TABLE, &td)) {
		return;
	}	
	DPAIPSEC_INFO("%s::WAN ESP_IPV6_TABLE %p\n", __FUNCTION__, td);
	
	if (dpa_ipsec_ofport_td(info, IPV4_UDP_TABLE, &td, &portid)) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF IPV4_TCPUDP_TABLE %p\n", __FUNCTION__, td);

	if (dpa_ipsec_ofport_td(info, IPV6_UDP_TABLE, &td, &portid )) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF IPV6_TCPUDP_TABLE %p\n", __FUNCTION__, td);

	if (dpa_ipsec_ofport_td(info, ESP_IPV4_TABLE, &td, &portid)) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF ESP_IPV4_TABLE %p, portif = %d\n", __FUNCTION__, td, portid);

	if (dpa_ipsec_ofport_td(info, ESP_IPV6_TABLE, &td, &portid)) {
		return;
	}	
	DPAIPSEC_INFO("%s::OF ESP_IPV6_TABLE %p\n", __FUNCTION__, td);

	handle = cdx_dpa_ipsecsa_alloc(info, 0xaa55);
	if (handle) {
		sh_desc = get_shared_desc(handle);
		tosec_fqid = get_fqid_to_sec(handle);	
		fromsec_fqid = get_fqid_from_sec(handle);	
		DPAIPSEC_INFO("%s::sh desc %p, tosec fqid %x(%d) from sec fqid %x(%d)\n",
				__FUNCTION__, sh_desc, tosec_fqid, tosec_fqid,
				fromsec_fqid, fromsec_fqid); 
		if (cdx_dpa_ipsecsa_release(handle)) {
                	DPAIPSEC_ERROR("%s::Failed to release sa %p\n", 
					__FUNCTION__, handle);
			return;
		}		
	} else {
                DPAIPSEC_ERROR("%s::Failed to alloc sa\n", __FUNCTION__);
		return;
	}
}
#else
#define dpa_ipsec_test(x)
#endif


int cdx_dpa_ipsec_init(void)
{

        DPAIPSEC_INFO("%s::\n", __FUNCTION__);
	ipsecinfo.crypto_channel_id = qm_channel_caam;
        if (ipsec_init_ohport(&ipsecinfo)) {
                return FAILURE;
        }
	if (dpa_fill_wanport_info(&ipsecinfo)) {
                return FAILURE;
        }
	if (add_ipsec_bpool(&ipsecinfo)) {
                return FAILURE;
	}
	if (create_ipsec_pcd_fqs(&ipsecinfo, 1)) {
                return FAILURE;
	}
		
	dpa_ipsec_test(&ipsecinfo);
	return SUCCESS;
}
int cdx_dpa_ipsec_exit(void)
{
        DPAIPSEC_INFO("%s::\n", __FUNCTION__);
 	release_ipsec_bpool(&ipsecinfo);
	return SUCCESS;
}
#else
#define cdx_dpa_ipsec_init()
#endif
