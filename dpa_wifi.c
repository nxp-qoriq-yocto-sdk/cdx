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

#include <linux/fsl_bman.h>

#include "portdefs.h"
#include "dpaa_eth.h"
#include "dpaa_eth_common.h"
#include "dpa_wifi.h"
#include "layer2.h"

//#define DPA_WIFI_DEBUG  1

#define DPAWIFI_ERROR(fmt, ...)\
{\
        printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#define DPAWIFI_INFO(fmt, ...)\
{\
        printk(KERN_INFO fmt, ## __VA_ARGS__);\
}


#ifdef CFG_WIFI_OFFLOAD

#define BUFFER_COPY 1 
struct dpaa_vwd_priv_s vwd;
unsigned int vwd_ofld = VWD_BHR_MODE;

extern struct qman_fq* dpa_get_tx_fq_by_name(char *name, uint32_t *fqid);
extern int vwd_wifi_if_send_pkt(struct sk_buff *skb);
extern struct dpa_bp *dpa_bpid2pool(int bpid);
extern int alloc_offline_port(uint32_t fm_idx, uint32_t type, qman_cb_dqrr defa_rx, qman_cb_dqrr err_rx);
extern int release_offline_port(uint32_t fm_idx, int handle);
extern int cdx_copy_eth_rx_channel_info(uint32_t fman_idx, struct dpa_fq *dpa_fq);
extern int get_ofport_info(uint32_t fm_idx, uint32_t handle, uint32_t *channel, void **td);
extern int get_phys_port_poolinfo_bysize(uint32_t size, struct port_bman_pool_info *pool_info);
extern void display_buf(void *buf, uint32_t size);
extern int get_oh_port_pcd_fqinfo(uint32_t fm_idx, uint32_t handle, uint32_t type, 
				uint32_t *fqid, uint32_t *count);
extern int get_ofport_portid(uint32_t fm_index, uint32_t handle, uint32_t *portid);
extern struct dpa_priv_s* get_eth_priv(unsigned char* name);
extern struct sk_buff *__hot get_vwd_skb(const struct dpa_priv_s *priv,
                               const struct qm_fd *fd, int *use_gro,
                               int *count_ptr);


static int dpaa_vwd_open(struct inode *inode, struct file *file);
static int dpaa_vwd_close(struct inode * inode, struct file * file);
static long dpaa_vwd_ioctl(struct file * file, unsigned int cmd, unsigned long arg);
static unsigned int dpaa_vwd_nf_route_hook_fn( void *ops, // nf_hookfn modified in netfilter.h //const struct nf_hook_ops *ops,
                                                struct sk_buff *skb,
                                                const struct nf_hook_state *state);

static unsigned int dpaa_vwd_nf_bridge_hook_fn( void *ops, // nf_hookfn modified in netfilter.h //const struct nf_hook_ops *ops,
						struct sk_buff *skb,
						const struct nf_hook_state *state);

static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv, void *vap_handle, struct sk_buff *skb);
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_show_fast_path_enable(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_set_fast_path_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
static ssize_t vwd_show_route_hook_enable(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_show_bridge_hook_enable(struct device *dev, struct device_attribute *attr, char *buf);
static ssize_t vwd_set_bridge_hook_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);
static ssize_t vwd_set_route_hook_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count);

static DEVICE_ATTR(vwd_debug_stats, 0444, vwd_show_dump_stats, NULL);
static DEVICE_ATTR(vwd_fast_path_enable, 0644, vwd_show_fast_path_enable, vwd_set_fast_path_enable);
static DEVICE_ATTR(vwd_route_hook_enable, 0644, vwd_show_route_hook_enable, vwd_set_route_hook_enable);
static DEVICE_ATTR(vwd_bridge_hook_enable, 0644, vwd_show_bridge_hook_enable, vwd_set_bridge_hook_enable);
//static DEVICE_ATTR(vwd_tso_stats, 0644, vwd_show_tso_stats, vwd_set_tso_stats);


static const struct file_operations vwd_fops = {
        .owner                  = THIS_MODULE,
        .open                   = dpaa_vwd_open,
        .unlocked_ioctl         = dpaa_vwd_ioctl,
        .release                = dpaa_vwd_close
};

/* IPV4 route hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook = {
        .hook = dpaa_vwd_nf_route_hook_fn,
        .pf = PF_INET,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
};

/* IPV6 route hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook_ipv6 = {
	.hook = dpaa_vwd_nf_route_hook_fn,
	.pf = PF_INET6,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP6_PRI_FIRST,
};

/* Bridge hook , recieve the packet and forward to VWD driver*/
static struct nf_hook_ops vwd_hook_bridge = {
	.hook = dpaa_vwd_nf_bridge_hook_fn,
	.pf = PF_BRIDGE,
	.hooknum = NF_BR_PRE_ROUTING,
	.priority = NF_BR_PRI_FIRST,
};

#define DPA_WRITE_NETDEV_PTR(dev, devh, addr, off) \
{ \
        devh = (struct net_device **)addr; \
        *(devh + (off)) = dev; \
}
#define DPA_READ_NETDEV_PTR(dev, devh, addr, off) \
{ \
        devh = (struct net_device **)addr; \
        dev = *(devh + (off)); \
}


/** vwd_show_dump_stats
 *
 */
static ssize_t vwd_show_dump_stats(struct device *dev, struct device_attribute *attr, char *buf)
{
        ssize_t len = 0;
        struct dpaa_vwd_priv_s *priv = &vwd;
        //int ii;

#ifdef VWD_DEBUG_STATS
        len += sprintf(buf, "\nTo DPAA\n");
        len += sprintf(buf + len, "  WiFi Rx pkts : %d\n", priv->pkts_transmitted);
        len += sprintf(buf + len, "  WiFi Tx pkts : %d\n", priv->pkts_total_local_tx);
        len += sprintf(buf + len, "  WiFi Tx SG pkts : %d\n", priv->pkts_local_tx_sgs);
        len += sprintf(buf + len, "  Drops : %d\n", priv->pkts_tx_dropped);

        len += sprintf(buf + len, "From DPAA\n");
        //len += sprintf(buf + len, "  WiFi Rx pkts : %d %d %d\n", priv->pkts_slow_forwarded[0],
         //               priv->pkts_slow_forwarded[1], priv->pkts_slow_forwarded[2]);
        len += sprintf(buf + len, "  WiFi Rx pkts : %d \n", priv->pkts_slow_forwarded);
        len += sprintf(buf + len, "  WiFi Tx pkts : %d %d \n", priv->pkts_rx_fast_forwarded[0],
                        priv->pkts_rx_fast_forwarded[1]);
                        //priv->pkts_rx_fast_forwarded[1], priv->pkts_rx_fast_forwarded[2]);
        len += sprintf(buf + len, "  Skb Alloc fails : %d\n", priv->rx_skb_alloc_fail);
        len += sprintf(buf + len, "  WiFI Rx Fails : %d\n", priv->pkts_slow_fail);
#endif
        len += sprintf(buf + len, "\nStatus\n");
        len += sprintf(buf + len, "  Fast path - %s\n", priv->fast_path_enable ? "Enable" : "Disable");
        len += sprintf(buf + len, "  Route hook - %s\n", priv->fast_routing_enable ? "Enable" : "Disable");
        len += sprintf(buf + len, "  Bridge hook - %s\n", priv->fast_bridging_enable ? "Enable" : "Disable");

#if 0
	len += sprintf(buf + len, "VAPs Configuration  : \n");
        for (ii = 0; ii < MAX_VAP_SUPPORT; ii++) {
                struct vap_desc_s *vap;

                vap = &priv->vaps[ii];

                if (vap->state == VAP_ST_CLOSE)
                        continue;

                len += sprintf(buf + len, "VAP Name : %s \n", vap->ifname);
                len += sprintf(buf + len, "     Id             : %d \n", vap->vapid);
                len += sprintf(buf + len, "     Index          : %d \n", vap->ifindex);
                len += sprintf(buf + len, "     State          : %s \n", (vap->state  == VAP_ST_OPEN) ? "OPEN":"CLOSED");
                len += sprintf(buf + len, "     CPU Affinity   : %d \n", vap->cpu_id);
                len += sprintf(buf + len, "     Direct Rx path : %s \n", vap->direct_rx_path ? "ON":"OFF");
                len += sprintf(buf + len, "     Direct Tx path : %s \n", vap->direct_tx_path ? "ON":"OFF");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
                len += sprintf(buf + len, "     Dev features   : VAP: %llx WiFi: %llx \n\n", vap->dev->features, vap->wifi_dev ? vap->wifi_dev->features:0);
#else
                len += sprintf(buf + len, "     Dev features   : VAP: %x WiFi: %x \n\n", vap->dev->features, vap->wifi_dev ? vap->wifi_dev->features:0);
#endif
        }
#endif

        return len;
}


/** vwd_show_fast_path_enable
 *
 */
static ssize_t vwd_show_fast_path_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        int idx;

        idx = sprintf(buf, "\n%d\n", priv->fast_path_enable);

        return idx;
}

/** vwd_set_fast_path_enable
 *
 */
static ssize_t vwd_set_fast_path_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct dpaa_vwd_priv_s  *priv = &vwd;
        unsigned int fast_path = 0;

        sscanf(buf, "%d", &fast_path);

        printk("%s: Wifi fast path %d\n", __func__, fast_path);

        if (fast_path && !priv->fast_path_enable)
        {
                printk("%s: Wifi fast path enabled \n", __func__);

                priv->fast_path_enable = 1;
        }
        else if (!fast_path && priv->fast_path_enable)
        {
                printk("%s: Wifi fast path disabled \n", __func__);

                priv->fast_path_enable = 0;

        }

        return count;
}

/** vwd_show_route_hook_enable
 *
 */
static ssize_t vwd_show_route_hook_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        int idx;

        idx = sprintf(buf, "\n%d\n", priv->fast_routing_enable);

        return idx;
}

/** vwd_set_route_hook_enable
 *
 */
static ssize_t vwd_set_route_hook_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        unsigned int user_val = 0;

        sscanf(buf, "%d", &user_val);

        if (user_val && !priv->fast_routing_enable)
        {
                printk("%s: Wifi fast routing enabled \n", __func__);
                priv->fast_routing_enable = 1;

                if (priv->fast_bridging_enable)
                {
                        nf_unregister_net_hook(&init_net,&vwd_hook_bridge);
                        priv->fast_bridging_enable = 0;
                }

                nf_register_net_hook(&init_net,&vwd_hook);
                nf_register_net_hook(&init_net,&vwd_hook_ipv6);


        }
        else if (!user_val && priv->fast_routing_enable)
        {
                printk("%s: Wifi fast routing disabled \n", __func__);
                priv->fast_routing_enable = 0;

                nf_unregister_net_hook(&init_net,&vwd_hook);
                nf_unregister_net_hook(&init_net,&vwd_hook_ipv6);

        }

        return count;
}

/** vwd_show_bridge_hook_enable
 *
 */
static ssize_t vwd_show_bridge_hook_enable(struct device *dev, struct device_attribute *attr, char *buf)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        int idx;

        idx = sprintf(buf, "%d", priv->fast_bridging_enable);
        return idx;
}

/** vwd_set_bridge_hook_enable
 *
 */
static ssize_t vwd_set_bridge_hook_enable(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        unsigned int user_val = 0;

        sscanf(buf, "%d", &user_val);

        if ( user_val && !priv->fast_bridging_enable )
        {
                printk("%s: Wifi fast bridging enabled \n", __func__);
                priv->fast_bridging_enable = 1;

                if(priv->fast_routing_enable)
                {
                        nf_unregister_net_hook(&init_net,&vwd_hook);
                        nf_unregister_net_hook(&init_net,&vwd_hook_ipv6);
                        priv->fast_routing_enable = 0;
                }

                nf_register_net_hook(&init_net,&vwd_hook_bridge);
        }
        else if ( !user_val && priv->fast_bridging_enable )
        {
                printk("%s: Wifi fast bridging disabled \n", __func__);
                priv->fast_bridging_enable = 0;

                nf_unregister_net_hook(&init_net,&vwd_hook_bridge);
        }

        return count;
}


/** dpaa_vwd_sysfs_init
 *
 */
static int dpaa_vwd_sysfs_init( struct dpaa_vwd_priv_s *priv )
{

        if (device_create_file(priv->vwd_device, &dev_attr_vwd_debug_stats))
                goto err_dbg_sts;

        if (device_create_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable))
                goto err_fp_en;

        if (device_create_file(priv->vwd_device, &dev_attr_vwd_route_hook_enable))
                goto err_rt;

        if (device_create_file(priv->vwd_device, &dev_attr_vwd_bridge_hook_enable))
                goto err_br;

#if 0
        if ((vwd_ofld == PFE_VWD_NAS_MODE ) && device_create_file(priv->vwd_device, &dev_attr_vwd_vap_create))
                goto err_vap_add;

        if ((vwd_ofld == PFE_VWD_NAS_MODE) && device_create_file(priv->vwd_device, &dev_attr_vwd_vap_reset))
                goto err_vap_del;

        if (device_create_file(vwd->vwd_device, &dev_attr_vwd_tso_stats))
                goto err_tso_stats;
#endif

#ifdef VWD_NAPI_STATS
        if (device_create_file(priv->vwd_device, &dev_attr_vwd_napi_stats))
                goto err_napi;
#endif

#ifdef VWD_LRO_STATS
        if (device_create_file(priv->vwd_device, &dev_attr_vwd_lro_nb_stats))
                goto err_lro_nb;

        if (device_create_file(priv->vwd_device, &dev_attr_vwd_lro_len_stats))
                goto err_lro_len;
#endif

        return 0;

#ifdef VWD_LRO_STATS
err_lro_len:
        device_remove_file(priv->vwd_device, &dev_attr_vwd_lro_nb_stats);
err_lro_nb:
#endif

#ifdef VWD_NAPI_STATS
        device_remove_file(priv->vwd_device, &dev_attr_vwd_napi_stats);
err_napi:
#endif

#if defined(PFE_VWD_LRO_STATS) || defined(PFE_VWD_NAPI_STATS)
        device_remove_file(priv->vwd_device, &dev_attr_vwd_tso_stats);
#endif

#if 0
err_tso_stats:
        if (vwd_ofld == VWD_NAS_MODE)
                device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_reset);
err_vap_del:
        if (vwd_ofld == VWD_NAS_MODE)
                device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_create);
err_vap_add:
#endif
        device_remove_file(priv->vwd_device, &dev_attr_vwd_bridge_hook_enable);
err_br:
        device_remove_file(priv->vwd_device, &dev_attr_vwd_route_hook_enable);
err_rt:
        device_remove_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable);
err_fp_en:
        device_remove_file(priv->vwd_device, &dev_attr_vwd_debug_stats);
err_dbg_sts:
        return -1;

}

/** dpaa_vwd_sysfs_exit
 *
 */
static void dpaa_vwd_sysfs_exit(void)
{
	struct dpaa_vwd_priv_s *priv = &vwd;

#if 0
        device_remove_file(priv->vwd_device, &dev_attr_vwd_tso_stats);
#ifdef PFE_VWD_LRO_STATS
        device_remove_file(priv->vwd_device, &dev_attr_vwd_lro_len_stats);
        device_remove_file(priv->vwd_device, &dev_attr_vwd_lro_nb_stats);
#endif
#endif

#ifdef PFE_VWD_NAPI_STATS
        device_remove_file(priv->vwd_device, &dev_attr_vwd_napi_stats);
#endif
#if 0
        if (vwd_ofld == PFE_VWD_NAS_MODE) {
                device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_create);
                device_remove_file(priv->vwd_device, &dev_attr_vwd_vap_reset);
        }
#endif
        device_remove_file(priv->vwd_device, &dev_attr_vwd_bridge_hook_enable);
        device_remove_file(priv->vwd_device, &dev_attr_vwd_route_hook_enable);
        device_remove_file(priv->vwd_device, &dev_attr_vwd_fast_path_enable);
        device_remove_file(priv->vwd_device, &dev_attr_vwd_debug_stats);
}



/** vwd_classify_packet
 *
 */
static int vwd_classify_packet( struct dpaa_vwd_priv_s *priv, struct sk_buff *skb, 
					int bridge_hook, int route_hook, int *vapid, int *own_mac)
{
        unsigned short type;
        struct vap_desc_s *vap;
        int rc = 1, ii, length;
        unsigned char *data_ptr;
        struct ethhdr *hdr;
#if defined (CONFIG_VWD_MULTI_MAC)
        struct net_bridge_fdb_entry *dst = NULL;
        struct net_bridge_port *p = NULL;
        const unsigned char *dest = eth_hdr(skb)->h_dest;
#endif
        *own_mac = 0;

        /* Move to packet network header */
        data_ptr = skb_mac_header(skb);
        length = skb->len + (skb->data - data_ptr);

        spin_lock_bh(&priv->vaplock);
        /* Broadcasts and MC are handled by stack */
        if( (eth_hdr(skb)->h_dest[0] & 0x1) ||
                        ( length <= ETH_HLEN ) )
        {
                rc = 1;
                goto done;
        }

        /* FIXME: This packet is VWD slow path packet, and already seen by VWD */

        if (*(unsigned long *)skb->head == 0xdead)
        {
                //printk(KERN_INFO "%s:This is dead packet....\n", __func__);
                *(unsigned long *)skb->head = 0x0;
                rc = 1;
                goto done;
        }

#ifdef VWD_DEBUG
        printk(KERN_INFO "%s: skb cur len:%d skb orig len:%d\n", __func__, skb->len, length );
#endif

        /* FIXME: We need to check the route table for the route entry. If route
         *  entry found for the current packet, send the packet to PFE. Otherwise
         *  REJECT the packet.
         */
        for ( ii = 0; ii < MAX_VAP_SUPPORT; ii++ )
        {
                vap = &priv->vaps[ii];
                if (vap->ifindex == skb->skb_iif)
                {
                        /* This interface packets need to be processed by direct API */
                        if (vap->direct_rx_path || (vap->state != VAP_ST_OPEN)) {
                                rc = 1;
                                goto done;
                        }

                        hdr = (struct ethhdr *)data_ptr;
                        type = htons(hdr->h_proto);
                        data_ptr += ETH_HLEN;
                        length -= ETH_HLEN;
                        rc = 0;

                        *vapid = vap->vapid;

                       /* FIXME send only IPV4 and IPV6 packets to PFE */
                        //Determain final protocol type
                        //FIXME : This multi level parsing is not required for
                        //        Bridged packets.
                        if( type == ETH_P_8021Q )
                        {
                                struct vlan_hdr *vhdr = (struct vlan_hdr *)data_ptr;

                                data_ptr += VLAN_HLEN;
                                length -= VLAN_HLEN;
                                type = htons(vhdr->h_vlan_encapsulated_proto);
                        }

                        if( type == ETH_P_PPP_SES )
                        {
                                struct pppoe_hdr *phdr = (struct pppoe_hdr *)data_ptr;

                                if (htons(*(u16 *)(phdr+1)) == PPP_IP)
                                        type = ETH_P_IP;
                                else if (htons(*(u16 *)(phdr+1)) == PPP_IPV6)
                                        type = ETH_P_IPV6;
                        }

                        if (bridge_hook)
                        {
#if defined (CONFIG_VWD_MULTI_MAC)
                                /* check if destination MAC matches one of the interfaces attached to the bridge */
                                if((p = rcu_dereference(skb->dev->br_port)) != NULL)
                                        dst = __br_fdb_get(p->br, dest);

                                if (skb->pkt_type == PACKET_HOST || (dst && dst->is_local))
#else
                                        if (skb->pkt_type == PACKET_HOST)
#endif
                                        {
                                                *own_mac = 1;

                                                if ((type != ETH_P_IP) && (type != ETH_P_IPV6))
                                                {
                                                        rc = 1;
                                                        goto done;
                                                }
                                        }
                                        else if (!memcmp(vap->macaddr, eth_hdr(skb)->h_dest, ETH_ALEN))
                                        {
                                                //WiFi management packets received with dst address
                                                //as bssid
                                                rc = 1;
                                                goto done;
                                        }
                        }
                        else
                                *own_mac = 1;

                        break;
                }

        }

done:
        spin_unlock_bh(&priv->vaplock);
        return rc;
}



static unsigned int dpaa_vwd_nf_bridge_hook_fn( void *ops, //const struct nf_hook_ops *ops,
						struct sk_buff *skb,
						const struct nf_hook_state *state)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	int vapid = -1;
	int own_mac = 0;


	if (!priv->fast_path_enable)
		goto done;

	if( !vwd_classify_packet(priv, skb, 1, 0, &vapid, &own_mac) )
	{
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s: Accepted devname : %s \n", __func__,skb->dev->name);
		//      vwd_dump_skb( skb );
#endif
		skb_push(skb, ETH_HLEN);
		dpaa_vwd_send_packet( priv, &priv->vaps[vapid], skb);
		return NF_STOLEN;
	}
done:
	return NF_ACCEPT;

}

/** vwd_nf_route_hook_fn
 *
 */
static unsigned int dpaa_vwd_nf_route_hook_fn( void *ops, //const struct nf_hook_ops *ops,
                                                struct sk_buff *skb,
                                                const struct nf_hook_state *state)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        int vapid = -1;
	int own_mac = 0;


        if (!priv->fast_path_enable)
                goto done;

        if( !vwd_classify_packet(priv, skb, 0, 1, &vapid, &own_mac) )
        {
#ifdef DPA_WIFI_DEBUG
		DPAWIFI_INFO("%s: Accepted devname : %s \n", __func__,skb->dev->name);
        //      vwd_dump_skb( skb );
#endif
                skb_push(skb, ETH_HLEN);
                dpaa_vwd_send_packet( priv, &priv->vaps[vapid], skb);
                return NF_STOLEN;
        }
done:
        return NF_ACCEPT;
}


int dpa_xmit_to_oh(struct qm_fd *fd, void* vap_handle)
{
        struct vap_desc_s *vap_dev;
	int i, err;

        vap_dev = (struct vap_desc_s *)vap_handle;
	display_fd(fd);
	for (i = 0; i < 100000; i++) {
                err = qman_enqueue(&vap_dev->wlan_fq_to_fman->fq_base, fd, 0);
                if (err != -EBUSY)
                        break;
        }
	if (unlikely(err < 0)) {
                //percpu_stats->tx_errors++;
                //percpu_stats->tx_fifo_errors++;
                return err;
        }

#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO("%s::ENQUEUED to dpaa\n", __FUNCTION__);
#endif
	return 0;
} 

#ifndef BUFFER_COPY
int __hot vwd_skb_to_contig_fd(struct dpa_priv_s *priv,
                               struct sk_buff *skb, struct qm_fd *fd,
                               int* offset)
{
	unsigned char *buffer_start;
	dma_addr_t addr;
	struct dpa_bp *dpa_bp = priv->dpa_bp;
	enum dma_data_direction dma_dir;
	struct sk_buff **skbh;
	//int headroom = 128;


	fd->bpid = 0xff;
	buffer_start = skb->data - skb_headroom(skb);
	fd->offset = skb_headroom(skb);
	
	dma_dir = DMA_TO_DEVICE;

	//DPAWIFI_INFO("%s::headroom :%d - %d - %d \n", __FUNCTION__, priv->tx_headroom, skb_headroom(skb), skb->len);
	//DPAWIFI_INFO("%s::skb :%p - %p - %p\n", __FUNCTION__, skb, skb->data, skb->head);
	
	DPA_WRITE_SKB_PTR(skb, skbh, buffer_start, 0);

	*offset = skb_headroom(skb) - fd->offset;

	/* Fill in the rest of the FD fields */
        fd->format = qm_fd_contig;
        fd->length20 = skb->len;
        //fd->cmd |= FM_FD_CMD_FCO;

	/* Map the entire buffer size that may be seen by FMan, but no more */
        addr = dma_map_single(dpa_bp->dev, skbh,
                        skb_tail_pointer(skb) - buffer_start, dma_dir);
        if (unlikely(dma_mapping_error(dpa_bp->dev, addr))) {
		DPAWIFI_ERROR("%s::DMA MAPPING ERROR :\n", __FUNCTION__);
                return -EINVAL;
        }

	fd->addr = addr;
	DPAWIFI_INFO("%s::phys addr :%llx \n", __FUNCTION__, addr);

	return 0;

}

static struct sk_buff *__hot contig_fd_to_vwd_skb(const struct dpa_priv_s *priv,
        					  const struct qm_fd *fd)
{
	dma_addr_t addr = qm_fd_addr(fd);
        //ssize_t fd_off = dpa_fd_offset(fd);
        void *vaddr;
	struct sk_buff *skb = NULL, **skbh;

	vaddr = phys_to_virt(addr);

        DPA_BUG_ON(!IS_ALIGNED((unsigned long)vaddr, SMP_CACHE_BYTES));

        /* Retrieve the skb and adjust data and tail pointers, to make sure
         * forwarded skbs will have enough space on Tx if extra headers
         * are added.
         */
        DPA_READ_SKB_PTR(skb, skbh, vaddr, 0);

	//DPAWIFI_INFO("%s::rx_hd_room :%d fd_off :%zd\n", __FUNCTION__, priv->rx_headroom, fd_off);

	//DPAWIFI_INFO("%s::FIRST skb :%p - %p - %p - %d\n", __FUNCTION__, skb, skb->data, skb->head,skb->len);
	//DPA_BUG_ON(fd_off != priv->rx_headroom);
        //skb_reserve(skb, fd_off);
        //skb_put(skb, dpa_fd_length(fd));

	return skb;

}
#endif

#ifndef BUFFER_COPY
static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv ,void *vap_handle, struct sk_buff *skb)
{
	struct vap_desc_s *vap_dev;
	struct qm_fd fd;
	int err;
	int offset;

	vap_dev = (struct vap_desc_s *)vap_handle;

	memset(&fd, 0, sizeof(struct qm_fd));
	err = vwd_skb_to_contig_fd(priv->eth_priv, skb, &fd, &offset);

	if (unlikely(err < 0))
	{
		DPAWIFI_ERROR("%s::vwd_skb_to_contig_fd failed\n", __FUNCTION__);
                goto skb_to_fd_failed;
	}

	if (qman_enqueue(&vap_dev->wlan_fq_to_fman->fq_base, &fd, 0)) {
                DPAWIFI_ERROR("%s::qman_enqueue failed\n", __FUNCTION__);
                goto qman_enq_failed;
        }

#ifdef VWD_DEBUG_STATS
        priv->pkts_transmitted += 1;
#endif
	return 0;

skb_to_fd_failed:
qman_enq_failed:
#ifdef VWD_DEBUG_STATS
	priv->pkts_tx_dropped += 1;
#endif
        dev_kfree_skb(skb);
        return -1;
}

static int process_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
                           const struct qm_dqrr_entry *dq)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        struct sk_buff *skb;
        struct net_device *net_dev;

        net_dev = ((struct dpa_fq *)fq)->net_dev;

#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO("%s::exception packet\n", __FUNCTION__);
        DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s addr %llx\n", __FUNCTION__,
                dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
                dq->fd.offset, net_dev, net_dev->name, (uint64_t)dq->fd.addr);
#endif

        if (dq->fd.format != qm_fd_contig) {
                DPAWIFI_ERROR("%s::TBD discarding SG frame\n ", __FUNCTION__);
#ifdef VWD_DEBUG_STATS
                priv->pkts_slow_fail += 1;
#endif
                goto rel_fd;
        }

        skb = contig_fd_to_vwd_skb(priv->eth_priv, &dq->fd);

        skb->dev = net_dev;
        skb->protocol = eth_type_trans(skb, net_dev);
        *(unsigned long *)skb->head = 0xdead;
        netif_receive_skb(skb);

#ifdef VWD_DEBUG_STATS
        priv->pkts_slow_forwarded += 1;
#endif

rel_fd:
        return 0;
}
#endif


/** dpaa_vwd_send_packet
 *
 */

#ifdef BUFFER_COPY
static int dpaa_vwd_send_packet(struct dpaa_vwd_priv_s *priv ,void *vap_handle, struct sk_buff *skb)
{
	int retval;
	struct qm_fd fd;
	uint32_t len;
	struct vap_desc_s *vap_dev;
	struct bm_buffer bmb;
	char *ptr ,*buffer_start;
	struct net_device *dev, **devh;

#ifdef DPA_WIFI_DEBUG
	//DPAWIFI_INFO("%s::pkt enqueue to dpaa\n", __FUNCTION__);
#endif
	retval = -1;
	vap_dev = (struct vap_desc_s *)vap_handle;
	len = skb->len;
	if (len > priv->parent_pool_info.buf_size) {
		DPAWIFI_ERROR("%s::dropped packet, pkt too big %d - %d\n", __FUNCTION__, len, priv->parent_pool_info.buf_size);
#ifdef VWD_DEBUG_STATS
		priv->pkts_tx_dropped += 1;
#endif
		goto err_ret;
	}
	if (bman_acquire(priv->bp->pool, &bmb, 1, 0) != 1) {
		//DPAWIFI_ERROR("%s::dropped packet, pool empty\n", __FUNCTION__);
#ifdef VWD_DEBUG_STATS
		priv->pkts_tx_dropped += 1;
#endif
		goto err_ret;
        }

	memset(&fd, 0, sizeof(struct qm_fd));
	fd.format = qm_fd_contig;
        fd.bpid = priv->bp->bpid;

        fd.length20 = len;
        fd.addr = bmb.addr;
        fd.offset = VAPBUF_HEADROOM;
	
	buffer_start = (phys_to_virt((uint64_t)bmb.addr));
	ptr = (phys_to_virt((uint64_t)bmb.addr) + dpa_fd_offset(&fd));
	dev = skb->dev;
	devh = &dev;
	
	DPA_WRITE_NETDEV_PTR(dev, devh, buffer_start, 0);

	if (skb_is_nonlinear(skb))
        {
                if (skb_linearize(skb))
                {
			struct skb_shared_info *sh;
			sh = skb_shinfo(skb);
                        printk(KERN_INFO "%s:: can't linearize, nr_frags: %d\n",__func__, sh->nr_frags);
                        goto err_ret;
                }
        }

	/* Copy the packet payload */
        skb_copy_from_linear_data(skb, ptr, len);
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("buf paddr %lx len %d ptr %p\n", (unsigned long)fd.addr, len, ptr);
	display_buf(ptr, len);
	display_fd(&fd);
	DPAWIFI_INFO("enqueue to fqid %x(%d)\n", vap_dev->wlan_fq_to_fman->fq_base.fqid,
			vap_dev->wlan_fq_to_fman->fq_base.fqid);
	//DPAWIFI_INFO("$ ");
#endif
        if (qman_enqueue(&vap_dev->wlan_fq_to_fman->fq_base, &fd, 0)) {
		DPAWIFI_ERROR("%s::qman_enqueue failed\n", __FUNCTION__);
		bman_release(priv->bp->pool, &bmb, 1, 0);
#ifdef VWD_DEBUG_STATS
		priv->pkts_tx_dropped += 1;
#endif
		goto err_ret;
	}

#ifdef VWD_DEBUG_STATS
        priv->pkts_transmitted += 1;
#endif
	retval = 0;
err_ret:
	dev_kfree_skb(skb);
	return retval;
}

static int process_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
                           const struct qm_dqrr_entry *dq)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        struct sk_buff *skb;
        struct net_device *net_dev;
        struct bm_buffer bmb;
        struct dpa_bp *dpa_bp;
        uint32_t len;
        uint8_t *ptr, *buffer_start;
        uint8_t *skb_ptr;
        struct net_device *dev , **devh;

        net_dev = ((struct dpa_fq *)fq)->net_dev;

#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO("%s::exception packet\n", __FUNCTION__);
        DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s addr %llx status: %x\n", __FUNCTION__,
                dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
                dq->fd.offset, net_dev, net_dev->name, (uint64_t)dq->fd.addr, dq->fd.status);
#endif

        if (dq->fd.format != qm_fd_contig) {
                DPAWIFI_ERROR("%s::TBD discarding SG frame\n ", __FUNCTION__);
#ifdef VWD_DEBUG_STATS
                priv->pkts_slow_fail += 1;
#endif
                goto rel_fd;
        }

	len = dq->fd.length20;
	buffer_start = (phys_to_virt((uint64_t)dq->fd.addr));
        ptr = (phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);

        DPA_READ_NETDEV_PTR(dev, devh, buffer_start, 0);
        //DPAWIFI_INFO("%s:: skb->dev:%p:%s \n", __func__, dev, dev->name);

        skb = dev_alloc_skb(len);
        if (!skb) {
                DPAWIFI_ERROR("%s::skb alloc failed\n", __FUNCTION__);
                goto rel_fd;
        }
        skb_ptr = skb_put(skb, len);
        memcpy(skb_ptr, ptr, len);
        //skb->dev = net_dev;
	skb->dev = dev;
        skb->protocol = eth_type_trans(skb, net_dev);
        *(unsigned long *)skb->head = 0xdead;

       netif_receive_skb(skb);

#ifdef VWD_DEBUG_STATS
        priv->pkts_slow_forwarded += 1;
#endif
rel_fd:
        bmb.bpid = dq->fd.bpid;
        bmb.addr = dq->fd.addr;
        dpa_bp = dpa_bpid2pool(dq->fd.bpid);
        while (bman_release(dpa_bp->pool, &bmb, 1, 0))
                cpu_relax();
        return 0;
}
#endif



static enum qman_cb_dqrr_result vap_rx_exception_pkt(struct qman_portal *portal, struct qman_fq *fq,
                           const struct qm_dqrr_entry *dq)
{

	struct dpa_priv_s               *priv = vwd.eth_priv;
	struct dpa_percpu_priv_s        *percpu_priv;
	//struct dpa_bp   *dpa_bp = priv->dpa_bp;
        //int* count_ptr = raw_cpu_ptr(dpa_bp->percpu_count);

	DPA_BUG_ON(priv);
	/* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
        percpu_priv = raw_cpu_ptr(priv->percpu_priv);

        if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
                return qman_cb_dqrr_stop;

#if 0
	if ( unlikely (dpaa_eth_refill_bpools(dpa_bp, count_ptr)))
        {
                DPAWIFI_INFO("%s:: refilled bpools failed\n", __FUNCTION__);
                dpa_fd_release(priv->net_dev, &dq->fd);
        }
        else
#endif
		process_rx_exception_pkt(portal, fq, dq);	

	return qman_cb_dqrr_consume;
}


void vwd_send_to_vap(struct sk_buff* skb)
{
	struct ethhdr *hdr;

	hdr = (struct ethhdr *)skb->data;
	skb->protocol = hdr->h_proto;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
	skb->mac.raw = skb->data;
	skb->nh.raw = skb->data + sizeof(struct ethhdr);
#else
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, sizeof(struct ethhdr));
#endif

	skb->priority = 0;

	original_dev_queue_xmit(skb);
	
	return;
}

static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq, struct dpa_percpu_priv_s        *percpu_priv);
static enum qman_cb_dqrr_result vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq,
                           const struct qm_dqrr_entry *dq)
{

        struct dpa_priv_s               *priv = vwd.eth_priv;
        struct dpa_percpu_priv_s        *percpu_priv;
	struct dpa_bp	*dpa_bp = priv->dpa_bp;
	struct net_device*	net_dev;
	int* count_ptr;

        DPA_BUG_ON(priv);
        /* IRQ handler, non-migratable; safe to use raw_cpu_ptr here */
        percpu_priv = raw_cpu_ptr(priv->percpu_priv);

	count_ptr = raw_cpu_ptr(dpa_bp->percpu_count);
	net_dev = ((struct dpa_fq *)fq)->net_dev;

        if (unlikely(dpaa_eth_napi_schedule(percpu_priv, portal)))
                return qman_cb_dqrr_stop;

#if 0
	if ( unlikely (dpaa_eth_refill_bpools(dpa_bp, count_ptr)))
	{
		DPAWIFI_INFO("%s:: refilled bpools failed\n", __FUNCTION__);
		dpa_fd_release(net_dev, &dq->fd);
	}
	else
#endif
		process_vap_rx_fwd_pkt(portal, fq, dq, percpu_priv);

        return qman_cb_dqrr_consume;
}


static int process_vap_rx_fwd_pkt(struct qman_portal *portal, struct qman_fq *fq, const struct qm_dqrr_entry *dq, struct dpa_percpu_priv_s *percpu_priv)
{
	struct dpaa_vwd_priv_s *priv = &vwd;
	uint8_t *ptr;
	uint8_t *skb_ptr;
	uint32_t len;
	struct sk_buff *skb;
	struct net_device *net_dev;
	struct bm_buffer bmb;
	struct dpa_bp *dpa_bp;

	net_dev = ((struct dpa_fq *)fq)->net_dev;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::forwarding packet\n", __FUNCTION__);
	DPAWIFI_INFO("%s::fqid %x(%d), bpid %d, len %d, offset %d netdev %p dev %s addr %llx\n", __FUNCTION__,
		dq->fqid, dq->fqid, dq->fd.bpid, dq->fd.length20,
		dq->fd.offset, net_dev, net_dev->name, (uint64_t)dq->fd.addr);
#endif
	/* The only FD types that we may receive are contig and S/G */
       if (dq->fd.format != qm_fd_contig) {
                DPAWIFI_ERROR("%s::TBD discarding SG frame :%d\n ", __FUNCTION__,dq->fd.format);
#ifdef VWD_DEBUG_STATS
                priv->pkts_slow_fail += 1;
#endif
                goto rel_fd;
        }

	len = dq->fd.length20;
	ptr = (phys_to_virt((uint64_t)dq->fd.addr) + dq->fd.offset);
	skb = dev_alloc_skb(len);
	if (!skb) {
		DPAWIFI_ERROR("%s::skb alloc failed\n", __FUNCTION__);
#ifdef VWD_DEBUG_STATS
		priv->rx_skb_alloc_fail += 1;
#endif

		goto rel_fd;
	}
	skb_ptr = skb_put(skb, len);
	memcpy(skb_ptr, ptr, len);
	skb->dev = net_dev;
	//vwd_wifi_if_send_pkt(skb); 
	//original_dev_queue_xmit(skb);
#ifdef VWD_DEBUG_STATS
	priv->pkts_rx_fast_forwarded[0] += 1;
#endif

	vwd_send_to_vap(skb);

rel_fd:
	bmb.bpid = dq->fd.bpid;
	bmb.addr = dq->fd.addr;
	dpa_bp = dpa_bpid2pool(dq->fd.bpid);
	while (bman_release(dpa_bp->pool, &bmb, 1, 0))
		cpu_relax();

	return 0;
}

#define PORTID_SHIFT_VAL 8
static int create_vap_pcd_fqs(struct vap_desc_s *vap)
{
	uint32_t fqbase;
	uint32_t fqcount;
	uint32_t portid;
	uint32_t ii;
	uint32_t portal_channel[NR_CPUS];
        uint32_t num_portals;
        uint32_t next_portal_ch_idx;
        const cpumask_t *affine_cpus;
	struct dpa_fq *dpa_fq;

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
                DPAWIFI_ERROR("%s::unable to get affined portal info\n",
                                                __FUNCTION__);
                return -1;
        }
#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO("%s::num_portals %d ::", __FUNCTION__, num_portals);
        for (ii = 0; ii < num_portals; ii++)
                DPAWIFI_INFO("%d ", portal_channel[ii]);
        DPAWIFI_INFO("\n");
#endif

#ifdef USE_PCD_FQ
	//get FQbase and count used for ethernet dist
	//with scheme sharing this is the only distribution that will be used
	if (get_oh_port_pcd_fqinfo(FMAN_IDX, vap->vwd->oh_port_handle, 
			ETHERNET_DIST, &fqbase, &fqcount)) {
			DPAWIFI_ERROR("%s::err getting pcd fq\n", __FUNCTION__) ;
			return -1;
	}
	//get port id required for FQ creation
	if (get_ofport_portid(FMAN_IDX, vap->vwd->oh_port_handle, &portid)) {
			DPAWIFI_ERROR("%s::err getting of port id\n", __FUNCTION__) ;
			return -1;
	}
	DPAWIFI_INFO("%s::pcd FQ base for portid %d eth dist %x(%d), count %d\n", 
		__FUNCTION__, portid, fqbase, fqbase, fqcount);
#endif
	//alloc for as amay fqs as required
	vap->wlan_exception_fq = kzalloc((sizeof(struct dpa_fq) * fqcount), 
			1);
	if (!vap->wlan_exception_fq) {
		DPAWIFI_ERROR("%s::err allocating fq mem\n", __FUNCTION__) ;
		return -1;
	}
	//save dpa_fq base info
	dpa_fq = vap->wlan_exception_fq;
	//add port id into FQID
	fqbase |= (portid << PORTID_SHIFT_VAL);
	//create all FQs
	vap->vwd->expt_fq_count = 0;
	for (ii = 0; ii < fqcount; ii++) {
		struct qman_fq *fq;
		struct qm_mcc_initfq opts;
	
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		//set FQ parameters
                dpa_fq->net_dev = vap->wifi_dev;
                dpa_fq->fq_type = FQ_TYPE_RX_PCD;
                dpa_fq->fqid = fqbase;
		//set call back function pointer
                fq = &dpa_fq->fq_base;
		fq->cb.dqrr = vap_rx_exception_pkt;
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
                        DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
                                 __FUNCTION__, dpa_fq->fqid);
			goto err_ret;
                }
                opts.fqid = dpa_fq->fqid;
                opts.count = 1;
                opts.fqd.dest.channel = dpa_fq->channel;
                opts.fqd.dest.wq = dpa_fq->wq;
                opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
                                QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);

		//init FQ
                if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
                        DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
                                __FUNCTION__, dpa_fq->fqid);
                        qman_destroy_fq(fq, 0);
			goto err_ret;
                }
#ifdef DPA_WIFI_DEBUG
                DPAWIFI_INFO("%s::created pcd fq %x(%d) for wlan packets "
                        "channel 0x%x\n", __FUNCTION__,
                        dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
		//next FQ
		dpa_fq++;	
		fqbase++;
		vap->vwd->expt_fq_count++;
	}
	return 0;
err_ret:
	/* release FQs allocated so far and mem */
	return -1;
}

static int create_vap_fqs(struct vap_desc_s *vap)
{
	uint32_t ii;
	struct dpa_fq *dpa_fq;
	struct qman_fq *fq;
	struct qm_mcc_initfq opts;

	if (create_vap_pcd_fqs(vap))
	{
			DPAWIFI_ERROR("%s::unable to create pcd fqs\n", __FUNCTION__) ;
			return -1;
	}
		
	for (ii = 1; ii < 3; ii++) {
		struct dpa_fq **dpa_fq_ptr;
		uint32_t flags;

		//create FQ for exception packets from wireless interface
		dpa_fq = kzalloc(sizeof(struct dpa_fq), 0);
		if (!dpa_fq) {
			DPAWIFI_ERROR("%s::unable to alloc mem for dpa_fq\n", __FUNCTION__) ;
			return -1;
		}
		memset(dpa_fq, 0, sizeof(struct dpa_fq));
		memset(&opts, 0, sizeof(struct qm_mcc_initfq));
		fq = &dpa_fq->fq_base;
		dpa_fq_ptr = NULL;
		flags = 0;
		dpa_fq->net_dev = vap->wifi_dev;
		switch (ii) {
			case 1:
				//fwd fq
        			fq->cb.dqrr = vap_rx_fwd_pkt;
				dpa_fq_ptr = &vap->wlan_fq_from_fman;
				if (cdx_copy_eth_rx_channel_info(FMAN_IDX, dpa_fq)) {
               				DPAWIFI_ERROR("%s::unable to get cpu channel info\n", __FUNCTION__) ;
                			return -1;
				}
        			opts.fqd.fq_ctrl = (QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_HOLDACTIVE);
        			opts.fqd.context_a.stashing.exclusive =
                			(QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_ANNOTATION);
        			opts.fqd.context_a.stashing.data_cl = NUM_PKT_DATA_LINES_IN_CACHE;
        			opts.fqd.context_a.stashing.annotation_cl = NUM_ANN_LINES_IN_CACHE;
        			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
				break;
			case 2:
				//offline port fq
				flags |= QMAN_FQ_FLAG_TO_DCPORTAL;
        			opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
				dpa_fq_ptr = &vap->wlan_fq_to_fman;
				dpa_fq->channel = vap->channel;
				//contexta, b 
				//not working, using default Fqs
				opts.fqd.context_a.hi = 0x92000000; //OVFQ, A2V, OVOM
				opts.fqd.context_a.lo = 0;
				opts.fqd.context_b = vap->wlan_exception_fq->fqid;
#ifdef DPA_WIFI_DEBUG
               			DPAWIFI_INFO("%s::alt fq %x(%d)\n", __FUNCTION__, vap->wlan_exception_fq->fqid,
							vap->wlan_exception_fq->fqid);
#endif
        			dpa_fq->fq_type = FQ_TYPE_RX_PCD;
				break;
		}
		dpa_fq->wq = DEFA_WQ_ID;
        	dpa_fq->net_dev = vap->wifi_dev;
		if (!dpa_fq->fqid)
			flags |= QMAN_FQ_FLAG_DYNAMIC_FQID;
        	if (qman_create_fq(dpa_fq->fqid, flags, fq)) {
                	DPAWIFI_ERROR("%s::qman_create_fq failed for fqid %d\n",
                       		 __FUNCTION__, dpa_fq->fqid);
			kfree(dpa_fq);
                	return -1;
        	}

        	dpa_fq->fqid = fq->fqid;
        	opts.fqid = dpa_fq->fqid;
        	opts.count = 1;
        	opts.fqd.dest.channel = dpa_fq->channel;
        	opts.fqd.dest.wq = dpa_fq->wq;
        	opts.we_mask = (QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
                                QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_CONTEXTA);
        	if (qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts)) {
                	DPAWIFI_ERROR("%s::qman_init_fq failed for fqid %d\n",
                        	__FUNCTION__, dpa_fq->fqid);
                	qman_destroy_fq(fq, 0);
			kfree(dpa_fq);
                	return -1;
       	 	}	
#ifdef DPA_WIFI_DEBUG
        	DPAWIFI_INFO("%s::created fq %x(%d) for wlan packets "
			"channel 0x%x\n", __FUNCTION__,
                	dpa_fq->fqid, dpa_fq->fqid, dpa_fq->channel);
#endif
		*dpa_fq_ptr = dpa_fq;
	}
	return 0;
}

/* Destroys Frame Queues */
static void vwd_fq_destroy(struct qman_fq *fq)
{
        int _errno = 0;

        _errno = qman_retire_fq(fq, NULL);
        if (unlikely(_errno < 0)){
                DPAWIFI_ERROR("%s: Error in retire_fq: %u with error:%d\n", __FUNCTION__, qman_fq_fqid(fq), _errno);
	}

        _errno = qman_oos_fq(fq);
        if (unlikely(_errno < 0)) {
                DPAWIFI_ERROR("%s: Error in retire_fq: %u with error:%d\n", __FUNCTION__, qman_fq_fqid(fq), _errno);
        }

        qman_destroy_fq(fq, 0);
}


static int release_vap_fqs(struct vap_desc_s *vap)
{
	struct qman_fq* fq;
	struct dpa_fq* dpafq;
	int i;
	/* This WLAN exception FQ is used for all vwd interfaces */
	/* TODO - Need to modify to delete only for last interface, and add 
	for 1st interface */	
#ifdef DPA_WIFI_DEBUG
	printk(KERN_INFO "%s:: vwd count :%d\n", __func__, vap->vwd->expt_fq_count);
#endif
	if (vap->wlan_exception_fq)
	{
#ifdef DPA_WIFI_DEBUG
		printk(KERN_INFO "%s:: releasing expt fq :%d\n", __func__, vap->vwd->expt_fq_count);
#endif
		dpafq = vap->wlan_exception_fq;
		for (i = 0; i < vap->vwd->expt_fq_count; i++)
		{
			fq= &dpafq->fq_base;
			vwd_fq_destroy(fq);
			dpafq++;
		}
		kfree(vap->wlan_exception_fq);
		vap->wlan_exception_fq = NULL;
	}

	if (vap->wlan_fq_from_fman)
	{
#ifdef DPA_WIFI_DEBUG
		printk(KERN_INFO "%s:: releasing fq from fman :%d\n", __func__, vap->wlan_fq_from_fman->fqid);
#endif
		vwd_fq_destroy(&vap->wlan_fq_from_fman->fq_base);
		kfree(vap->wlan_fq_from_fman);
		vap->wlan_fq_from_fman = NULL;
	}
        if (vap->wlan_fq_to_fman)
        {
#ifdef DPA_WIFI_DEBUG
		printk(KERN_INFO "%s:: releasing fq to fman :%d\n", __func__, vap->wlan_fq_to_fman->fqid);
#endif
		vwd_fq_destroy(&vap->wlan_fq_to_fman->fq_base);
                kfree(vap->wlan_fq_to_fman);
                vap->wlan_fq_to_fman = NULL;
        }
	return 0;
}

int dpaa_get_vap_fwd_fq(uint16_t vap_id, uint32_t* fqid)
{
	*fqid = vwd.vaps[vap_id].wlan_fq_from_fman->fqid;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: fwd_fq :%x\n",__func__, *fqid);
#endif
	return 0;
}

int dpaa_get_wifi_ohport_handle( uint32_t* oh_handle)
{
	*oh_handle = vwd.oh_port_handle;
	return 0;
}
#if 0
//call under vaplock, retuenrs true if device is found
static int find_vapdev_by_name(char *devname, struct vap_desc_s **freedev)
{
	int retval;
	uint16_t ii;
	struct vap_desc_s *vapdev;
	struct vap_desc_s *freevapdev;

	vapdev = &vwd.vaps[0];
	freevapdev = NULL;
	retval = 0;
	for (ii = 0; ii < MAX_VAP_SUPPORT; ii++) {
		if (vapdev->state == VAP_ST_CLOSE) {
			if (!freevapdev) {
				freevapdev = vapdev;
				vapdev->vapid = ii;
				vapdev->vwd = &vwd;
			}
		} else {
			if (!strcmp(devname, vapdev->ifname)) {
				DPAWIFI_ERROR("%s::device %s already associated\n", 
					__FUNCTION__, devname);
				retval = 1;
				break;
			}
		}
		vapdev++;
	}
	if (freedev)
		*freedev = freevapdev;
	return retval;
}
#endif

//static int add_device_bpool(struct vap_desc_s *vap_dev)
static int add_device_bpool(struct dpaa_vwd_priv_s  *vwd)
{

	struct dpa_bp *bp, *bp_parent;
	int buffer_count = 0, ret = 0, refill_cnt ;


	bp = kzalloc(sizeof(struct dpa_bp), 0);
	if (unlikely(bp == NULL)) {
		DPAWIFI_ERROR("%s::failed to allocate mem for bman pool for dev %s\n",
				__FUNCTION__,vwd->name);
		return -1;
	}
	bp->size = VAPDEV_BUFSIZE;
	bp->config_count = VAPDEV_BUFCOUNT;
	if (get_phys_port_poolinfo_bysize(VAPDEV_BUFSIZE, &vwd->parent_pool_info)) {
		DPAWIFI_ERROR("%s::failed to locate eth bman pool for dev %s\n", __FUNCTION__, vwd->name);
		bman_free_pool(bp->pool);
		kfree(bp);
		return -1;
	}

	vwd->bp = bp;

	bp_parent = dpa_bpid2pool(vwd->parent_pool_info.pool_id);
	bp->dev = bp_parent->dev;

	if (dpa_bp_alloc(bp, bp->dev)) {
		DPAWIFI_ERROR("%s::dpa_bp_alloc failed for dev %s\n", __FUNCTION__,vwd->name);
		kfree(bp);
		return -1;
	}

	while (buffer_count < VAPDEV_BUFCOUNT)
	{
		refill_cnt = 0;
		ret = dpaa_eth_refill_bpools(bp, &refill_cnt);
		if (ret < 0)
		{
			DPAWIFI_ERROR("%s:: Error returned for dpaa_eth_refill_bpools %d\n", __FUNCTION__,ret);
			break;
		}

		buffer_count += refill_cnt;
	}
	bp->config_count = buffer_count;

	DPAWIFI_INFO("%s::buffers_allocated %d\n", __FUNCTION__,bp->config_count);
	return 0;
	
}

void drain_bp_pool(struct dpa_bp *bp)
{
        int ret, num = 8;

        do {
                struct bm_buffer bmb[8];
                int i;

                ret = bman_acquire(bp->pool, bmb, num, 0);
                if (ret < 0) {
                        if (num == 8) {
                                /* we have less than 8 buffers left;
                                 * drain them one by one
                                 */
                                num = 1;
                                ret = 1;
                                continue;
                        } else {
                                /* Pool is fully drained */
                                break;
                        }
                }

                for (i = 0; i < num; i++) {
                        dma_addr_t addr = bm_buf_addr(&bmb[i]);

                        dma_unmap_single(bp->dev, addr, bp->size,
                                        DMA_BIDIRECTIONAL);

                        _dpa_bp_free_pf(phys_to_virt(addr));
                }
        } while (ret > 0);
}

static int release_device_bpool(struct dpaa_vwd_priv_s  *vwd)
{
	if (!vwd->bp)
		return 0;

	drain_bp_pool(vwd->bp);
	vwd->bp = NULL;
	return 0;
}

static int vwd_vap_up(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
        struct net_device *wifi_dev;

	wifi_dev = dev_get_by_name(&init_net, cmd->ifname);
        if (!wifi_dev) {
        	DPAWIFI_ERROR("%s::No WiFi device %s\n", 
			__func__, &cmd->ifname[0]);
        	return -1;
        }
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:: wifidev found.. %s\n", __FUNCTION__, cmd->ifname);
#endif
        if (!(wifi_dev->flags & IFF_UP)) {
       		DPAWIFI_ERROR("%s::WiFi device %s not UP\n",
        		__FUNCTION__, &cmd->ifname[0]);
        	dev_put(wifi_dev);
        	return -1;
        }
#if 0
	//get free vap instance
        if (find_vapdev_by_name(&cmd->ifname[0], &vap)) {
		DPAWIFI_ERROR("%s::device %s already associated\n", 
			__FUNCTION__, &cmd->ifname[0]);
        	dev_put(wifi_dev);
        	return -1;
        }
	if (!vap) {
		DPAWIFI_ERROR("%s:: no free vap instance for device %s\n", 
			__FUNCTION__, &cmd->ifname[0]);
        	dev_put(wifi_dev);
        	return -1;
	}
#endif
	if (get_ofport_info(FMAN_IDX, priv->oh_port_handle, &vap->channel, 
			&vap->td[0])) 
	{
        	dev_put(wifi_dev);
		return -1;
	}

	vap->ifindex = cmd->ifindex;
        vap->direct_rx_path = cmd->direct_rx_path;
        vap->direct_tx_path = 0;
        memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
        vap->wifi_dev = wifi_dev;
	vap->vwd = priv;

	dev_put(wifi_dev);
	//create frame queues
	if (create_vap_fqs(vap)) {
		DPAWIFI_ERROR("%s::unable to create vap fqs for device %s\n", 
			__FUNCTION__, &cmd->ifname[0]);
		release_vap_fqs(vap);	
		return -1;
	}

	vap->state = VAP_ST_OPEN;
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: UP: name:%s, vapid:%d, direct_rx_path : %s, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
                        __func__, vap->ifname, vap->vapid,
                        vap->direct_rx_path ? "ON":"OFF", vap->ifindex,
                        vap->macaddr[0], vap->macaddr[1],
                        vap->macaddr[2], vap->macaddr[3],
                        vap->macaddr[4], vap->macaddr[5] );

#endif
	return 0;
}

int vwd_vap_down(struct dpaa_vwd_priv_s *priv , struct vap_desc_s *vap)
{
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s:%d\n", __func__, __LINE__);
        DPAWIFI_INFO("%s:DOWN: name:%s, vapid:%d, direct_rx_path : %s, ifindex:%d, mac:%x:%x:%x:%x:%x:%x\n",
                        __func__, vap->ifname, vap->vapid,
                        vap->direct_rx_path ? "ON":"OFF", vap->ifindex,
                        vap->macaddr[0], vap->macaddr[1],
                        vap->macaddr[2], vap->macaddr[3],
                        vap->macaddr[4], vap->macaddr[5] );
#endif
	
	release_vap_fqs(vap);

        vap->state = VAP_ST_CONFIGURED;
	vap->wifi_dev = NULL;
        priv->vap_count--;

	return 0;
}

/** vwd_vap_configure
 *
 */
static int vwd_vap_configure(struct dpaa_vwd_priv_s *priv, struct vap_desc_s *vap, struct vap_cmd_s *cmd)
{
	vap->vapid = cmd->vapid;
        vap->ifindex = cmd->ifindex;
        vap->direct_rx_path = cmd->direct_rx_path;
        vap->direct_tx_path = 0;
        memcpy(vap->ifname, cmd->ifname, 12);
        memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
	vap->cpu_id = -1;

	vap->state = VAP_ST_CONFIGURED;
        return 0;

}

/** dpaa_vwd_handle_vap
 *
 */
int dpaa_vwd_handle_vap( struct dpaa_vwd_priv_s *priv, struct vap_cmd_s *cmd )
{
        int rc = 0, ii;
	struct vap_desc_s *vap;

#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO( "%s function called %d: %s\n", __func__, cmd->action, cmd->ifname);
#endif

	if (cmd->vapid >= MAX_VAP_SUPPORT) {
		DPAWIFI_ERROR("%s : VAPID (%d)  >=  MAX_VAP_SUPPORT(%d)\n", __func__, cmd->vapid, MAX_VAP_SUPPORT);
		return -1;
	}

	vap = &priv->vaps[cmd->vapid];

	switch (cmd->action) {
		case CONFIGURE:
			DPAWIFI_INFO("%s: CONFIGURE ... %s\n", __func__, cmd->ifname);
                        if (vap->state != VAP_ST_CLOSE) {
                                DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not in close state\n",
                                                __func__, cmd->vapid, cmd->ifname);
                                rc = -1;
                                break;
                        }

			if (!(rc = vwd_vap_configure(priv, vap, cmd)))
			{
				DPAWIFI_INFO("%s: Configured VAP (id : %d  name : %s)\n", __func__, cmd->vapid, cmd->ifname);
			}
			else
			{
				DPAWIFI_ERROR("%s: Failed to configure VAP (id : %d  name : %s)\n",
						__func__, cmd->vapid, cmd->ifname);
			}
			break;


		case ADD:
			DPAWIFI_INFO("%s: ADD ... %s\n", __func__, cmd->ifname);
                        if (vap->state != VAP_ST_CONFIGURED) {
                                DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not configured \n",
                                                                 __func__, cmd->vapid, cmd->ifname);
                                rc = -1;
                                break;
                        }

			
			rc = vwd_vap_up(priv,vap,cmd);
			if (rc < 0)
			{
                                DPAWIFI_ERROR("%s : VAP (id : %d  name : %s) is not UP \n",
                                                                 __func__, cmd->vapid, cmd->ifname);
				rc = -1;
			}
			break;
		case REMOVE:
			DPAWIFI_INFO("%s: REMOVE ... %s\n", __func__, cmd->ifname);
                        if (vap->state != VAP_ST_OPEN) {
                                printk(KERN_ERR "%s : VAP (id : %d  name : %s) is not opened \n",
                                                                 __func__, cmd->vapid, cmd->ifname);
                                rc = -1;
                                break;
                        }
                        vwd_vap_down(priv, vap);

			break;
		case UPDATE:
			DPAWIFI_INFO(KERN_INFO "%s: UPDATE ... %s\n", __func__, cmd->ifname);
			vap->ifindex = cmd->ifindex;
			vap->direct_rx_path = cmd->direct_rx_path;
			memcpy(vap->macaddr, cmd->macaddr, ETH_ALEN);
			break;		
		case RESET:
			DPAWIFI_INFO(KERN_INFO "%s: RESET ...\n", __func__);
                        for (ii = 0; ii < MAX_VAP_SUPPORT; ii++) {
                                vap = &priv->vaps[ii];

                                if (vap->state == VAP_ST_CLOSE)
                                        continue;

                                if (vap->state == VAP_ST_OPEN)
                                        vwd_vap_down(priv, vap);
				if (vap->state == VAP_ST_CONFIGURED) {
					vap->state = VAP_ST_CLOSE;
				}
			}
			break;

		default:
			DPAWIFI_INFO("%s::unhandled cmd %d\n", __FUNCTION__, cmd->action);	
			rc = -1;
			break;
	}
	return rc;

}

/** vwd_open
 *
 */
static int dpaa_vwd_open(struct inode *inode, struct file *file)
{
#if 0
        //allow only one open instance
        if (!atomic_dec_and_test(&dpa_vwd_open_count)) {
                atomic_inc(&dpa_vwd_open_count);
                return -EBUSY;
        }
#endif
	int result = 0;
	unsigned dev_minor = iminor(inode);

#if defined (CONFIG_VWD_MULTI_MAC)
	printk( "%s :  Multi MAC mode enabled\n", __func__);
#endif
	printk( "%s :  minor device -> %d\n", __func__, dev_minor);
	if (dev_minor != 0)
	{
                printk(KERN_ERR ": trying to access unknown minor device -> %d\n", dev_minor);
                result = -ENODEV;
                goto out;
        }

        file->private_data = &vwd;

out:
        return result;

	return 0;
}

/** vwd_close
 *
 */
static int dpaa_vwd_close(struct inode * inode, struct file * file)
{
	DPAWIFI_INFO("%s TODO \n", __func__);
#if 0
        //TBD - recover resources here
        atomic_inc(&dpa_vwd_open_count);
#endif
	return 0;
}


#define SIOCVAPUPDATE  ( 0x6401 )

/**dpaa_vwd_ioctl
 *
 */
long dpaa_vwd_ioctl(struct file * file, unsigned int cmd, unsigned long arg)
{
	struct vap_cmd_s vap_cmd;
	void __user *argp = (void __user *)arg;
	int rc = -EOPNOTSUPP;
	struct dpaa_vwd_priv_s *priv = (struct dpaa_vwd_priv_s *)file->private_data;

	rtnl_lock();
	spin_lock_bh(&priv->vaplock);
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s vapcmd recvd:%x \n", __func__, cmd);
#endif
	switch(cmd) {
		case SIOCVAPUPDATE:
			if (copy_from_user(&vap_cmd, argp, sizeof(struct vap_cmd_s))) {
				rc = -EFAULT;
				goto done;
			}

			rc = dpaa_vwd_handle_vap(priv, &vap_cmd);
	}
	spin_unlock_bh(&priv->vaplock);
	rtnl_unlock();
done:
	return rc;
}

static int vwd_init_ohport(struct dpaa_vwd_priv_s *priv)
{

        /* Get OH port for this driver */
        priv->oh_port_handle = alloc_offline_port(FMAN_IDX, PORT_TYPE_WIFI, NULL, NULL);
        if (priv->oh_port_handle < 0)
        {
                DPAWIFI_ERROR("%s: Error in allocating OH port Channel\n", __func__);
		return -1;
        }
#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO("%s: allocated oh port %d\n", __func__, priv->oh_port_handle);
#endif
	return 0;
}

static int vwd_free_ohport(struct dpaa_vwd_priv_s *priv)
{

	int rc;
#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO("%s: releasing oh port %d\n", __func__, priv->oh_port_handle);
#endif
	rc = release_offline_port(FMAN_IDX, priv->oh_port_handle);
	if (rc < 0)
	{
                DPAWIFI_ERROR("%s: Error in releasing OH port Channel\n", __func__);
		return -1;
	}
	
        return 0;
}


/** dpaa_vwd_up
 *
 */
static int dpaa_vwd_up(struct dpaa_vwd_priv_s *priv )
{
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s::\n", __func__);
#endif
	nf_register_net_hook(&init_net,&vwd_hook);
        nf_register_net_hook(&init_net,&vwd_hook_ipv6);

        priv->fast_routing_enable = 1;
        priv->fast_path_enable = 1;
        priv->fast_bridging_enable = 0;

        if (dpaa_vwd_sysfs_init(priv))
                goto err0;


#if 0
       comcerto_wifi_rx_fastpath_register(vwd_wifi_if_send_pkt);

        if (vwd_ofld == PFE_VWD_NAS_MODE) {
                register_netdevice_notifier(&vwd_vap_notifier);
        }

        /* supported features */
        priv->vap_dev_hw_features =
                        NETIF_F_RXCSUM | NETIF_F_IP_CSUM |  NETIF_F_IPV6_CSUM |
                        NETIF_F_SG | NETIF_F_TSO;

        /* enabled by default */
        if (lro_mode) {
                priv->vap_dev_hw_features |= NETIF_F_LRO;
        }

        priv->vap_dev_features = priv->vap_dev_hw_features;
#endif

#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO("%s: End\n", __func__);
#endif
        return 0;

err0:
        nf_unregister_net_hook(&init_net,&vwd_hook);
        nf_unregister_net_hook(&init_net,&vwd_hook_ipv6);

        return -1;

}

/** dpaa_vwd_down
 *
 */
int dpaa_vwd_down( struct dpaa_vwd_priv_s *priv )
{
       int ii;

#ifdef DPA_WIFI_DEBUG
        DPAWIFI_INFO( "%s: %s\n", priv->name, __func__);
#endif

#if 0
        comcerto_wifi_rx_fastpath_unregister();
#endif
        if( priv->fast_bridging_enable )
        {
                nf_unregister_net_hook(&init_net,&vwd_hook_bridge);
        }

        if( priv->fast_routing_enable )
        {
                nf_unregister_net_hook(&init_net,&vwd_hook);
                nf_unregister_net_hook(&init_net,&vwd_hook_ipv6);
        }

        for (ii = 0; ii < MAX_VAP_SUPPORT; ii++)
        {
                struct vap_desc_s *vap = &priv->vaps[ii];
                struct net_device *wifi_dev = NULL;

                if (vap->state == VAP_ST_OPEN) {
                        vwd_vap_down(priv, vap);
                }

                if (vap->state == VAP_ST_CONFIGURED) {

                        wifi_dev = dev_get_by_name(&init_net, vap->ifname);

                        if (wifi_dev) {
#if 0
                                if (wifi_dev->wifi_offload_dev) {
                                        wifi_dev->ethtool_ops = vap->wifi_ethtool_ops;
                                        wifi_dev->wifi_offload_dev = NULL;
                                        wifi_dev->hw_features = vap->wifi_hw_features;
                                        wifi_dev->features = vap->wifi_features;
                                }
#endif
                                dev_put(wifi_dev);
                        }

#if 0
                        sysfs_remove_group(vap->vap_kobj, &vap_attr_group);
                        kobject_put(vap->vap_kobj);
                        dev_deactivate(vap->dev);
                        unregister_netdev(vap->dev);
                        free_netdev(vap->dev);
#endif
                        vap->state = VAP_ST_CLOSE;
                }
        }

#if 0
        if (vwd_ofld == PFE_VWD_NAS_MODE) {
                unregister_netdevice_notifier(&vwd_vap_notifier);
        }
#endif

        priv->vap_count = 0;
        dpaa_vwd_sysfs_exit();

	return 0;
}

/** dpaa_vwd_driver_init
 *
 *       DPAA wifi offload:
 *       -
 */

int dpaa_vwd_driver_init( struct dpaa_vwd_priv_s *priv )
{
	int rc;

	strcpy(priv->name, "vwd");
	spin_lock_init(&priv->vaplock);
	rc = dpaa_vwd_up(priv);
	return rc;
}

/** vwd_driver_remove
 *
 */
static int dpaa_vwd_driver_remove(void)
{
        struct dpaa_vwd_priv_s *priv = &vwd;
        dpaa_vwd_down(priv);
        return 0;
}


/**dpaa_vwd_init
 *
 */
int dpaa_vwd_init(void)
{
	struct dpaa_vwd_priv_s  *priv = &vwd;
	int rc = 0;

	memset(priv, 0, sizeof(*priv));

	priv->vwd_major = register_chrdev(0,"vwd",&vwd_fops);
	if (priv->vwd_major < 0)
	{
		DPAWIFI_ERROR("%s register_chrdev failed\n",__func__);
		goto err0;	
	}
#ifdef DPA_WIFI_DEBUG
	DPAWIFI_INFO("%s: created vwd device(%d, 0)\n", __func__, priv->vwd_major );
#endif
	priv->vwd_class = class_create(THIS_MODULE, "vwd");
	if (priv->vwd_class == NULL)
	{
		DPAWIFI_ERROR("%s class_create failed\n",__func__);
		goto err1;	
	}

	priv->vwd_device = device_create(priv->vwd_class, NULL, MKDEV(priv->vwd_major,0), NULL, "vwd0");
        if (priv->vwd_device == NULL)
	{
		DPAWIFI_ERROR("%s class_create failed\n",__func__);
		goto err2;	
	}

	if( dpaa_vwd_driver_init( priv ) )
	{
		DPAWIFI_ERROR("%s dpaa_vwd_driver_init failed\n",__func__);
		goto err3;
	}

        rc = vwd_init_ohport(priv);
        if (rc < 0)
        {
        	DPAWIFI_ERROR("%s: vwd_init_ohport failed\n",__func__);
                goto err4;
        }


	//vaptest_init();
	vwd.eth_priv = get_eth_priv("eth0");
	if (!vwd.eth_priv)
        {
        	DPAWIFI_ERROR("%s: eth_priv failed\n",__func__);
		goto err5;
        }

	if (add_device_bpool(priv))
        {
                DPAWIFI_ERROR("%s::unable to create  device bpool %s\n", __FUNCTION__, priv->name);
                goto err6;
        }
	DPAWIFI_INFO("%s: INIT successful\n", __func__ );

	return rc;

err6: 
	vwd.eth_priv = NULL;
err5:
	release_offline_port(FMAN_IDX, priv->oh_port_handle);
err4: 
	dpaa_vwd_driver_remove();
err3:
	device_destroy(priv->vwd_class, MKDEV(priv->vwd_major, VWD_MINOR));
	priv->vwd_device = NULL;
err2:
	class_destroy(priv->vwd_class);
	priv->vwd_class = NULL;
err1:
	unregister_chrdev(priv->vwd_major, "vwd");
	priv->vwd_major = 0;
err0:
	return -1;
}


/** dpaa_vwd_exit
 *
 */
void dpaa_vwd_exit(void)
{
	struct dpaa_vwd_priv_s  *priv = &vwd;

	release_device_bpool(priv);
	priv->eth_priv = NULL;
	/* Release OH port here */
	vwd_free_ohport(priv);	
	//TODO ensure all vaps are down
	dpaa_vwd_driver_remove();
	device_destroy(priv->vwd_class, MKDEV(priv->vwd_major, VWD_MINOR));
	unregister_chrdev(priv->vwd_major, "vwd");
	class_destroy(priv->vwd_class);

}

#else /* !CFG_WIFI_OFFLOAD */

/** pfe_vwd_init
 *
 */
int pfe_vwd_init(struct pfe *pfe)
{
        printk(KERN_INFO "%s\n", __func__);
        return 0;
}

/** pfe_vwd_exit
 *
 */
void pfe_vwd_exit(struct pfe *pfe)
{
        printk(KERN_INFO "%s\n", __func__);
}

#endif /* !CFG_WIFI_OFFLOAD */

