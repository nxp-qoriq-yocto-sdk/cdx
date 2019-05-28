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
 * @file                dpa_test.c     
 * @description         test code to add connections
 */

#include <linux/device.h>
#include "linux/ioctl.h"
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fdtable.h>

#include "portdefs.h"
#include "misc.h"
#include "cdx_ioctl.h"
#include "lnxwrp_fm.h"
#include "layer2.h"
#include "cdx.h"
#include "control_ipv4.h"
#include "cdx_ceetm_app.h"
#include "dpa_control_mc.h"

//#define DPA_TEST_DEBUG 1

#define EGRESS_PORTNAME_LEN	32
enum flow_id
{
	FWD_FLOW_IDENTIFIER,
	REV_FLOW_IDENTIFIER,
	MAX_IDENTIFIERS
};


extern int insert_entry_in_classif_table(PCtEntry entry);
int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index , 
			uint32_t *fm_index, uint32_t *port_index, uint32_t *portid);


void cdx_ceetm_init(void);
unsigned int lfqid1, lfqid2;
int cdx_ioc_dpa_configqos(unsigned long args)
{
  struct QoSConfig_Info qos_params;
  cdx_ceetm_lni_ctxt_t *pLNI_ctxt;
  cdx_ceetm_channel_ctxt_t *pChannelCtxt;
  cdx_ceetm_queue_ctxt_t *pQueueCtxt;
  cdx_ceetm_ccg_in_params_t ccg_params;
//  char port_name[EGRESS_PORTNAME_LEN];
  int ret_val, ii;
  unsigned int uiNoOfSchedulers;
  POnifDesc onif_desc;
 
  cdx_ceetm_init();
  return 0;
  ret_val =  0;
  if (copy_from_user(&qos_params, (void *)args,
                        sizeof(struct QoSConfig_Info))) 
  {
                DPA_ERROR("%s::Read uspace args failed\n", __FUNCTION__);
                return -EBUSY;
  }

  pLNI_ctxt = (cdx_ceetm_lni_ctxt_t *) 
	kzalloc ((sizeof(cdx_ceetm_lni_ctxt_t)),0);
  if (!pLNI_ctxt)
  {
    DPA_ERROR("%s::mem alloc for conn info failed\n", 
			__FUNCTION__);
	ret_val = -ENOMEM;	
	goto err_ret;
  }

  if(qos_params.uiCIR)
    pLNI_ctxt->shaper.shaping_en = 1;
  else
    pLNI_ctxt->shaper.shaping_en = 0;
    
  pLNI_ctxt->shaper.rate = qos_params.uiCIR ;
  pLNI_ctxt->shaper.ceil = qos_params.uiEIR ;
  pLNI_ctxt->shaper.mpu = 64 ;
  pLNI_ctxt->shaper.token_limit = qos_params.uiCBS ;
  pLNI_ctxt->shaper.overhead = 0 ;

  onif_desc = get_onif_by_name(qos_params.If_info); 
  if (!onif_desc)
  {
    DPA_ERROR("%s::unable to get onif for iface %s\n",
                       __FUNCTION__, qos_params.If_info);
    ret_val = -EIO;
    goto err_ret;
  }

  if(dpa_get_fm_port_index(onif_desc->itf->index, 0,
                       &pLNI_ctxt->fman_id, &pLNI_ctxt->port_id, NULL))
  {
    DPA_ERROR("%s::unable to get fmindex for itfid %d\n",
                        	__FUNCTION__, onif_desc->itf->index);
    ret_val = -EIO;
    goto err_ret;
  }
  
  ceetm_cfg_lni( pLNI_ctxt->fman_id,pLNI_ctxt->port_id, pLNI_ctxt->port_type, &pLNI_ctxt->shaper, (void*)(&(pLNI_ctxt->lni)));
  if(pLNI_ctxt->lni == NULL)
  {
    DPA_ERROR("CEETM: Configuring LNI failed \r\n");
    ret_val = -1;
  }
  uiNoOfSchedulers = qos_params.uiNoOfSchedulers;
  while(uiNoOfSchedulers)
  {
    pChannelCtxt = (cdx_ceetm_channel_ctxt_t *) 
 	kzalloc ((sizeof(cdx_ceetm_channel_ctxt_t)),0);
    if (!pChannelCtxt)
    {
      DPA_ERROR("%s::mem alloc for Channel Context failed\n", 
   			__FUNCTION__);
      ret_val = -ENOMEM;	
      goto err_ret;
    }

    pChannelCtxt->params.shaping_en = 1;
    pChannelCtxt->params.shaper.rate = qos_params.uiCIR/qos_params.uiNoOfSchedulers;
    pChannelCtxt->params.shaper.ceil = qos_params.uiEIR/qos_params.uiNoOfSchedulers;
    pChannelCtxt->params.shaper.token_limit = qos_params.uiCBS;

    ceetm_cfg_channel(pLNI_ctxt->lni, &pChannelCtxt->params, (void *)(&pChannelCtxt->pChannel));
    if(pChannelCtxt->pChannel == NULL)
    {
      DPA_ERROR("%s::%d configuring channel failed \r\n", 
  			__FUNCTION__, __LINE__);
	ret_val = -1;	
	goto err_ret;
    }
    pLNI_ctxt->pChannels[pLNI_ctxt->uiNoOfChannels++] = pChannelCtxt;
  

    for(ii=0; ii < qos_params.uiNoOfQueues; ii++) // configuring only strict prio queues
    {
      ccg_params.cong_avoid_alg = QOS_CEETM_TAIL_DROP;
      ccg_params.tail_drop.threshold = 100;
      ret_val = ceetm_cfg_ccg_to_class_queue(pChannelCtxt->pChannel, ii, &ccg_params);
      if(ret_val)
      {
        DPA_ERROR("%s %d :: ceetm_cfg_ccg_to_class_queue failed \r\n", __FUNCTION__, __LINE__);
      }

      pQueueCtxt = (cdx_ceetm_queue_ctxt_t *) 
         	kzalloc ((sizeof(cdx_ceetm_queue_ctxt_t)),0);
      if (!pQueueCtxt)
      {
        DPA_ERROR("%s::mem alloc for Queue context failed\n", 
        			__FUNCTION__);
        ret_val = -ENOMEM;	
        goto err_ret;
      }

      pQueueCtxt->idx = ii;
      pQueueCtxt->prio.params.cr_eligible = 1;
      pQueueCtxt->prio.params.er_eligible = 1;
      ceetm_cfg_prio_class_queue((void*)(pChannelCtxt->pChannel), pQueueCtxt);
      if((pQueueCtxt->cq == NULL) || (pQueueCtxt->fq == NULL))
      {
        DPA_ERROR("%s::%d Configuring Prio class queue failed \r\n", 
        			__FUNCTION__, __LINE__);
        ret_val = -1;	
        goto err_ret;
      }
      pChannelCtxt->pQueues[ii] = pQueueCtxt;
    }
    uiNoOfSchedulers--;
  }
  lfqid1 = pLNI_ctxt->pChannels[0]->pQueues[0]->fq->recycle_fq.fqid; 
  lfqid2 = pLNI_ctxt->pChannels[0]->pQueues[1]->fq->recycle_fq.fqid; 
  printk("%s::%d lfq created with ids %d,%d \r\n", __FUNCTION__,__LINE__,lfqid1, lfqid2);
  return 0;

err_ret:
return ret_val;

}
extern int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index , 
			uint32_t *fm_index, uint32_t *port_index, uint32_t *portid);
extern void *dpa_get_pcdhandle(uint32_t fm_index);
extern int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
	struct dpa_l3hdr_info *l3_info, PRouteEntry tnl_rt_entry, uint32_t queue_no);
#ifndef USE_ENHANCED_EHASH
extern int create_hm_chain_for_mcast_member(RouteEntry *pRtEntry, struct ins_entry_info *pInsEntry,
             struct hm_chain_info **pphm_info, int mtu,
                 char*pInIface, int IsFirstMem,  int bIsIPv6);
extern int insert_mcast_entry_in_classif_table(struct _tCtEntry *pCtEntry, int mc_grpid);
#else
extern int insert_mcast_entry_in_classif_table(struct _tCtEntry *pCtEntry, 
						unsigned int num_members, uint64_t first_member_flow_addr,
						void *first_listener_entry);
#endif // USE_ENHANCED_EHASH
int mcast_grpd;
extern  struct list_head mc4_grp_list[MC4_NUM_HASH_ENTRIES];
extern  struct list_head mc6_grp_list[MC6_NUM_HASH_ENTRIES];

int cdx_ioc_create_mc_group(unsigned long args)
{
#ifndef USE_ENHANCED_EHASH
  struct add_mc_group_info mcast_group;
  struct dpa_cls_mcast_group_params *pMcastGrp;
  struct dpa_cls_mcast_group_resources *pMcastGrpRsrcs = NULL;
  POnifDesc onif_desc;
  int fm_idx, port_idx;
  RouteEntry *pRtEntry;
  struct dpa_l2hdr_info *pL2Info;
  struct dpa_l3hdr_info *pL3Info;
  int iRet;
  struct ins_entry_info *pInsEntryInfo;
  struct mcast_group_info *pMcastGrpInfo;
  int ii;
  struct hm_chain_info *hm_info;
  struct net_device *dev;
  printk("%s::%d Trying to create mcast group \r\n", __FUNCTION__, __LINE__);
  return 0;

  pMcastGrp = NULL;
  pInsEntryInfo = NULL;
  pRtEntry = NULL;
 
    
  if(copy_from_user(&mcast_group, (void *)args, sizeof(struct add_mc_group_info)))
  {
    DPA_ERROR("%s::%d read uspace args failed \r\n", __FUNCTION__, __LINE__);
    return -EBUSY;
  }

  pMcastGrpInfo = (struct mcast_group_info *)kzalloc((sizeof(struct mcast_group_info)), 0);
  if(!pMcastGrpInfo)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    return -ENOMEM;
  }
  
  INIT_LIST_HEAD(&pMcastGrpInfo->list); 
  pMcastGrpInfo->mctype = mcast_group.mctype;
  if(mcast_group.mctype == 0)
  {
    pMcastGrpInfo->ipv4_saddr = mcast_group.ipv4_saddr;
    pMcastGrpInfo->ipv4_daddr = mcast_group.ipv4_daddr;
  }
  else
  {
    for(ii=0;ii<16;ii++)
    {
      pMcastGrpInfo->ipv6_saddr[ii] = mcast_group.ipv6_saddr[ii];
      pMcastGrpInfo->ipv6_daddr[ii] = mcast_group.ipv6_daddr[ii];
    }
  }
  
  if((iRet = GetMcastGrpId(pMcastGrpInfo))!= -1)
  {
    printk("%s::%d multicast group already exists \r\n", __FUNCTION__, __LINE__);
    iRet = -1;
    goto err_ret;
  }

  pMcastGrp = (struct dpa_cls_mcast_group_params *)kzalloc((sizeof(struct dpa_cls_mcast_group_params)), 0);
  if(!pMcastGrp)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    iRet = -ENOMEM;
    goto err_ret;
  }

  pMcastGrp->max_members = mcast_group.uiMaxMembers;
  printk("%s::%d  Multicast group max members =%d  \r\n", __FUNCTION__, __LINE__, pMcastGrp->max_members);
  

  onif_desc = get_onif_by_name(&mcast_group.ucListenerPort[0]); 
  if (!onif_desc)
  {
    DPA_ERROR("%s::unable to get onif for iface %s\n", __FUNCTION__, &mcast_group.ucListenerPort[0]);
    iRet = -EIO;
    goto err_ret;
  }

  if(dpa_get_fm_port_index(onif_desc->itf->index,0, &fm_idx, &port_idx, NULL))
  {
    DPA_ERROR("%s::unable to get fmindex for itfid %d\n",__FUNCTION__, onif_desc->itf->index);
    iRet = -EIO;
    goto err_ret;
  }

  pMcastGrp->fm_pcd = dpa_get_pcdhandle(fm_idx);
  if (!pMcastGrp->fm_pcd)
  {
    DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",__FUNCTION__, fm_idx);
    iRet = -EIO;
    goto err_ret;
  }	
  
  pMcastGrp->prefilled_members = 0;

  //Code to create hm for mcast single member
  pInsEntryInfo = (struct ins_entry_info*)kzalloc((sizeof(struct ins_entry_info)), 0);
  if(!pInsEntryInfo)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    iRet = -ENOMEM;
    goto err_ret;
  }

  pInsEntryInfo->fm_pcd = pMcastGrp->fm_pcd;
  pInsEntryInfo->fm_idx = fm_idx;
  pInsEntryInfo->port_idx = port_idx;
  pL2Info = &pInsEntryInfo->l2_info;
  pL3Info = &pInsEntryInfo->l3_info;
  //Code to create hm for mcast single member

  //Code to get Tx fqid of given interface

  pRtEntry = kzalloc((sizeof(RouteEntry)), 0);
  if (!pRtEntry)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    iRet = -ENOMEM;
    goto err_ret;
  }

  pRtEntry->itf = onif_desc->itf;
//strcpy(&pRtEntry->input_interface[0], &mcast_group.ucListenerPort[0]);
  pRtEntry->input_itf = onif_desc->itf;

  if (dpa_get_tx_info_by_itf(pRtEntry, pL2Info,pL3Info, NULL, 1))
  {
    DPA_ERROR("%s::unable to get tx params\n",__FUNCTION__);
    iRet = -EIO;
    goto err_ret;
  }

  pMcastGrp->first_member_params.override_fqid = 1;
  pMcastGrp->first_member_params.new_fqid = pL2Info->fqid;
  pMcastGrp->first_member_params.hmd = DPA_OFFLD_DESC_NONE;

  dev = dev_get_by_name(&init_net, &mcast_group.ucListenerPort[0]);
  if(dev == NULL)
  {
    iRet = -1;
    goto err_ret;
  }
  //End of code to get tx fqid

  //Code to create hm for mcast single member
  if((iRet = create_hm_chain_for_mcast_member(pRtEntry, pInsEntryInfo, &hm_info, dev->mtu,
            mcast_group.ucListenerPort,1,mcast_group.mctype ))!= 0)
  {
    DPA_ERROR("%s::failed to create hm chain for member of mcast group\n",__FUNCTION__);
    goto err_ret;
  }
  pMcastGrp->first_member_params.hmd = pInsEntryInfo->action.enq_params.hmd;
  //Code to create hm for mcast single member

  iRet = dpa_classif_mcast_create_group(pMcastGrp, &mcast_grpd, pMcastGrpRsrcs);
  if(iRet !=0)
  {
    printk("%s::%d mcast create group failed with error:%d \r\n", __FUNCTION__, __LINE__,iRet);
    goto err_ret;
  }
  
  pMcastGrpInfo->grpid = mcast_grpd;
  AddToMcastGrpList(pMcastGrpInfo);
  
  printk("%s::%d mcast group created with group id :%d \r\n", __FUNCTION__, __LINE__,mcast_grpd);
  
err_ret:
         if(pMcastGrpInfo && iRet != 0)
         {
           kfree(pMcastGrpInfo);
         }
         if(pMcastGrp)
         {
           kfree(pMcastGrp);
         }
         if(pRtEntry)
         {
           kfree(pRtEntry);
         }
         if(pInsEntryInfo)
         {
           kfree(pInsEntryInfo);
         }
  return iRet;
#else
	printk("%s::not implemented\n", __FUNCTION__);
	return -1;
#endif
}


int cdx_ioc_add_member_to_group(unsigned long args)
{
#ifndef USE_ENHANCED_EHASH
  struct add_mc_group_info mcast_group;
  struct dpa_cls_tbl_enq_action_desc  *pEnqActDesc;
  int member_id;
  POnifDesc onif_desc;
  int fm_idx, port_idx;
  RouteEntry *pRtEntry;
  struct dpa_l2hdr_info *pL2Info;
  struct dpa_l3hdr_info *pL3Info;
  int iRet, ii, mc_grpid;
  struct ins_entry_info *pInsEntryInfo;
  struct mcast_group_info *pMcastGrpInfo;
  struct hm_chain_info *hm_info;
  struct net_device *dev;

  return 0;

  pEnqActDesc = NULL;
  pInsEntryInfo = NULL;
  pRtEntry = NULL;
  
  printk("%s::%d Trying to add member to mcast group \r\n", __FUNCTION__, __LINE__);

  if(copy_from_user(&mcast_group, (void *)args, sizeof(struct add_mc_group_info)))
  {
    DPA_ERROR("%s::%d read uspace args failed \r\n", __FUNCTION__, __LINE__);
    return -EBUSY;
  }

#if 1
  pMcastGrpInfo = (struct mcast_group_info *)kzalloc((sizeof(struct mcast_group_info)), 0);
  if(!pMcastGrpInfo)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    return -ENOMEM;
  }
  
  pMcastGrpInfo->mctype = mcast_group.mctype;
  if(mcast_group.mctype == 0)
  {
    pMcastGrpInfo->ipv4_saddr = mcast_group.ipv4_saddr;
    pMcastGrpInfo->ipv4_daddr = mcast_group.ipv4_daddr;
  }
  else
  {
    for(ii=0;ii<16;ii++)
    {
      pMcastGrpInfo->ipv6_saddr[ii] = mcast_group.ipv6_saddr[ii];
      pMcastGrpInfo->ipv6_daddr[ii] = mcast_group.ipv6_daddr[ii];
    }
  }
  
  INIT_LIST_HEAD(&pMcastGrpInfo->list); 
  mc_grpid = GetMcastGrpId(pMcastGrpInfo);
  if(mc_grpid == -1)
  {
    printk("%s::%d multicast group is not created \r\n", __FUNCTION__, __LINE__);
    iRet = -1;
    goto err_ret;
  }
#endif

  //strcpy(&pRtEntry->input_interface[0],&mc_entry_info.ucIngressPort[0]);

  pEnqActDesc = (struct dpa_cls_tbl_enq_action_desc *)kzalloc((sizeof(struct dpa_cls_tbl_enq_action_desc)), 0);
  if(!pEnqActDesc)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    iRet = -ENOMEM;
    goto err_ret;
  }

  onif_desc = get_onif_by_name(&mcast_group.ucListenerPort[0]); 
  if (!onif_desc)
  {
    DPA_ERROR("%s::unable to get onif for iface %s\n", __FUNCTION__, &mcast_group.ucListenerPort[0]);
    iRet = -EIO;
    goto err_ret;
  }

  if(dpa_get_fm_port_index(onif_desc->itf->index,0, &fm_idx, &port_idx, NULL))
  {
    DPA_ERROR("%s::unable to get fmindex for itfid %d\n",__FUNCTION__, onif_desc->itf->index);
    iRet = -EIO;
    goto err_ret;
  }

  pInsEntryInfo = (struct ins_entry_info*)kzalloc((sizeof(struct ins_entry_info)), 0);
  if(!pInsEntryInfo)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    iRet = -ENOMEM;
    goto err_ret;
  }

  pInsEntryInfo->fm_pcd = dpa_get_pcdhandle(fm_idx);
  if (!pInsEntryInfo->fm_pcd)
  {
    DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",__FUNCTION__, fm_idx);
    iRet = -EIO;
    goto err_ret;
  }	
  pInsEntryInfo->fm_idx = fm_idx;
  pInsEntryInfo->port_idx = port_idx;
  dev = dev_get_by_name(&init_net, &mcast_group.ucListenerPort[0]);
  if(dev ==NULL)
  {
    iRet = -1;
    goto err_ret;
  }
  //Code to get Tx fqid of given interface

  pRtEntry = kzalloc((sizeof(RouteEntry)), 0);
  if (!pRtEntry)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    iRet = -ENOMEM;
    goto err_ret;
  }

  pL2Info = &pInsEntryInfo->l2_info;
  pL3Info = &pInsEntryInfo->l3_info;

  pRtEntry->itf = onif_desc->itf;
//strcpy(&pRtEntry->input_interface[0], &mcast_group.ucListenerPort[0]);
  pRtEntry->input_itf = onif_desc->itf;

  if (dpa_get_tx_info_by_itf(pRtEntry, pL2Info, pL3Info, NULL, 1))
  {
    DPA_ERROR("%s::unable to get tx params\n",__FUNCTION__);
    iRet  = -EIO;
    goto err_ret;
  }

  if(create_hm_chain_for_mcast_member(pRtEntry, pInsEntryInfo,
                 &hm_info,dev->mtu,mcast_group.ucListenerPort, 0, mcast_group.mctype))
  {
    DPA_ERROR("%s::failed to create hm chain for member of mcast group\n",__FUNCTION__);
    iRet = -EIO;
    goto err_ret;
  }

  pEnqActDesc->override_fqid = 1;
  pEnqActDesc->new_fqid = pL2Info->fqid;
  pEnqActDesc->hmd = pInsEntryInfo->action.enq_params.hmd;

  //End of code to get tx fqid

  iRet = dpa_classif_mcast_add_member(mc_grpid, pEnqActDesc, &member_id);
  if(iRet !=0)
  {
    printk("%s::%d adding member to mcast group mcast_group:%d  failed with error:%d \r\n", __FUNCTION__, __LINE__,mc_grpid, iRet);
    goto err_ret;
  }
  printk("%s::%d added member:%d to mcast group :%d \r\n", __FUNCTION__, __LINE__, member_id, mc_grpid);
  
err_ret:
        if(pMcastGrpInfo)
        {
          kfree(pMcastGrpInfo);
        }
        if(pEnqActDesc)
        {
          kfree(pEnqActDesc);
        }
        if(pInsEntryInfo)
        {
          kfree(pInsEntryInfo);
        }
        if(pRtEntry)
        {
          kfree(pRtEntry);
        }
  return iRet;
#else
	printk("%s::not implemented\n", __FUNCTION__);
	return -1;
#endif
}

int cdx_ioc_add_mcast_table_entry(unsigned long args)
{
#ifndef USE_ENHANCED_EHASH
  struct add_mc_entry_info mc_entry_info;
  RouteEntry *pRtEntry;
  POnifDesc onif_desc;
  struct _tCtEntry *pCtEntry;
  int retval, i;
  char *ipv6_saddr, *ipv6_daddr;
  struct mcast_group_info *pMcastGrpInfo;
  int mc_grpid, ii;

  return 0;

  pRtEntry = NULL;
  pCtEntry = NULL;

  if(copy_from_user(&mc_entry_info, (void *)args, sizeof(struct add_mc_entry_info)))
  {
    DPA_ERROR("%s::%d read uspace args failed \r\n", __FUNCTION__, __LINE__);
    return -EBUSY;
  }

#if 1
  pMcastGrpInfo = (struct mcast_group_info *)kzalloc((sizeof(struct mcast_group_info)), 0);
  if(!pMcastGrpInfo)
  {
    printk("%s::%d  failed to allocate memory \r\n", __FUNCTION__, __LINE__);
    return -ENOMEM;
  }
  
  pMcastGrpInfo->mctype = mc_entry_info.mctype;
  if(mc_entry_info.mctype == 0)
  {
    pMcastGrpInfo->ipv4_saddr = mc_entry_info.ipv4_saddr;
    pMcastGrpInfo->ipv4_daddr = mc_entry_info.ipv4_daddr;
  }
  else
  {
    for(ii=0;ii<16;ii++)
    {
      pMcastGrpInfo->ipv6_saddr[ii] = mc_entry_info.ipv6_saddr[ii];
      pMcastGrpInfo->ipv6_daddr[ii] = mc_entry_info.ipv6_daddr[ii];
    }
  }
   
  mc_grpid = GetMcastGrpId(pMcastGrpInfo); 
  if(mc_grpid == -1)
  {
    printk("%s::%d multicast group record not created \r\n", __FUNCTION__, __LINE__);
    retval = -1;
    goto err_ret;
  }
#endif
  pRtEntry = kzalloc((sizeof(RouteEntry)), 0);
  if (!pRtEntry)
  {
    return -ENOMEM;	
  }

  pCtEntry = kzalloc((sizeof(struct _tCtEntry)), 0);
  if (!pCtEntry)
  {
    retval = -ENOMEM;	
    goto err_ret;
  }

  pCtEntry->proto = IPPROTOCOL_UDP;
  /** proto is UDP for any mutlicast packet **/

  pCtEntry->Sport = 0;
  pCtEntry->Dport = 0;
  /** port fields should be masked in match key**/

  if(mc_entry_info.mctype == 0)
  {
    pCtEntry->Saddr_v4 = htonl(mc_entry_info.ipv4_saddr);
    pCtEntry->Daddr_v4 = htonl(mc_entry_info.ipv4_daddr);
    pCtEntry->fftype = FFTYPE_IPV4;
  }
  else
  {
    ipv6_saddr = (char *)&pCtEntry->Saddr_v6[0];
    ipv6_daddr = (char *)&pCtEntry->Daddr_v6[0];
    for (i = 0; i < 16; i++)
    {
      ipv6_saddr[i] = mc_entry_info.ipv6_saddr[i];
      ipv6_daddr[i] = mc_entry_info.ipv6_daddr[i];
    }
    pCtEntry->fftype = FFTYPE_IPV4;
  }

  onif_desc = get_onif_by_name(&mc_entry_info.ucIngressPort[0]); 
  if (!onif_desc)
  {
    DPA_ERROR("%s::unable to get onif for iface %s\n",__FUNCTION__, &mc_entry_info.ucIngressPort[0]);
    retval = -EIO;
    goto err_ret;
  }

  pRtEntry->itf = onif_desc->itf;
//strcpy(&pRtEntry->input_interface[0],&mc_entry_info.ucIngressPort[0]);
  pRtEntry->input_itf = onif_desc->itf;
  pCtEntry->pRtEntry = pRtEntry;
  retval = insert_mcast_entry_in_classif_table(pCtEntry, mc_grpid);

err_ret:
        if(pMcastGrpInfo)
        {
          kfree(pMcastGrpInfo);
        }
	if (pRtEntry)
        {
          kfree(pRtEntry);
        }
        if(pCtEntry)
        {
          kfree(pCtEntry);
        }
	return retval;
#else
	return -1;
#endif // USE_ENHANCED_EHASH
}

int cdx_ioc_dpa_connadd(unsigned long args)
{
        struct add_conn_info add_conn;
        int retval;
        uint32_t ii;
		struct test_conn_info *conn_info;
		struct _tCtEntry *ct;
		RouteEntry *rt;
		struct _tCtEntry *ct_entry;
		RouteEntry *rt_entry;

        if (copy_from_user(&add_conn, (void *)args,
                        sizeof(struct add_conn_info))) {
                DPA_ERROR("%s::Read uspace args failed\n", __FUNCTION__);
                return -EBUSY;
        }
        retval = 0;
	ct = NULL;
	rt = NULL;
	conn_info = (struct test_conn_info *) 
		kzalloc ((sizeof(struct test_conn_info) * add_conn.num_conn),
			0);
	if (!conn_info) {
        	DPA_ERROR("%s::mem alloc for conn info failed\n", 
			__FUNCTION__);
		retval = -ENOMEM;	
		goto err_ret;
		
	}
	if (copy_from_user(conn_info, add_conn.conn_info,
                        (sizeof(struct test_conn_info) * add_conn.num_conn))) {
                DPA_ERROR("%s::Read uspace args failed\n",
                        __FUNCTION__);
                retval = -EIO;
                goto err_ret;
        }
	ct = kzalloc((sizeof(struct _tCtEntry) * 2), 0);
	if (!ct) {
		retval = -ENOMEM;	
                goto err_ret;
	}
	rt = kzalloc((sizeof(RouteEntry) * 2), 0);
	if (!rt) {
		retval = -ENOMEM;	
        	goto err_ret;
	}
#ifdef DPA_TEST_DEBUG
	DPA_INFO("%s::adding %d connections\n", __FUNCTION__, add_conn.num_conn);
#endif
	for (ii = 0; ii < add_conn.num_conn; ii++) {
		char port_name[EGRESS_PORTNAME_LEN];
		POnifDesc onif_desc;
		uint32_t nat_op;

		if ((conn_info->fwd_flow.sport != conn_info->rev_flow.dport) ||
		    (conn_info->fwd_flow.dport != conn_info->rev_flow.sport) ||
		    (conn_info->fwd_flow.ipv4_saddr != 
				conn_info->rev_flow.ipv4_daddr) ||
		    (conn_info->fwd_flow.ipv4_daddr != 
				conn_info->rev_flow.ipv4_saddr))
			nat_op = CONNTRACK_NAT;
		else
			nat_op = 0;

		ct_entry = ct;
		rt_entry = rt;

		//fill fwd flow entry
		ct_entry->status = 
				(conn_info->flags | CONNTRACK_ORIG);
		
		ct_entry->proto = conn_info->proto;
		ct_entry->Sport = htons(conn_info->fwd_flow.sport);
		ct_entry->Dport = htons(conn_info->fwd_flow.dport);
		ct_entry->Saddr_v4 = htonl(conn_info->fwd_flow.ipv4_saddr);
		ct_entry->Daddr_v4 = htonl(conn_info->fwd_flow.ipv4_daddr);
		ct_entry->twin = (ct_entry + 1);
		ct_entry->twin_Sport = htons(conn_info->rev_flow.sport);
		ct_entry->twin_Dport = htons(conn_info->rev_flow.dport);
		ct_entry->twin_Saddr = htonl(conn_info->rev_flow.ipv4_saddr);
		ct_entry[FWD_FLOW_IDENTIFIER].twin_Daddr = 						htonl(conn_info->rev_flow.ipv4_daddr);
		ct_entry->pRtEntry = rt_entry;
		memcpy(&rt_entry->dstmac[0], conn_info->fwd_flow.dest_mac, 
			ETHER_ADDR_LEN);
		rt_entry->mtu = conn_info->fwd_flow.mtu;
		retval = strncpy_from_user(&port_name[0],
                        conn_info->fwd_flow.egress_port, EGRESS_PORTNAME_LEN);
                if (retval == -EFAULT) {
                        DPA_ERROR("%s::unable to read fwd flow egress port\n",
                                __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
                }
		onif_desc = get_onif_by_name(&port_name[0]); 
		if (!onif_desc) {
                        DPA_ERROR("%s::unable to get onif for iface %s\n",
                                __FUNCTION__, &port_name[0]);
                        retval = -EIO;
                        goto err_ret;
		}
		rt_entry->itf = onif_desc->itf;
		retval = strncpy_from_user(&port_name[0],
                        conn_info->fwd_flow.ingress_port, EGRESS_PORTNAME_LEN);
                if (retval == -EFAULT) {
                        DPA_ERROR("%s::unable to read fwd flow ingress port\n",
                                __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
                }
		if(!rt_entry->input_itf)
		{
                        DPA_ERROR("%s::NULL input interface \n",
                                __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
		}

		ct_entry->inPhyPortNum = rt_entry->input_itf->index;
		ct_entry->status |= nat_op;

		//fill rev flow entra
		rt_entry++;
		ct_entry++;
		rt_entry->mtu = conn_info->fwd_flow.mtu;
                ct_entry->proto = conn_info->proto;
		ct_entry->status = conn_info->flags;
		ct_entry->Sport = htons(conn_info->rev_flow.sport);
                ct_entry->Dport = htons(conn_info->rev_flow.dport);
                ct_entry->Saddr_v4 = htonl(conn_info->rev_flow.ipv4_saddr);
                ct_entry->Daddr_v4 = htonl(conn_info->rev_flow.ipv4_daddr);
		ct_entry->twin = (ct_entry - 1);
		ct_entry->twin_Sport = 
				htons(conn_info->fwd_flow.sport);
		ct_entry->twin_Dport = 
				htons(conn_info->fwd_flow.dport);
		ct_entry->twin_Saddr = 
				htonl(conn_info->fwd_flow.ipv4_saddr);
		ct_entry->twin_Daddr = 
				htonl(conn_info->fwd_flow.ipv4_daddr);
		
		ct_entry->pRtEntry = rt_entry;
		memcpy(&rt_entry->dstmac[0], conn_info->rev_flow.dest_mac, 
				ETHER_ADDR_LEN);
		rt_entry->mtu = conn_info->rev_flow.mtu;

		retval = strncpy_from_user(&port_name[0],
                        conn_info->rev_flow.egress_port, EGRESS_PORTNAME_LEN);
                if (retval == -EFAULT) {
                        DPA_ERROR("%s::unable to read rev flow egress port\n",
                                __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
                }
		onif_desc = get_onif_by_name(&port_name[0]); 
                if (!onif_desc) {
                        DPA_ERROR("%s::unable to get onif for iface %s\n",
                                __FUNCTION__, &port_name[0]);
                        retval = -EIO;
                        goto err_ret;
                }
		rt_entry->itf = onif_desc->itf;
		retval = strncpy_from_user(&port_name[0],
                        conn_info->rev_flow.ingress_port, EGRESS_PORTNAME_LEN);
                if (retval == -EFAULT) {
                        DPA_ERROR("%s::unable to read rev flow ingress port\n",
                                __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
                }
		if(!rt_entry->input_itf)
		{
                        DPA_ERROR("%s::NULL input interface \n",
                                __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
		}

		ct_entry->inPhyPortNum = rt_entry->input_itf->index;
		ct_entry->status |= nat_op;
		//insert forward entry
                if (insert_entry_in_classif_table((ct_entry - 1))) {
                        DPA_ERROR("%s::failed to insert forward entry\n",
                        __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
                }
#ifdef DPA_TEST_DEBUG
                DPA_INFO("%s::inserted forward entry\n", __FUNCTION__);
#endif
                //insert reply/reverse entry
                if (insert_entry_in_classif_table(ct_entry)) {
                        DPA_ERROR("%s::unable to repl entry\n",
                                __FUNCTION__);
                        retval = -EIO;
                        goto err_ret;
                }
#ifdef DPA_TEST_DEBUG
                DPA_INFO("%s::inserted reverse entry\n", __FUNCTION__);
#endif
	}
err_ret:
	if (ct)
		kfree(ct);
	if (rt)
		kfree(rt);
	if (conn_info)
		kfree(conn_info);
	return retval;
	
}
