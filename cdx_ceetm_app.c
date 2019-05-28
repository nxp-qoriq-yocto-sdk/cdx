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

#include <dpaa_eth.h>
#include <dpaa_eth_common.h>
#include <mac.h>
#include "lnxwrp_fm.h"
#include "cdx_ceetm_app.h"
#include "cdx_ceetm_gdef.h"


#define MAX_10G_INTERFACES 2
#define MAX_1G_INTERFACES 8

static u8 ceetm_lni_index_10G[MAX_CEETM][MAX_10G_INTERFACES]; 
static u8 ceetm_lni_index_1G[MAX_CEETM][MAX_1G_INTERFACES]; 

u8 igw_ceetm_total_lnis_per_fman[2]={0,0};
u8 igw_ceetm_total_channels_per_fman[2]={0,0};
EXPORT_SYMBOL(igw_ceetm_total_lnis_per_fman);
EXPORT_SYMBOL(igw_ceetm_total_channels_per_fman);

struct mutex LniIndexlock;

void cdx_ceetm_init(void)
{
  mutex_init(&LniIndexlock);
}

void igw_ceetm_deinit(void)
{
  return;
}

void ceetm_cscn(struct qm_ceetm_ccg *p, void *cb_ctx, int congested)
{
  struct ceetm_fq *ceetm_fq = (struct ceetm_fq *)cb_ctx;
  
  /* Update the congestion state */
  if(ceetm_fq)
  {
    ceetm_fq->congested = congested;
  }
  else
  {
    ceetm_err("ceetm fq NULL congested:: %d\n\r", congested);
  }
  return;
}


void ceetm_cfg_lni( uint32_t fman_id, uint32_t port_id, uint32_t port_type,
   cdx_ceetm_lni_params_t *pLNIparams,
   void **ppLNI)
{
  struct qm_ceetm_sp *sp = NULL;
  struct qm_ceetm_lni *lni = NULL;
  uint32_t sp_idx, lni_idx;
  struct qm_ceetm_rate token_rate, token_ceil;
  uint16_t token_limit;
  uint8_t bLNIIndexClaimed;

  *ppLNI = NULL;
  bLNIIndexClaimed = 0;

  if(port_type == PORT_TYPE_10G)
  {
    if(igwGetFreeLNIIndex(fman_id, e_FM_PORT_TYPE_TX_10G, &lni_idx) != CEETM_SUCCESS)
    {
      goto error;
    }
  }
  else
  {
    if(igwGetFreeLNIIndex(fman_id, e_FM_PORT_TYPE_TX, &lni_idx) != CEETM_SUCCESS)
    {
      goto error;
    }
  }

  if(port_type != PORT_TYPE_10G )
    sp_idx = port_id + CEETM_OFFSET_1G;
  else
    sp_idx = port_id;

  bLNIIndexClaimed = 1;

  ceetm_dbg("%s::%d fmanid = %d subportalid = %d \r\n", __FUNCTION__, __LINE__, fman_id, sp_idx);

  /* claim a subportal */
  if(qman_ceetm_sp_claim(&sp, fman_id, sp_idx))
  {
    ceetm_err("%s %d. qman_ceetm_sp_claim failed \n", __FUNCTION__, __LINE__);
    goto error;
  }
  sp->dcp_idx = fman_id;
  sp->lni = NULL;

  /* claim a LNI */
  if(qman_ceetm_lni_claim(&lni, fman_id, lni_idx))
  {
    ceetm_err("%s %d. qman_ceetm_lni_claim failed \n", __FUNCTION__, __LINE__);
    goto error;
  }

  lni->dcp_idx = fman_id;
  /* Set SP to LNI Mapping */

  if(qman_ceetm_sp_set_lni(sp, lni))
  {
    ceetm_err("%s %d. qman_ceetm_sp_set_lni failed \n", __FUNCTION__, __LINE__);
    goto error;
  }


  ceetm_dbg("Claimed LNI_idx %d & SP_idx %d\n", lni_idx, sp_idx);
  /* Store the SP pointer in LNI.... */
  lni->sp = sp;

  /* Enable Shaper, if Configured */
  if (!pLNIparams->shaping_en)
  {
    ceetm_err(":%s::%d Unshaped Class: Skipping Shaper configuration.\n", __FUNCTION__,__LINE__);
    goto exit;
  }

  /* Else configure the LNI Shaper */
  if(qman_ceetm_lni_enable_shaper(lni, 1, pLNIparams->overhead))
  {
    ceetm_err("%s %d. qman_ceetm_lni_enable_shaper failed \n", __FUNCTION__, __LINE__);
    goto error;
  }

  if(qman_ceetm_bps2tokenrate(pLNIparams->rate, &token_rate, 0))
  {
    ceetm_err("%s %d. qman_ceetm_bps2tokenrate failed \n", __FUNCTION__, __LINE__);
    goto error;
  }

 ceetm_dbg("CR Rate %llu token.whole %d  token.fraction %d\n",
             pLNIparams->rate, token_rate.whole, token_rate.fraction);

  if(qman_ceetm_bps2tokenrate(pLNIparams->ceil, &token_ceil, 0))
  {
    ceetm_err("%s %d. qman_ceetm_bps2tokenrate failed \n", __FUNCTION__, __LINE__);
      goto error;
  }
  
  ceetm_dbg("ER Rate %llu token.whole %d  token.fraction %d\n",
               pLNIparams->ceil, token_ceil.whole, token_ceil.fraction);

  /* Set Committed Rate */
  token_limit = pLNIparams->token_limit;

  ceetm_dbg("Token limit %d  \n", token_limit);

  if(qman_ceetm_lni_set_commit_rate(lni, &token_rate,token_limit))
  {
    ceetm_err("%s %d. qman_ceetm_lni_set_commit_rate failed \n", __FUNCTION__, __LINE__);
    goto error;
  }

  /* Set Exccess Rate */
  if(qman_ceetm_lni_set_excess_rate(lni, &token_ceil, token_limit))
  {
    ceetm_err("%s %d. qman_ceetm_lni_set_excess_rate failed \n", __FUNCTION__, __LINE__);
    goto error;
  }

exit:
  *ppLNI = (void *)lni;
  return;
error:
  if(bLNIIndexClaimed)
  {
//  igwReleaseLNIIndex(fman_id, get_tx_port_type(mac_dev), lni_idx);
    igwReleaseLNIIndex(fman_id, e_FM_PORT_TYPE_TX, lni_idx);
  }
  if(lni)
    qman_ceetm_lni_release(lni);
  if(sp)
    qman_ceetm_sp_release(sp);
}



/**********************************************************************
API to release acquired LNI 
Input param: LNI handle
**********************************************************************/
int ceetm_release_lni(void *handle)
{
  struct qm_ceetm_lni *lni = (struct qm_ceetm_lni *)handle;
  int ret;

  if (!lni)
   return CEETM_SUCCESS;

  ret = qman_ceetm_lni_release(lni);
  if(ret == 0)
    ret = qman_ceetm_sp_release(lni->sp);
#if 0  
  if(lni->idx < 2)
  {
    igwReleaseLNIIndex(lni->dcp_idx, e_FM_PORT_TYPE_TX_10G, lni->idx);
  }
  else
#endif
  {
    igwReleaseLNIIndex(lni->dcp_idx, e_FM_PORT_TYPE_TX, lni->idx);
  }

  ceetm_dbg("Releasing LNI %d ---> SP %d ret:: %d\n", lni->idx, lni->sp->idx, ret);
  return ret;
}


void ceetm_cfg_channel(void *handle,
                     cdx_ceetm_channel_params_t *pChannelparams,
                       void **ppChannel)

{
  struct qm_ceetm_lni *lni = (struct qm_ceetm_lni *)handle;
  struct qm_ceetm_channel *channel = NULL;
  struct qm_ceetm_rate token_rate, token_ceil;

  *ppChannel = NULL;

  /* claim a channel scheduler */
  if (qman_ceetm_channel_claim(&channel, lni))
  {
    ceetm_err("Failed to claim Channel Scheduler for LNI (0x%X)\n", lni->idx);
    return;
  }

  if(channel == NULL)
  {
    ceetm_err("Channel Scheduler is NULL\n");
    return;
  }

  ceetm_dbg("Claimed Channel %d for LNI %d\n", channel->idx, lni->idx);
  /* Enable Shaper, if Configured */

  if (pChannelparams->shaping_en)
  {
    /* configure channel shaper */
    if (qman_ceetm_channel_enable_shaper(channel, 1))
        goto error;
    if (qman_ceetm_bps2tokenrate(pChannelparams->shaper.rate ,&token_rate, 0))
        goto error;

    ceetm_dbg("CR Rate %llu token.whole %d  token.fraction %d\n",
          pChannelparams->shaper.rate, token_rate.whole,token_rate.fraction);
    if (qman_ceetm_bps2tokenrate(pChannelparams->shaper.ceil ,&token_ceil, 0))
        goto error;
    ceetm_dbg("ER Rate %llu token.whole %d  token.fraction %d\n",
          pChannelparams->shaper.ceil, token_ceil.whole,token_ceil.fraction);

    /* Set Committed Rate */
    if (qman_ceetm_channel_set_commit_rate(channel, &token_rate,pChannelparams->shaper.token_limit))
       goto error;

    /* Set Exccess Rate */
    if (qman_ceetm_channel_set_excess_rate(channel, &token_ceil, pChannelparams->shaper.token_limit))
       goto error;
  }
  else 
  {
    /* This may be a unshaped channel */
    ceetm_dbg("Configuring unshaped weight %d\n", pChannelparams->wbfs.weight);
    /* Configure weight for unshaped channel fair queuing */
    if (qman_ceetm_channel_set_weight(channel, pChannelparams->wbfs.weight))
       goto error;
  }

  ceetm_dbg("%s::%d channel idx:%d, dcp_id:%d, lni_idx:%d \r\n",__FUNCTION__,__LINE__,channel->idx, channel->dcp_idx,channel->lni_idx);

  *ppChannel = (void *)channel;
  return;

error:
  if (channel)
     qman_ceetm_channel_release(channel);
  return;
}

void cdx_release_buffer_using_fd( const struct qm_fd *fd, struct net_device *dev)
{
  dma_addr_t addr ;
  struct sk_buff *skb;
  struct sk_buff **skbh;
  const struct dpa_priv_s *priv;
  struct dpa_bp *bp;
        
  if (fd->bpid)
  {
    dpa_fd_release(dev, fd);
  }
  else
  {
    /* release heap SKB */
    priv = netdev_priv(dev);
    bp = priv->dpa_bp;
    addr = qm_fd_addr(fd);

    if(addr)
    {
      DPA_READ_SKB_PTR(skb, skbh, phys_to_virt(addr), 0);
      dma_unmap_single(priv->dpa_bp->dev, addr, fd->length20+fd->offset, DMA_TO_DEVICE);
      dev_kfree_skb_any(skb);
    }
    else
    {
      ceetm_err("%s::%d invalid address received for buffer free \r\n", __FUNCTION__,__LINE__);
    }
  }
  return;
}

extern int qman_ceetm_cq_peek_pop_xsfdrread(struct qm_ceetm_cq *cq,
                        u8 command_type, u16 xsfdr,
                        struct qm_mcr_ceetm_cq_peek_pop_xsfdrread *cq_ppxr);


/**********************************************************************
API to release acquired class queue channel
Input param:
Channel handle
**********************************************************************/
int ceetm_release_channel(void *handle, struct net_device *dev)
{
  struct qm_ceetm_channel *channel = (struct qm_ceetm_channel *)handle;
  struct qm_ceetm_cq *cq, *tmp1;
  struct qm_ceetm_lfq *lfq, *tmp2;
  struct qm_ceetm_ccg *p , *tmp3;
  struct ceetm_fq *fq;
  int ret;

  if(NULL == handle)
    return CEETM_SUCCESS;

  /* Find out the congestion group with index '0'*/
  list_for_each_entry_safe(p, tmp3, &channel->ccgs, node)
  {
    /* release FQs*/
    fq = p->cb_ctx;
    if(fq != NULL)
    {
      /* release the FQ index */
      kfree(fq);
      p->cb_ctx = NULL;
    }
    qman_ceetm_ccg_release(p);
  }
  /* Release all the CQ & LFQs */
  list_for_each_entry_safe(cq, tmp1, &channel->class_queues, node)
  {
    list_for_each_entry_safe(lfq, tmp2, &cq->bound_lfqids, node)
    {
      qman_ceetm_lfq_release(lfq);
    }

#if 0
    /*** code to remove all fds which are already placed into lfq ****/
    {
      struct qm_mcr_ceetm_cq_peek_pop_xsfdrread ppxr;
      int ret;
      do
      {
        ret = qman_ceetm_cq_peek_pop_xsfdrread(cq, 1, 0, &ppxr);
        if (ret)
        {
          ceetm_dbg("Failed to pop frame from CQ\n");
          break;
        }
        if( ppxr.stat & 0x01)
        {
          cdx_release_buffer_using_fd(&(ppxr.fd),dev); 
        }
      }while (!(ppxr.stat & 0x2));
    }
#endif
    ret = qman_ceetm_cq_release(cq);
    if (ret)
    {
      return ret;
    }
  }
  ret = qman_ceetm_channel_release(channel);

  ceetm_dbg("%s %d:: qman_ceetm_channel_release returned :: %d\n\r", __FUNCTION__, __LINE__, ret);
  return ret;
}

/**********************************************************************
API for error handling
Input param:
**********************************************************************/
//extern __igw_qos_scheduler_db_t  igw_qos_scheduler_db;

static void egress_ern(struct qman_portal *portal,
                              struct qman_fq  *fq,
                       const struct qm_mr_entry *msg)
{
  const struct qm_fd *fd = &(msg->ern.fd);
  struct ceetm_fq *pceetm_fq;
  struct sk_buff *skb;
  const struct dpa_priv_s *priv;
#if 0
  dma_addr_t addr = qm_fd_addr(fd);
  struct sk_buff **skbh;
  struct dpa_bp *bp;
#endif

  /* Updates  Pkt Drop STATS */

  if (fd->cmd & FM_FD_CMD_FCO)
    pceetm_fq =  ((struct ceetm_fq*)((unsigned char *)(fq)-(unsigned long)(&((struct ceetm_fq*)0)->recycle_fq)));
  else
    pceetm_fq =  ((struct ceetm_fq*)((unsigned char *)(fq)-(unsigned long)(&((struct ceetm_fq*)0)->egress_fq)));

  if(pceetm_fq)
  {
    //IGWUpdatePktStats((pceetm_fq->pkt_drop_stats), fd->length20);

   /* use BPID here */
    if (fd->bpid != 0xff)
    {
      dpa_fd_release(pceetm_fq->net_dev, fd);
      return;
    }
    else
    {

      /* release SKB */
      priv = netdev_priv(pceetm_fq->net_dev);
      skb = _dpa_cleanup_tx_fd(priv, fd);
      dev_kfree_skb_any(skb); 

      #if 0
         bp = priv->dpa_bp;

         if(unlikely(!addr))
           return;

         DPA_READ_SKB_PTR(skb, skbh, phys_to_virt(addr), 0);
         dma_unmap_single(priv->dpa_bp->dev, addr, fd->length20+fd->offset, DMA_TO_DEVICE);
  
         dev_kfree_skb_any(skb);
      #endif
    }
  }
  else
  {
    ceetm_err("%s::%d invalid ceetm fq pointer received \r\n", __FUNCTION__,__LINE__ );
  }
  return;
}

/************************************************************************
API to get/configure any of the 8 independent prio class queue of a channel 
*************************************************************************/
void ceetm_cfg_prio_class_queue(void *handle, cdx_ceetm_queue_ctxt_t *queue_ctxt)
{
  struct qm_ceetm_channel *channel;
  struct ceetm_fq *fq;
  struct qm_ceetm_cq *cq;
  struct qm_ceetm_lfq *lfq;
  struct qm_ceetm_lfq *recyclelfq;
  struct qm_ceetm_ccg *p = NULL;
  unsigned long context_a = VQA_DPAA_VAL_TO_RELEASE_BUFFER;
  int iRet;
  unsigned int idx; 

  channel = (struct qm_ceetm_channel*)handle;

  idx = queue_ctxt->idx;

  /* Find out the congestion group with index '0'*/
  queue_ctxt->fq = NULL;
  queue_ctxt->cq = NULL;
  
  list_for_each_entry(p, &channel->ccgs, node)
  {
    if (p->idx == idx)
    break;
  }
  if (p == NULL)
  {
    ceetm_err("CCG not found Class Queue %d for CH (0x%X)\n", idx, channel->idx);
    return;
  }

  /* claim a class queue */
  if (qman_ceetm_cq_claim(&cq, channel, idx, p))
  {
    ceetm_err("Failed to claim Class Queue for CH (0x%X)\n", channel->idx);
    return;
  }

  /* Set CR and ER eligibility of PRIO QDisc */
  if (qman_ceetm_channel_set_cq_cr_eligibility(channel, idx, queue_ctxt->prio.params.cr_eligible))
  {
    ceetm_err("Failed to set cr eligibility of cq %d"
      " for CH (0x%X)\n", idx, channel->idx);
    return;
  }

  if (qman_ceetm_channel_set_cq_er_eligibility(channel, idx, queue_ctxt->prio.params.er_eligible))
  {
    ceetm_err("Failed to set er eligibility of cq %d"
      " for CH (0x%X)\n", idx, channel->idx);
    return;
  }

  /* Claim a LFQ */
  if (qman_ceetm_lfq_claim(&lfq, cq))
  {
    ceetm_err("Failed to claim LFQ for CQ (0x%X)\n", cq->idx);
    return;
  }

  /* Claim a recycle FQ */
  if (qman_ceetm_lfq_claim(&recyclelfq, cq))
  {
    ceetm_err("Failed to claim LFQ for CQ (0x%X)\n", cq->idx);
    return;
  }

  /* set context_A for recycle FQ */
  iRet = qman_ceetm_lfq_set_context(recyclelfq,context_a,0);
  if(iRet)
  {
    ceetm_err("%s::%d Set context for lfq failed error:%d \r\n",__FUNCTION__,__LINE__, iRet); 
    return;
  }

  ceetm_dbg("Creating CQ [%d] --> LFQ/FQ [%d]\n", idx, recyclelfq->idx);
  ceetm_dbg("Creating CQ [%d] --> LFQ/FQ [%d]\n", idx, lfq->idx);

  /* get free FQ index */
  fq = (struct ceetm_fq *) kzalloc(sizeof(struct ceetm_fq),GFP_KERNEL);
  if(fq == NULL)
  {
    ceetm_dbg("%s :: Memory allocation failed for FQ array\n\r", __FUNCTION__);
    return ;
  }

  /* create LFQ */
  lfq->ern = egress_ern;
  if (qman_ceetm_create_fq(lfq, &fq->egress_fq))
  {
    kfree(fq);
    return;
  }
  
  /* create recycle FQ */
  recyclelfq->ern = egress_ern;
  if (qman_ceetm_create_fq(recyclelfq, &fq->recycle_fq))
  {
    kfree(fq);
    return;
  }

  ceetm_dbg("%d:: CEETM CQ:: %p fq : %p egrssfq:: %p recylefq::%p \n", __LINE__, cq, fq, &fq->egress_fq, &fq->recycle_fq);

  /* All is well */
  p->cb_ctx = (void *) fq;
  queue_ctxt->cq = (void *)cq;
  queue_ctxt->fq = (void *)fq;

  return;
}

/************************************************************************
API to get/configure any of the 8 independent class queue of a channel 
*************************************************************************/
void ceetm_cfg_wbfs_class_queue(void *handle, cdx_ceetm_queue_ctxt_t *queue_ctxt)
{
  struct qm_ceetm_channel *channel = (struct qm_ceetm_channel *)handle;
  struct qm_ceetm_lfq *lfq;
  struct qm_ceetm_lfq *recyclelfq;
  struct qm_ceetm_cq *cq;
  struct ceetm_fq *fq;
  struct qm_ceetm_ccg *p = NULL;
  unsigned long context_a = VQA_DPAA_VAL_TO_RELEASE_BUFFER;
  struct qm_ceetm_weight_code weight_code;
  int iRet;
  unsigned int idx;

  idx = queue_ctxt->idx;
  /* Find out the congestion group with index '0'*/
  queue_ctxt->fq = NULL;
  queue_ctxt->cq = NULL;

  list_for_each_entry(p, &channel->ccgs, node) 
  {
    if (p->idx == idx)
      break;
  }
  if (p == NULL)
  {
    ceetm_err("CCG not found Class Queue %d" " for CH (0x%X)\n", idx, channel->idx);
    return;
  }

  if(queue_ctxt->wbfs.grp_type == CEETM_WBFS_GRP_B)
  {
    if (qman_ceetm_cq_claim_B(&cq, channel, idx, p)) 
    {
      ceetm_err("Failed to claim Class Queue B" " for CH (0x%X)\n", channel->idx);
      return;
    }
  }
  else
  {
    if (qman_ceetm_cq_claim_A(&cq, channel, idx, p)) 
    {
      ceetm_err("Failed to claim Class Queue A" " for CH (0x%X) \n", channel->idx);
      return;
    }
  }

  /* Set the Queue Weight */
  qman_ceetm_ratio2wbfs(queue_ctxt->wbfs.params.weight, 1, &weight_code, 0);
  qman_ceetm_set_queue_weight(cq, &weight_code);

  ceetm_dbg(" CQ weight is [%d] -->  y[%d] x[%d]\n",
                        queue_ctxt->wbfs.params.weight, weight_code.y, weight_code.x);
        /* Claim a LFQ */
  if (qman_ceetm_lfq_claim(&lfq, cq)) 
  {
    ceetm_err("Failed to claim LFQ" " for CQ (0x%X)\n", cq->idx);
    return;
  }

  if (qman_ceetm_lfq_claim(&recyclelfq, cq))
  {
    ceetm_err("Failed to claim LFQ for CQ (0x%X)\n", cq->idx);
    return;
  }

  iRet = qman_ceetm_lfq_set_context(recyclelfq,context_a,0);

  if(iRet)
  {
    ceetm_err("%s::%d Set context for lfq failed error:%d \r\n",__FUNCTION__,__LINE__, iRet); 
    return;
  }

  ceetm_dbg("Creating CQ [%d] --> LFQ/FQ [%d]\n", idx, recyclelfq->idx);
  ceetm_dbg("Creating CQ [%d] --> LFQ/FQ [%d]\n", idx, lfq->idx);

  fq = (struct ceetm_fq *) kzalloc(sizeof(struct ceetm_fq),GFP_KERNEL);
  if(fq == NULL)
  {
    ceetm_dbg("%s :: Memory allocation failed for FQ array\n\r", __FUNCTION__);
    return ;
  }

  lfq->ern = egress_ern;
  if (qman_ceetm_create_fq(lfq, &fq->egress_fq))
  {
    kfree(fq);
    return;
  }
  
  recyclelfq->ern = egress_ern;
  if (qman_ceetm_create_fq(recyclelfq, &fq->recycle_fq))
  {
    kfree(fq);
    return;
  }

  /* All is well */
  ceetm_dbg("%d:: CEETMFQ:: %p egrssfq:: %p recylefq::%p \n", __LINE__, fq, &fq->egress_fq, &fq->recycle_fq);

  p->cb_ctx = (void *) fq;
  queue_ctxt->cq = (void *)cq;
  queue_ctxt->fq = (void *)fq;

  return;
}
EXPORT_SYMBOL(ceetm_cfg_wbfs_class_queue);


/************************************************************************
API to release class queue 
*************************************************************************/
void ceetm_release_cq(void *handle)
{
  /* release the (struct ceetm_fq) object memory */
  if(handle)
     kfree(handle);
}
void igw_num_to_2powN_multiple(unsigned int uiNum, unsigned int *pNum, unsigned int *pMul, 
                               unsigned int uiMaxBitsInN, unsigned int uiMaxBitsInMul)
{
  int ii, iMsbBit = 0;

  for(ii=0; ii < (sizeof(ii) * 8) ; ii++)
  {
    if(uiNum & (1 << ii))
       iMsbBit = ii;
  }

  if(iMsbBit < uiMaxBitsInMul)
  {
    *pNum = 0;
    *pMul = uiNum;
  }
  else if(iMsbBit < (uiMaxBitsInMul + (1<<uiMaxBitsInN) - 1))
  {
    *pNum = iMsbBit - uiMaxBitsInMul + 1;
    *pMul = uiNum >> (*pNum);
  }
  else
  {
    *pNum = uiMaxBitsInN;
    *pMul = (1 << uiMaxBitsInMul) - 1;
  }
}

int ceetm_cfg_ccg_to_class_queue(struct qm_ceetm_channel *pChannel, unsigned int iCqNum, 
                                       cdx_ceetm_ccg_in_params_t *pCcg_params)
{
  struct qm_ceetm_ccg *ccg = NULL/*, *tmp*/;
  struct qm_ceetm_ccg_params params;
  uint16_t mask = 0;
  unsigned int uiNum, uiMul;
  unsigned int uiMa, uiMn;

  /* Claim Congestion control groups with index 0 - 15.*/
  memset(&params, 0, sizeof(struct qm_ceetm_ccg_params));
  params.mode = 1/* 0 -bytecount, 1 - framecount */;

  if(pCcg_params->cong_avoid_alg & QOS_CEETM_TAIL_DROP)
  {
    params.td_en = 1; //enable taildrop congestion avoidance algo
    params.td_mode = 1;
    igw_num_to_2powN_multiple(pCcg_params->tail_drop.threshold, &uiNum, &uiMul, 4, 8);
    params.td_thres.Tn = uiNum;
    params.td_thres.TA = uiMul;
    mask = QM_CCGR_WE_MODE | QM_CCGR_WE_TD_EN | QM_CCGR_WE_TD_MODE| QM_CCGR_WE_TD_THRES;

    /* Threshold start limt is 64 & exit limt is 32 . These values
                  are reffered from HW QMAN CEETM test scripts*/
    params.cscn_en = 1; //disable wred congestion avoidance
    params.cs_thres_in.TA = QOS_CEETM_CS_THRSIN_TA;
    params.cs_thres_in.Tn = QOS_CEETM_CS_THRSIN_TN;
    params.cs_thres_out.TA = QOS_CEETM_CS_THRSOUT_TA;
    params.cs_thres_out.Tn = QOS_CEETM_CS_THRSOUT_TN;

    mask |= QM_CCGR_WE_MODE | QM_CCGR_WE_CSCN_EN | QM_CCGR_WE_CS_THRES_IN | QM_CCGR_WE_CS_THRES_OUT;
  }
  else
  if(pCcg_params->cong_avoid_alg & QOS_CEETM_WRED)
  {
    /*set params to ccg structure */
    if(pCcg_params->wred[CEETM_WRED_GREEN].color)
    {
       /* calculate Ma and Mn*/
      igw_num_to_2powN_multiple(pCcg_params->wred[CEETM_WRED_GREEN].max_threshold, &uiMn, &uiMa, 4, 8);
      params.wr_en_g = 1;
      params.wr_parm_g.MA = uiMa;
      params.wr_parm_g.Mn = uiMn;
      params.wr_parm_g.SA = pCcg_params->wred[CEETM_WRED_GREEN].uiSa;
      params.wr_parm_g.Sn = pCcg_params->wred[CEETM_WRED_GREEN].uiSn;
      params.wr_parm_g.Pn = pCcg_params->wred[CEETM_WRED_GREEN].uiMaxP;
      mask = QM_CCGR_WE_MODE | QM_CCGR_WE_WR_EN_G | QM_CCGR_WE_WR_PARM_G;
    }
    if(pCcg_params->wred[CEETM_WRED_YELLOW].color)
    {
      igw_num_to_2powN_multiple(pCcg_params->wred[CEETM_WRED_YELLOW].max_threshold, &uiMn, &uiMa, 4, 8);
      params.wr_en_y = 1;
      params.wr_parm_y.MA = uiMa;
      params.wr_parm_y.Mn = uiMn;
      params.wr_parm_y.SA = pCcg_params->wred[CEETM_WRED_YELLOW].uiSa;
      params.wr_parm_y.Sn = pCcg_params->wred[CEETM_WRED_YELLOW].uiSn;
      params.wr_parm_y.Pn = pCcg_params->wred[CEETM_WRED_YELLOW].uiMaxP;
      mask |= QM_CCGR_WE_MODE | QM_CCGR_WE_WR_EN_Y | QM_CCGR_WE_WR_PARM_Y;
    }
    if(pCcg_params->wred[CEETM_WRED_RED].color)
    {
      igw_num_to_2powN_multiple(pCcg_params->wred[CEETM_WRED_RED].max_threshold, &uiMn, &uiMa, 4, 8);
      params.wr_en_r = 1;
      params.wr_parm_r.MA = uiMa;
      params.wr_parm_r.Mn = uiMn;
      params.wr_parm_r.SA = pCcg_params->wred[CEETM_WRED_RED].uiSa;
      params.wr_parm_r.Sn = pCcg_params->wred[CEETM_WRED_RED].uiSn;
      params.wr_parm_r.Pn = pCcg_params->wred[CEETM_WRED_RED].uiMaxP;
      mask |= QM_CCGR_WE_MODE | QM_CCGR_WE_WR_EN_R | QM_CCGR_WE_WR_PARM_R;
    }
  }
  else
  {
    params.cscn_en = 1; //disable wred congestion avoidance
  /* Threshold start limt is 64 & exit limt is 32 . These values
                  are reffered from HW QMAN CEETM test scripts*/
    params.cs_thres_in.TA = QOS_CEETM_CS_THRSIN_TA;
    params.cs_thres_in.Tn = QOS_CEETM_CS_THRSIN_TN;
    params.cs_thres_out.TA = QOS_CEETM_CS_THRSOUT_TA;
    params.cs_thres_out.Tn = QOS_CEETM_CS_THRSOUT_TN;

    mask = QM_CCGR_WE_MODE | QM_CCGR_WE_CSCN_EN | 
                   QM_CCGR_WE_CS_THRES_IN | QM_CCGR_WE_CS_THRES_OUT;
  }

  /* Callback context of each CQ will set later, when alloacted */
  if (qman_ceetm_ccg_claim(&ccg, pChannel, iCqNum, ceetm_cscn, NULL))
     return -1;
  if (qman_ceetm_ccg_set(ccg, mask, &params))
     return -1;
  ceetm_dbg("CCG claimed for class queue %d ccgid=:%u \n", iCqNum, ccg->idx);

  return 0;
}


int ceetm_cfg_wbfs_grp(void *handle, int grp, uint32_t pri)
{
  struct qm_ceetm_channel *channel = (struct qm_ceetm_channel *)handle;

  /* claim a class queue */
  switch (grp) 
  {
    case CEETM_WBFS_GRP_A:
    {
      /* Keeping Priority of group B = group A, till it's not configured in future */
      ceetm_dbg("CEETM_WBFS_GRP_A with priority %d\n", pri);
      if (qman_ceetm_channel_set_group(channel, 1, pri, pri)) 
      {
        ceetm_err("Failed to set Group A for CH (0x%X)\n", channel->idx);
        return -EINVAL;
      }
    }
    break;
  
    case CEETM_WBFS_GRP_B:
    {
      uint32_t prio_a, prio_b;
      int group_b;
    
/*      if(prio_b > 7 )
      {
        ceetm_err("CEETM_WBFS_GRP_B priority(%d) should be  <= 7\n", prio_b);
        return -EINVAL;
      }*/

      if (qman_ceetm_channel_get_group(channel, &group_b, &prio_a, &prio_b)) 
      {
        ceetm_err("Failed to Get WBFS Group Settings for CH (0x%X)\n", channel->idx);
        return -EINVAL;
      }
      ceetm_dbg("CEETM_WBFS_GRP_B with prio_A %d  prio_B %d\n", prio_a, pri);
      
      if (qman_ceetm_channel_set_group(channel, 1, prio_a, pri)) 
      {
        ceetm_err("Failed to Set Group B for CH (0x%X)\n", channel->idx);
        return -EINVAL;
      }
    }
    break;
 
    case CEETM_WBFS_GRP_BOTH:
    {
      /* add check to verify pri */
      if(pri > 7 /* grp max priority */)
      {
        ceetm_err("CEETM_WBFS_GRP_both priority should be  <= 7");
        return -EINVAL;
      }
      if (qman_ceetm_channel_set_group(channel, 0, pri, 0)) 
      {
        ceetm_err("Failed to Set Group A for CH (0x%X)\n", channel->idx);
        return -EINVAL;
      }
    }
    break;
  }

  return CEETM_SUCCESS;
}

EXPORT_SYMBOL(ceetm_cfg_wbfs_grp);


                  
int qman_ceetm_channel_set_group_cr_er_eligibility(void *handle,
                int grp,
                u16 cr_eligibility,
                u16 er_eligibility)
{       
  struct qm_ceetm_channel *channel = (struct qm_ceetm_channel *)handle;

  int group_b_flag = 0;           
        
  if (grp == CEETM_WBFS_GRP_B) 
    group_b_flag = 1;
                
  if (qman_ceetm_channel_set_group_cr_eligibility(channel, group_b_flag, cr_eligibility)) 
  {
    ceetm_err("Failed to set cr eligibility of group %d for CH (0x%X)\n", grp, channel->idx);
    return -1;
  }
  if (qman_ceetm_channel_set_group_er_eligibility(channel, group_b_flag, er_eligibility)) 
  {
    ceetm_err("Failed to set er eligibility of cq %d for CH (0x%X)\n", grp, channel->idx);
    return -1;
  }

  return CEETM_SUCCESS;
}
EXPORT_SYMBOL(qman_ceetm_channel_set_group_cr_er_eligibility);

void  igwConvertFloatToSa2Sn(  double dFloatVal,
                          unsigned int uiMinSa,
                          unsigned int uiMaxSa,
                          unsigned int uiMinSn,
                          unsigned int uiMaxSn,
                          unsigned int *pSa,
                          unsigned int *pSn);


int igwGetFreeLNIIndex( int dcp_id, int interface_type, unsigned int *pIndex)
{
  unsigned int ii;

  mutex_lock(&LniIndexlock);
  if(interface_type == e_FM_PORT_TYPE_TX)
  {
    for(ii=0;ii < MAX_1G_INTERFACES; ii++)
    {
      if(ceetm_lni_index_1G[dcp_id][ii] == 0)
      {
        ceetm_lni_index_1G[dcp_id][ii] = 1;
        *pIndex = ii+2;
        mutex_unlock(&LniIndexlock);
        return CEETM_SUCCESS;
      }
    } 
  }
  else
  {
    for(ii=0;ii < MAX_10G_INTERFACES; ii++)
    {
      if(ceetm_lni_index_10G[dcp_id][ii] == 0)
      {
        ceetm_lni_index_10G[dcp_id][ii] = 1;
        *pIndex = ii;
        mutex_unlock(&LniIndexlock);
        return CEETM_SUCCESS;
      }
    } 
  }
  mutex_unlock(&LniIndexlock);
  return CEETM_FAILURE;
}

void igwReleaseLNIIndex( int dcp_id, int interface_type, int index)
{
  mutex_lock(&LniIndexlock);
  if(interface_type == e_FM_PORT_TYPE_TX_10G )
  {
    ceetm_lni_index_10G[dcp_id][index] = 0;
  }
  else
  {
    ceetm_lni_index_1G[dcp_id][index - 2] = 0;
  }
  mutex_lock(&LniIndexlock);
  return;
}


