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


#include "cdx.h"
#include "cdx_ioctl.h"
#include "module_qm.h"
#include "cdx_ceetm_app.h"
#include "misc.h"



#define FFS(x)	__fls(x)
QM_context_ctl gQMCtx[MAX_PHY_PORTS];
//#define QM_DEBUG

struct list_head  Qos_list;
// The global stat array is initialized to invalid values, to force the initial state to be
// written to the class PEs at initialization time.
//static u8 qm_global_stat[GEM_PORTS] = {1, 1, 1};
extern struct cdx_port_info *get_dpa_port_info(char *name);

extern void cdx_ceetm_init(void);

/** Fill the QOS query command.
 * This function is used to fill the information from the qos context
 * to the command strucutre on issue of query command.
 *
 * @param pQoscmd  Qos query command structure.
 *
 */
static int QM_Get_Info(pQosQueryCmd pQoscmd)
{
	struct tQM_context_ctl *qm_context_ctl;
	struct cdx_port_info *port_info;

	//PQM_ShaperDesc pshaper;
	//PQM_ShaperDesc_ctl pshaper_ctl;
	//PQM_SchedDesc psched;
	//PQM_QDesc pq;
	int i;


	if (!(port_info = get_dpa_port_info(pQoscmd->ifname)))
		pQoscmd->queue_qosenable_mask =  0; //qm_global_stat[qm_context_ctl->port] == QM_ENABLE ? 0xffffffff : 0;
	else 
		pQoscmd->queue_qosenable_mask =  0xffffffff;

	qm_context_ctl = QM_GET_CONTEXT(port_info->index);

	//pQoscmd->max_txdepth = 0;  // not used for C2K

	for (i = 0; i < NUM_SHAPERS; i++)
	{
		//pshaper = &qm_context_ctl->hw_shaper[i];
		//pshaper_ctl = &qm_context_ctl->hw_shaper_ctl[i];
		pQoscmd->shaper_qmask[i] = qm_context_ctl->qmask;
		pQoscmd->shaper_rate[i] = qm_context_ctl->shaper_enable ? qm_context_ctl->shaper_rate : 0;
		pQoscmd->bucket_size[i] = qm_context_ctl->bucket_size;
	}

	for (i = 0; i < NUM_SCHEDULERS; i++)
	{
		pQoscmd->sched_qmask[i] = qm_context_ctl->qmask;
		pQoscmd->sched_alg[i] = 0; /*FIXME : 8 queues will be in SPQ and other 8 in WFQ */
	}

	for (i = 0; i < NUM_QUEUES; i++)
	{
		//pq = &qm_context->q[i];
		pQoscmd->max_qdepth[i] = qm_context_ctl->max_qdepth[i];
	//	pQoscmd->weight[i] = qm_context_ctl->weight[i];
	}


	return 0;


}
#if 0
static void dump_qos_configuration(struct tQM_context_ctl *qmCtx)
{
	int ii, len;
	char buf[128];

	printk(KERN_INFO "Num_hw_shapers : %d \n", qmCtx->num_hw_shapers);
        printk(KERN_INFO "Num_sched	 : %d \n", qmCtx->num_sched);
        printk(KERN_INFO "ifg		 : %d \n", qmCtx->ifg);
        printk(KERN_INFO "qweight_change_flag : %d \nqdepth_change_flag : %d \nsched_change_flag : %d\n shaper_change_flag : %d \n", qmCtx->qweight_change_flag, qmCtx->qdepth_change_flag, qmCtx->sched_change_flag, qmCtx->shaper_change_flag);
        printk(KERN_INFO "qmask : %x \n", qmCtx->qmask);
	
	for (len = 0, ii = 0; ii < NUM_QUEUES; ii++)
        	len += sprintf(&buf[len], " %02d", qmCtx->weight[ii]);
        
        printk(KERN_INFO "weights : %s\n", buf);
	
	for (len = 0, ii = 0; ii < NUM_QUEUES; ii++)
        	len += sprintf(&buf[len], " %02d", qmCtx->max_qdepth[ii]);
        
	printk(KERN_INFO "\nmax_qdepth : %s\n", buf);

        printk(KERN_INFO"\nshaper_enable : %d\n", qmCtx->shaper_enable);
        printk(KERN_INFO"\nshaper_rate : %d\n", qmCtx->shaper_rate);
        printk(KERN_INFO"\nbucket_size : %d\n", qmCtx->bucket_size);

	return;
}
#endif

cdx_ceetm_lni_ctxt_t* GetQoSShaperInfo(int fmanId, int portId)
{
  cdx_ceetm_lni_ctxt_t *tmp;
  struct list_head *ptr;

  printk("%s::%d fmanid:%d portid:%d \r\n", __FUNCTION__, __LINE__,fmanId, portId);
  list_for_each(ptr, &Qos_list)
  {
    tmp = list_entry(ptr, cdx_ceetm_lni_ctxt_t, list);
    if((tmp->fman_id == fmanId) && (tmp->port_id == portId))
         return tmp;
  }
  printk("%s::%d fmanid:%d portid:%d \r\n", __FUNCTION__, __LINE__,fmanId, portId);
  return NULL;
}

struct qman_fq* cdx_ceetm_get_queue(struct net_device *net_dev, int queue_no)
{
  cdx_ceetm_lni_ctxt_t *tmp, *pLNICtxt;
  struct list_head *ptr;

  pLNICtxt = NULL;
  
  list_for_each(ptr, &Qos_list)
  {
    tmp = list_entry(ptr, cdx_ceetm_lni_ctxt_t, list);
    if(!strcmp(tmp->name, net_dev->name))
        pLNICtxt = tmp;
  }
  
  if(pLNICtxt)
  {
    if(pLNICtxt->pChannels[0]->pQueues[queue_no])
       return (&(pLNICtxt->pChannels[0]->pQueues[queue_no]->fq->recycle_fq));
    else
    {
      //printk("Queue not configured , using default Queue\r\n");
      return (&(pLNICtxt->pChannels[0]->pQueues[QOS_DEFAULT_QUEUE]->fq->recycle_fq));
    }
  }

  return NULL;
}

int cdx_ceetm_IsShaperEnabled(int fmanId, int portId)
{
  cdx_ceetm_lni_ctxt_t *tmp;
  struct list_head *ptr;
  
  list_for_each(ptr, &Qos_list)
  {
    tmp = list_entry(ptr, cdx_ceetm_lni_ctxt_t, list);
    if((tmp->fman_id == fmanId) && (tmp->port_id == portId))
         return 1;
  }
  return 0;
}

int cdx_ceetm_get_lfqid(int fmanId, int portId, int queue_no)
{
  cdx_ceetm_lni_ctxt_t *tmp, *pLNI_Ctxt;
  struct list_head *ptr;

  pLNI_Ctxt = NULL;
  list_for_each(ptr, &Qos_list)
  {
    tmp = list_entry(ptr, cdx_ceetm_lni_ctxt_t, list);
    if((tmp->fman_id == fmanId) && (tmp->port_id == portId))
    {
      pLNI_Ctxt =  tmp;
    }
  }

  if(pLNI_Ctxt)
  {
    if(pLNI_Ctxt->pChannels[0]->pQueues[queue_no])
      return (pLNI_Ctxt->pChannels[0]->pQueues[queue_no]->fq->recycle_fq.fqid);
    else
    {
      //printk("Queue not configured , using default Queue\r\n");
      return (pLNI_Ctxt->pChannels[0]->pQueues[QOS_DEFAULT_QUEUE]->fq->recycle_fq.fqid);
    }
  }
  return -1;
}

int ConfigureCEETM(struct tQM_context_ctl *qm_context_ctl)
{
  cdx_ceetm_lni_ctxt_t *pLNI_ctxt;
  int ii, ret_val;
  unsigned int uiNoOfSchedulers;
  cdx_ceetm_channel_ctxt_t *pChannelCtxt;
  cdx_ceetm_queue_ctxt_t *pQueueCtxt;
  cdx_ceetm_ccg_in_params_t ccg_params;
  int ceetm_qno, iInitGroup ;
  int  jj;
  struct net_device *pDev;

  pLNI_ctxt = (cdx_ceetm_lni_ctxt_t *)
        kzalloc ((sizeof(cdx_ceetm_lni_ctxt_t)),0);
  if (!pLNI_ctxt)
  {
    printk("%s::mem alloc for conn info failed\n",
                        __FUNCTION__);
        ret_val = -ENOMEM;
        return -1;
  }


  pLNI_ctxt->shaper.shaping_en = qm_context_ctl->shaper_enable;
  pLNI_ctxt->shaper.rate = qm_context_ctl->shaper_rate * 1000 ;
  pLNI_ctxt->shaper.ceil = 0;
  pLNI_ctxt->shaper.mpu = 64 ;
  pLNI_ctxt->shaper.token_limit = qm_context_ctl->bucket_size ;
  pLNI_ctxt->shaper.overhead = 24 ; //change it according to IFG
  pLNI_ctxt->fman_id = qm_context_ctl->port_info->fm_index;
  pLNI_ctxt->port_id = qm_context_ctl->port_info->index;
  pLNI_ctxt->port_type = qm_context_ctl->port_info->type;
  strncpy(pLNI_ctxt->name, qm_context_ctl->port_info->name, CDX_CTRL_PORT_NAME_LEN);

  pDev = dev_get_by_name(&init_net, pLNI_ctxt->name);
  if(pDev == NULL)
  {
    printk("%s:: Invalid interface name \r\n", __FUNCTION__);
    return -1;
  }
  
  ceetm_cfg_lni( pLNI_ctxt->fman_id,pLNI_ctxt->port_id,
        pLNI_ctxt->port_type, &pLNI_ctxt->shaper, (void*)(&(pLNI_ctxt->lni)));
  if(pLNI_ctxt->lni == NULL)
  {
    DPA_ERROR("CEETM: Configuring LNI failed \r\n");
    kfree(pLNI_ctxt);
    return -1;
  }

  uiNoOfSchedulers = qm_context_ctl->num_sched;

  uiNoOfSchedulers = 1;
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
    pChannelCtxt->params.shaper.rate = qm_context_ctl->shaper_rate*1000;
    pChannelCtxt->params.shaper.ceil = 0;
    pChannelCtxt->params.shaper.token_limit = qm_context_ctl->bucket_size;

    ceetm_cfg_channel(pLNI_ctxt->lni, &pChannelCtxt->params, (void *)(&pChannelCtxt->pChannel));
    if(pChannelCtxt->pChannel == NULL)
    {
      DPA_ERROR("%s::%d configuring channel failed \r\n",
                        __FUNCTION__, __LINE__);
        ret_val = -1;
        kfree(pChannelCtxt);
        goto err_ret;
    }
    pLNI_ctxt->pChannels[pLNI_ctxt->uiNoOfChannels++] = pChannelCtxt;

    //Using queue 7 as default queue for control packets
    //Using queue 0 for unmarked packets
    qm_context_ctl->qmask |= ((1<<QOS_LEAST_PRIORITY_QUEUE)|(1<<QOS_DEFAULT_QUEUE));

    // Configuring priority class queues

    for(ii=7, ceetm_qno = 0; ii>=0; ii--, ceetm_qno++)
    {
      pQueueCtxt = NULL;
      if((qm_context_ctl->qmask>>ii)&1)
      {
        ccg_params.cong_avoid_alg = QOS_CEETM_TAIL_DROP;
        ccg_params.tail_drop.threshold = qm_context_ctl->max_qdepth[ii];
        ccg_params.tail_drop.threshold = 8;
        ret_val = ceetm_cfg_ccg_to_class_queue(pChannelCtxt->pChannel, ceetm_qno, &ccg_params);
        if(ret_val)
        {
          DPA_ERROR("%s %d :: ceetm_cfg_ccg_to_class_queue failed \r\n", __FUNCTION__, __LINE__);
          goto err_ret;
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

        pQueueCtxt->idx = ceetm_qno;
        pQueueCtxt->prio.params.cr_eligible = 1;
        pQueueCtxt->prio.params.er_eligible = 1;
        ceetm_cfg_prio_class_queue((void*)(pChannelCtxt->pChannel), pQueueCtxt);
        if((pQueueCtxt->cq == NULL) || (pQueueCtxt->fq == NULL))
        {
          DPA_ERROR("%s::%d Configuring Prio class queue failed \r\n",
                                __FUNCTION__, __LINE__);
          kfree(pQueueCtxt);
          ret_val = -1;
          goto err_ret;
        }
        pQueueCtxt->fq->net_dev = pDev;
      }
      pChannelCtxt->pQueues[ii] = pQueueCtxt;  
    }
    iInitGroup =0;
    for(ii=15; ii>=8; ii--)
    {
      pQueueCtxt=NULL;
      if((qm_context_ctl->qmask>>ii)&1)
      {
        ccg_params.cong_avoid_alg = QOS_CEETM_TAIL_DROP;
        ccg_params.tail_drop.threshold = qm_context_ctl->max_qdepth[ii];
        ccg_params.tail_drop.threshold = 8;
        ret_val = ceetm_cfg_ccg_to_class_queue(pChannelCtxt->pChannel, ii,  &ccg_params);
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
        if(iInitGroup == 0)
        {
          if(ceetm_cfg_wbfs_grp((void*)(pChannelCtxt->pChannel), CEETM_WBFS_GRP_BOTH, 6))   //Settting WBFS group priority to 7 by default.
          {
            DPA_ERROR("%s::configuring wbfs group failed \r\n",
                                          __FUNCTION__);
            ret_val = -1;
            goto err_ret;
          }
          if(qman_ceetm_channel_set_group_cr_er_eligibility(
                          (void*)(pChannelCtxt->pChannel),
                                 CEETM_WBFS_GRP_BOTH,1,1))
          {
            DPA_ERROR("%s::configuring wbfs group cr er eligibility failed \r\n", __FUNCTION__);
            ret_val = -1;
            goto err_ret;
          }
              
          iInitGroup = 1;
        }
        pQueueCtxt->idx = ii;
        pQueueCtxt->wbfs.grp_type = CEETM_WBFS_GRP_BOTH;
        pQueueCtxt->wbfs.params.weight = qm_context_ctl->weight[ii];

        ceetm_cfg_wbfs_class_queue((void*)(pChannelCtxt->pChannel), pQueueCtxt);
        if((pQueueCtxt->cq == NULL) || (pQueueCtxt->fq == NULL))
        {
          DPA_ERROR("%s::%d Configuring WBFS class queue failed \r\n",
                                __FUNCTION__, __LINE__);
          kfree(pQueueCtxt);
          ret_val = -1;
          goto err_ret;
        }
        pQueueCtxt->fq->net_dev = pDev;
      }
      pChannelCtxt->pQueues[ii] = pQueueCtxt;  
    }
    uiNoOfSchedulers--;
  }

  list_add(&(pLNI_ctxt->list),&Qos_list);
  return 0;
err_ret:
  for(ii=0; ii<pLNI_ctxt->uiNoOfChannels;ii++)
  {
    pChannelCtxt = (pLNI_ctxt->pChannels[ii]);
    if(pChannelCtxt)
    {
      ceetm_release_channel(pChannelCtxt->pChannel,NULL);
      for(jj=0;jj<CDX_CEETM_MAX_QUEUES_PER_CHANNEL; jj++)
      {
        if(pChannelCtxt->pQueues[jj] != NULL)
        {
          kfree(pChannelCtxt->pQueues[jj]);
        }
      }
      kfree(pChannelCtxt);
    }
  }
  ceetm_release_lni(pLNI_ctxt->lni);
  kfree(pLNI_ctxt);  
  return -1;
}

/** QOS command executer.
 * This function is the QOS handler function / the entry point
 * to process the qos commands
 *
 * @param cmd_code   Command code.
 * @param cmd_len    Command length.
 * @param p          Command structure.
 *
 */

static U16 M_qm_cmdproc(U16 cmd_code, U16 cmd_len, U16 *p)
{
	struct tQM_context_ctl *qm_context_ctl;
	struct cdx_port_info *port_info;
	int i;
	U16 rtncode = 0;
	U16 retlen = 2;

	rtncode = CMD_OK;
#ifdef QM_DEBUG
	printk(KERN_INFO "%s: cmd_code=0x%x\n", __func__, cmd_code);
#endif
	switch (cmd_code)
	{
		// enable/disable QOS processing
		case CMD_QM_QOSALG:
		case CMD_QM_MAX_TXDEPTH:
		case CMD_QM_RATE_LIMIT:
		case CMD_QM_QUEUE_QOSENABLE:
			break;

		case CMD_QM_QOSENABLE:
		{
			PQosEnableCommand pcmd;
			U32 qmask;

			pcmd = (PQosEnableCommand)p;

			
#ifdef QM_DEBUG
			printk(KERN_INFO "%s:%d Qos is enable for %s\n", __func__, __LINE__, pcmd->ifname);
#endif

			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				rtncode = CMD_ERR;
				break;
			}

			qm_context_ctl = QM_GET_CONTEXT(port_info->index);
			qm_context_ctl->port_info = port_info;

			if (pcmd->enable_flag)
			{
				qm_context_ctl->qos_enabled = 1;
				if (qm_context_ctl->num_sched) {
					qmask = qm_context_ctl->qmask;

					while(qmask) {
						i = FFS(qmask);
						qmask &= ~(1 << i);
				
						if (!qm_context_ctl->max_qdepth[i])
							qm_context_ctl->max_qdepth[i] = DEFAULT_MAX_QDEPTH; 

						/* Queue 8 to 15 are WFQ weight should be configured */
						if (!qm_context_ctl->weight[i] && (i > 7))
							qm_context_ctl->weight[i] = 1;
					}
				}
					
				ConfigureCEETM(qm_context_ctl);
#ifdef QM_DEBUG
				printk(KERN_INFO "%s:%d CEETM enabled \n", __func__, __LINE__);
#endif
			}
			else
			{	
				qm_context_ctl->qos_enabled = 0;
				//Disable CEETM
				printk(KERN_INFO "%s:%d CEETM disable is not supported \n", __func__, __LINE__);
			}


		//	printk(KERN_INFO "%s:%d Qos is enabled by default\n", __func__, __LINE__);
			
			break;
		}

		case CMD_QM_MAX_QDEPTH:
		{
			PQosMaxqdepthCommand pcmd;
#ifdef QM_DEBUG
			printk(KERN_INFO "MAX QDEPTH command received %d\n", cmd_code);
#endif
			pcmd = (PQosMaxqdepthCommand)p;

			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				rtncode = CMD_ERR;
				break;
			}

			qm_context_ctl = QM_GET_CONTEXT(port_info->index);
			qm_context_ctl->port_info = port_info;

			for (i = 0; i < NUM_QUEUES; i++) {
				if (pcmd->maxqdepth[i] > 0)
					qm_context_ctl->max_qdepth[i] = pcmd->maxqdepth[i];
			}
			qm_context_ctl->qdepth_change_flag = 1;

			/* TODO Update CEETM */
			break;
		}
					// set weight parameters
		case CMD_QM_MAX_WEIGHT:
		{
			PQosWeightCommand pcmd = (PQosWeightCommand)p;
			
			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				rtncode = CMD_ERR;
				break;
			}

			qm_context_ctl = QM_GET_CONTEXT(port_info->index);
			qm_context_ctl->port_info = port_info;

			for (i = 0; i < NUM_QUEUES; i++) {
				if (pcmd->weight[i] > 0)
				{
#ifdef QM_DEBUG
					printk(KERN_INFO "Setting qweight: port=%s, queue=%d, weight=%d\n", pcmd->ifname, i, pcmd->weight[i]);
#endif
					qm_context_ctl->weight[i] = pcmd->weight[i];
				}
			}
			qm_context_ctl->qweight_change_flag = 1;
			/* TODO Update CEETM */
			break;
		}

		// set exception handler rate limit
		case CMD_QM_EXPT_RATE:
		{
			printk(KERN_INFO " %s:%d This command not yet implemented/poted\n", __func__, __LINE__);
			rtncode = CMD_ERR;
			break;
		}

		case CMD_QM_QUERY:
		{
		       pQosQueryCmd pcmd = (pQosQueryCmd)p;
#ifdef QM_DEBUG
		       printk(KERN_INFO "QUERY command received %d - cmdlen %d -  size %lu\n", cmd_code, cmd_len, sizeof(QosQueryCmd));
#endif
		       if ((long unsigned int)cmd_len != sizeof(QosQueryCmd))
		       {
			       rtncode = CMD_ERR;
			       break;
		       }
		       QM_Get_Info(pcmd);
		       retlen = sizeof(QosQueryCmd);

		       break;
		}

		case CMD_QM_QUERY_PORTINFO:
		{
			pQosQueryPortInfoCmd pcmd = (pQosQueryPortInfoCmd)p;
			if (cmd_len != sizeof(QosQueryPortInfoCmd))
			{
			       printk(KERN_INFO "CMD_QM_QUERY_PORTINFO cmd_len=%d, expected= %lu\n", cmd_len, sizeof(QosQueryPortInfoCmd));
			       rtncode = CMD_ERR;
			       break;
			}
			
			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				pcmd->queue_qosenable_mask = 0;
			}
			else 
			{
				qm_context_ctl = QM_GET_CONTEXT(port_info->index);
				pcmd->queue_qosenable_mask = qm_context_ctl->qos_enabled ? 0xffffffff:0;
				pcmd->ifg = qm_context_ctl->ifg;
			}

			pcmd->max_txdepth = 0;
			pcmd->unused = 0;
			retlen = sizeof(QosQueryPortInfoCmd);
			break;
		}

		case CMD_QM_QUERY_QUEUE:
		{
			U16 qweight = 0;
			U32 qnum;
			pQosQueryQueueCmd pcmd = (pQosQueryQueueCmd)p;
			if (cmd_len != sizeof(QosQueryQueueCmd))
			{
			       rtncode = CMD_ERR;
			       break;
			}
			
			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				pcmd->qweight = 0;
				pcmd->max_qdepth = 0;
			}
			else 
			{
				qm_context_ctl = QM_GET_CONTEXT(port_info->index);
				qnum = pcmd->queue_num;
				
				if ((qm_context_ctl->qmask & (1 << qnum)) && (qnum > 7))
					qweight = qm_context_ctl->weight[qnum];

				pcmd->qweight = qweight ? qweight : 1;
				pcmd->max_qdepth = qm_context_ctl->max_qdepth[qnum];
			}
			retlen = sizeof(QosQueryQueueCmd);

			break;
		}

		case CMD_QM_QUERY_SHAPER:
		{
			U32 shaper_num;
			pQosQueryShaperCmd pcmd = (pQosQueryShaperCmd)p;
			if (cmd_len != sizeof(QosQueryShaperCmd))
			{
			       rtncode = CMD_ERR;
			       break;
			}
			
			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				pcmd->enabled = 0;
				pcmd->unused = 0;
				pcmd->qmask = 0;
				pcmd->rate = 0;
				pcmd->bucket_size = 0;
				retlen = sizeof(QosQueryShaperCmd);
				break;
			}

			qm_context_ctl = QM_GET_CONTEXT(port_info->index);
			
			shaper_num = pcmd->shaper_num;
			if (shaper_num == PORT_SHAPER_NUM)
			{
				//shaper_num = PORT_SHAPER_INDEX;
				pcmd->enabled = qm_context_ctl->shaper_enable;
				pcmd->unused = 0;
				pcmd->qmask = qm_context_ctl->qmask;
				pcmd->rate = qm_context_ctl->shaper_rate;
				pcmd->bucket_size = qm_context_ctl->bucket_size;
			}
			else
			{
				pcmd->enabled = 0;
				pcmd->unused = 0;
				pcmd->qmask = 0;
				pcmd->rate = 0;
				pcmd->bucket_size = 0;
			}
			retlen = sizeof(QosQueryShaperCmd);
			break;
		}

		case CMD_QM_QUERY_SCHED:
		{
		//	PQM_SchedDesc psched;
			pQosQuerySchedCmd pcmd = (pQosQuerySchedCmd)p;
			if (cmd_len != sizeof(QosQuerySchedCmd))
			{
			       rtncode = CMD_ERR;
			       break;
			}
			
			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				pcmd->qmask = 0;
			}
			else
			{
				qm_context_ctl = QM_GET_CONTEXT(port_info->index);
				pcmd->qmask = qm_context_ctl->qmask;
			}
			
		//	psched = &qm_context_ctl->sched[pcmd->sched_num];
			pcmd->alg = 0;
			pcmd->unused = 0;
			retlen = sizeof(QosQuerySchedCmd);
			break;
		}
		case CMD_QM_QUERY_EXPT_RATE:
		{
			printk(KERN_INFO " %s:%d This command not yet implemented/poted\n", __func__, __LINE__);
			rtncode = CMD_ERR;
			break;
		}


		case CMD_QM_RESET:
		{
			printk(KERN_INFO " %s:%d This command not yet implemented/poted\n", __func__, __LINE__);
			rtncode = CMD_ERR;
			break;
		}

		case CMD_QM_SHAPER_CONFIG:
		{
			U32 shaper_num; 
			//U8 *ptr = (U8  *)p;
			PQosShaperConfigCommand pcmd = (PQosShaperConfigCommand)p;
			
#if 0
			for( ii = 0; ii < sizeof (QosShaperConfigCommand); ii++) 
				printk(KERN_INFO " %02x ", ptr[ii]);	
				
			printk(KERN_INFO "\n");	
#endif
			
			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				rtncode = CMD_ERR;
				break;
			}

			qm_context_ctl = QM_GET_CONTEXT(port_info->index);
			qm_context_ctl->port_info = port_info;

			shaper_num = pcmd->shaper_num;
			if (!(shaper_num == PORT_SHAPER_NUM))
			{
				printk(KERN_INFO " %s:%d Only port shaper is supported \n", __func__, __LINE__);
				rtncode = CMD_ERR;
				break;
			}
			
			if (pcmd->ifg_change_flag)
				qm_context_ctl->ifg = pcmd->ifg + 4;	// add 4 to account for FCS

#if 0				
			for( ii = 0; ii < sizeof (QosShaperConfigCommand); ii++) 
				printk(KERN_INFO " %02x ", ptr[ii]);	
				
			printk(KERN_INFO "\n");	
			printk(KERN_INFO " %s:%d rate %d ifg %d bucket_size %d \n", __func__, __LINE__, pcmd->rate, pcmd->ifg , pcmd->bucket_size);
#endif

			if (pcmd->rate)
			{
				U32 bucket_size;

				qm_context_ctl->shaper_rate = pcmd->rate;
				bucket_size = pcmd->bucket_size;
				qm_context_ctl->bucket_size = bucket_size;
				if (bucket_size == 0)
					bucket_size = pcmd->rate/8;  // default bucket size is bytes per msec
			}
			
			qm_context_ctl->num_hw_shapers = 1;
			qm_context_ctl->shaper_change_flag = 1;
			qm_context_ctl->shaper_enable = pcmd->enable_disable_control;
			break;
		}

		case CMD_QM_SCHEDULER_CONFIG:
		{
			U32 sched_num;
			U32 qmask;
			U32 numqueues;
			PQosSchedulerConfigCommand pcmd = (PQosSchedulerConfigCommand)p;

			if (!(port_info = get_dpa_port_info(pcmd->ifname)))
			{
				rtncode = CMD_ERR;
				break;
			}

			qm_context_ctl = QM_GET_CONTEXT(port_info->index);
			qm_context_ctl->port_info = port_info;

			sched_num = pcmd->sched_num;
			if (sched_num >= NUM_SCHEDULERS)
			{
				rtncode = CMD_ERR;
				break;
			}

			qmask = pcmd->qmask | qm_context_ctl->qmask;
			numqueues = 0;

			while(qmask)
			{
				i = FFS(qmask);
				numqueues++;
				qmask &= ~(1 << i);
			}

			if (numqueues > MAX_SCHEDULER_QUEUES)
			{
				rtncode = CMD_ERR;
				break;
			}

			if (qm_context_ctl->qmask ^ pcmd->qmask)
				qm_context_ctl->sched_change_flag = 1;
			else	
				qm_context_ctl->sched_change_flag = 0;

			if (qm_context_ctl->qmask)
				qm_context_ctl->num_sched = 1;

			qm_context_ctl->qmask |= pcmd->qmask;



			break;
		}

		case CMD_QM_DSCP_QM:
		{
			printk(KERN_INFO " %s:%d This command not yet implemented/poted\n", __func__, __LINE__);
			rtncode = CMD_ERR;
			//			rtncode = QM_Handle_DSCP_QueueMod(p, cmd_len);
			break;
		}

		// unknown command code
		default:
		{
			rtncode = CMD_ERR;
			break;
		}
	}

	*p = rtncode;
#ifdef QM_DEBUG
	if (rtncode != 0)
		printk(KERN_INFO "%s: Command error, rtncode=%d", __func__, (short)rtncode);
#endif
	return retlen;
}

/** QOS init function.
 * This function initializes the qos control context with default configuration
 * and sends the same configuration to TMU.
 *
 */
int qm_init()
{
	int i;
	PQM_context_ctl qmCtx;
	
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);

	set_cmd_handler(EVENT_QM,M_qm_cmdproc);
//	set_cmd_handler(EVENT_EXPT,M_expt_cmdproc);

	for (i = 0; i < GEM_PORTS; i++)
	{
		qmCtx = &gQMCtx[i];

		memset(qmCtx, 0, sizeof(QM_context_ctl));
	//	qmCtx->port = i;
		qmCtx->num_hw_shapers = 1;
		qmCtx->num_sched = 1;
		qmCtx->qmask = 0;

			/*TODO Initialize CEETM */
	}
        
	cdx_ceetm_init();
	INIT_LIST_HEAD(&Qos_list);
        RegisterCEETMHandler(cdx_ceetm_get_queue);

	return NO_ERR;
}
/** QOS exit function.
*/
void qm_exit(void)
{

}

