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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <net/pkt_sched.h>

#include <linux/skbuff.h>
#include <linux/fsl_qman.h>
#include "cdx.h"


/**********************************************************************************************************************
 DEBUG definitions
***********************************************************************************************************************/
//#define CEETM_DEBUG
#define CEETM_SCH_DEBUG

#define CEETM_SUCCESS  0
#define CEETM_FAILURE  -1

/*sub portal index of DPAA 1G port = cell index + 2*/
#define CEETM_OFFSET_1G  2
/*sub portal index of DPAA OH port = cell index + 9*/
#define CEETM_OFFSET_OH  9

#define ceetm_err(fmt, arg...)  \
  printk(KERN_ERR"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
  __LINE__, __func__, ##arg)

#if 0
#define ceetm_dbg(fmt, arg...)  \
  printk(KERN_INFO"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
  __LINE__, __func__, ##arg)
#else
#define ceetm_dbg(fmt, arg...)
#endif
//#ifdef CEETM_SCH_DEBUG
#if 1
#define ceetm_sch_dbg(fmt, arg...)  \
  printk(KERN_INFO"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
  __LINE__, __func__, ##arg)
#else
#define ceetm_sch_dbg(fmt, arg...)
#endif

/* Mask to determine the sub-portal id from a channel number */
#define CHANNEL_SP_MASK		0x1f
/* The number of the last channel that services DCP0, connected to FMan 0.
 * Value validated for B4 and T series platforms.
 */
#define DCP0_MAX_CHANNEL	0x80f

/**********************************************************************************************************************
Structure and Macro definitions
**********************************************************************************************************************/
#define MAX_CEETM 2

#define CDX_CEETM_MAX_LNIS                      8
#define CDX_CEETM_MAX_CHANNELS                 32
#define CDX_CEETM_MAX_QUEUES_PER_CHANNEL       16
#define CDX_CEETM_MAX_SP_QUEUES_PER_CHANNEL    10
#define CDX_CEETM_MAX_SP_CQS_PER_CHANNEL        8
#define CDX_CEETM_MAX_WBFS_QUEUES_PER_CHANNEL   8

#define CEETM_WBFS_MIN_Q        4
#define CEETM_WBFS_MAX_Q        8
#define VQA_DPAA_VAL_TO_RELEASE_BUFFER 0x9200000080000000ull

typedef enum
{
  CEETM_WBFS_GRP_A=1,
  CEETM_WBFS_GRP_B,
  CEETM_WBFS_GRP_BOTH,
  CEETM_WBFS_GRP_A_SINGLE_Q,
  CEETM_WBFS_GRP_B_SINGLE_Q,
}wbfs_grp_type;

typedef struct cdx_ceetm_lni_params_s
{
  bool shaping_en;   /* enable shaping on this lni */
  unsigned long long int rate; /* Committed Rate  */
  unsigned long long int ceil; /* Excess Rate */
  unsigned int mpu; /* Minimum Packet Size */
  unsigned int token_limit;
  unsigned int overhead; /* Required for Shaping */
} cdx_ceetm_lni_params_t;

typedef struct cdx_ceetm_channel_params_s
{
  bool shaping_en;
  union
  {
    struct cdx_shaper_node 
    {
      unsigned long long int rate;
      unsigned long long int ceil;
      unsigned int token_limit;
    }shaper;
    struct cdx_unshaped_node
    {
      unsigned short int cr_eligible[8];
      unsigned short int er_eligible[8]; /* This should be at group level  */
      unsigned short int weight;
    }wbfs;
  };
} cdx_ceetm_channel_params_t;

typedef struct cdx_ceetm_prio_params
{
  unsigned char cr_eligible;
  unsigned char er_eligible;  
}cdx_ceetm_prio_params_t;

typedef struct cdx_ceetm_wfq_params
{
  unsigned int  weight;
}cdx_ceetm_wbfs_params_t;

typedef struct cdx_ceetm_queue_ctxt_s
{
  unsigned int idx;
  struct qm_ceetm_cq *cq;
  struct ceetm_fq *fq;  
  union
  {
    struct prio_queue_s
    {
      cdx_ceetm_prio_params_t params;
    }prio;
    struct wbfs_queue_s
    {
      char                    grp_type;
      cdx_ceetm_wbfs_params_t params;
    }wbfs;
  };
  char valid;
  char is_prio_queue;
}cdx_ceetm_queue_ctxt_t;

typedef struct cdx_ceetm_channel_ctxt_s
{
  void *pChannel;
  cdx_ceetm_channel_params_t params;
  cdx_ceetm_queue_ctxt_t *pQueues[CDX_CEETM_MAX_QUEUES_PER_CHANNEL];
}cdx_ceetm_channel_ctxt_t;

typedef struct cdx_ceetm_lni_ctxt_s
{
  struct list_head list;
  unsigned int fman_id;
  unsigned int port_id;
  unsigned int port_type;
  struct qm_ceetm_lni *lni;
  cdx_ceetm_lni_params_t shaper;
  cdx_ceetm_channel_ctxt_t *pChannels[CDX_CEETM_MAX_CHANNELS];
  unsigned int uiNoOfChannels;
  char name[CDX_CTRL_PORT_NAME_LEN];
}cdx_ceetm_lni_ctxt_t;


struct ceetm_fq {
  struct net_device  *net_dev;
  int      congested;
  /* Queue Statistics */
  uint64_t    ulEnqueuePkts;  /* Total number of packets received */
  uint64_t    ulDroppedPkts;  /* Total number of packets dropped
            due to Buffer overflow */
  struct qman_fq    egress_fq;
  struct qman_fq    recycle_fq;
};



typedef enum
{
  QOS_CEETM_TAIL_DROP = 1,
  QOS_CEETM_WRED,
}ceetm_cong_alg_e;

#define QOS_CEETM_CS_THRSIN_TA  16
#define QOS_CEETM_CS_THRSIN_TN  1

#define QOS_CEETM_CS_THRSOUT_TA 32
#define QOS_CEETM_CS_THRSOUT_TN 1

typedef struct cdx_ceetm_wred_params
{
  union {
    u32 word;
    struct {
      u32 MA:8;
      u32 Mn:5;
      u32 SA:7; /* must be between 64-127 */
      u32 Sn:6; /* must be between 7-63*/
      u32 Pn:6;
    } __packed;
  };
}cdx_ceetm_wred_params_t;

typedef enum
{
  CEETM_WRED_GREEN =1,
  CEETM_WRED_YELLOW,
  CEETM_WRED_RED,
  CEETM_WRED_MAX_COLOR
}ceetm_wred_color;

typedef struct cdx_ceetm_ccg_out_params
{
  int wred_enable;
  union
  {
    struct
    {
      unsigned int threshold;
      unsigned int cs_threshold_in;
      unsigned int cs_threshold_out;
    }tail_drop;

    struct
    {
      cdx_ceetm_wred_params_t wred[CEETM_WRED_MAX_COLOR];
      unsigned char color;
    }wred;
  };
  unsigned char cong_avoid_alg;
}cdx_ceetm_ccg_out_params_t;

typedef struct ceetm_ccg_wred_s
{
  unsigned int max_threshold;
  unsigned int min_threshold;
  unsigned int uiMaxP;
  unsigned int uiSa;
  unsigned int uiSn;
  unsigned char color;
}ceetm_ccg_wred_t;

#define CEETM_INVALID_INDEX -1
#define CEETM_MAX_FQS_PER_IFACE 512

typedef struct cdx_ceetm_ccg_in_params
{
  union{
    struct 
    {
      unsigned int threshold;
    }tail_drop;
    ceetm_ccg_wred_t wred[3];
  };
  unsigned char cong_avoid_alg;
}cdx_ceetm_ccg_in_params_t;


/**********************************************************************************************************************
   Function Prototypes
**********************************************************************************************************************/
void ceetm_cfg_lni(uint32_t fman_id, uint32_t port_id, uint32_t port_type,
   cdx_ceetm_lni_params_t *pLNIparams,
   void **ppLNI);
void ceetm_cfg_channel(void *handle, 
                             cdx_ceetm_channel_params_t *pChannelparams,
                               void **ppChannel);

int ceetm_cfg_wbfs_grp(void *handle, int  grp, uint32_t pri);
int ceetm_release_lni(void *handle);
int ceetm_release_channel(void *handle, struct net_device *dev);
int ceetm_release_wbfs_cq(void *handle);
void ceetm_release_cq(void *handle);
//int cdx_ceetm_init();
int qman_ceetm_channel_set_cq_cr_eligibility(struct qm_ceetm_channel *channel,
                                         unsigned int idx, int cre);
int qman_ceetm_channel_set_cq_er_eligibility(struct qm_ceetm_channel *channel,
                                         unsigned int idx, int ere);
 

int ceetm_cfg_ccg_to_class_queue(struct qm_ceetm_channel *pChannel, unsigned int iCqNum,
                                 cdx_ceetm_ccg_in_params_t *pCcg_params);

void ceetm_cfg_prio_class_queue(void *handle, cdx_ceetm_queue_ctxt_t *queue_ctxt);

int igwGetFreeLNIIndex( int dcp_id, int interface_type, unsigned int *pIndex);

void igwReleaseLNIIndex( int dcp_id, int interface_type, int index);
void ceetm_cfg_wbfs_class_queue(void *handle, cdx_ceetm_queue_ctxt_t *queue_ctxt);
int cdx_ceetm_get_lfqid(int fmanId, int portId, int queue_no);
int cdx_ceetm_IsShaperEnabled(int fmanId, int portId);

typedef struct qman_fq* (*FnHandler)(struct net_device *net_dev, int queue);
void RegisterCEETMHandler(FnHandler pCeetmGetQueue);
int qman_ceetm_channel_set_group_cr_er_eligibility(void *handle,
                int grp,
                u16 cr_eligibility,
                u16 er_eligibility);
