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


#ifndef _MODULE_QM_H_
#define _MODULE_QM_H_

#include "types.h"
#include <linux/if.h>



#define NUM_QUEUES		16
#define NUM_SCHEDULERS		1
#define MAX_SCHEDULER_QUEUES	16
#define NUM_SHAPERS		1
#define PORT_SHAPER_NUM		0xffff
#define DEFAULT_MAX_QDEPTH 	96


typedef struct tQM_context_ctl {
        struct cdx_port_info *port_info;
	U8 qos_enabled;
	U8 num_hw_shapers;
	U8 num_sched;
	U8 sched_mask;
        U8 ifg;
	U8 qweight_change_flag;
	U8 qdepth_change_flag;
	U8 sched_change_flag;
	U8 shaper_change_flag;
	
	U32 qmask;
        U16 weight[NUM_QUEUES];
        U16 max_qdepth[NUM_QUEUES];
	
	U32 shaper_enable;
	U32 shaper_rate;
	U32 bucket_size;
	U32 lfqid_map[NUM_QUEUES];
} __attribute__((aligned(32))) QM_context_ctl, *PQM_context_ctl;

//#include "pfe_mod.h"

#define QM_GET_CONTEXT(output_port) (&gQMCtx[output_port])
#define QM_GET_QOSOFF_CONTEXT(output_port) (&gQMQosOffCtx[output_port])

// commands
#define QM_ENABLE 	0x1
#define QM_DISABLE 	0x0

#define	QM_INITIAL_ENABLE_STATE	QM_ENABLE

#define EXPT_PORT_ID	GEM_PORTS

#define DEFAULT_EXPT_RATE	1000  /* 10000 packets per msec
					(i.e 1000 packets per usec) */

#define EXPT_CTRLQ_CONFIG	(1 << 0)
#define EXPT_DSCP_CONFIG	(1 << 1)

typedef struct _tQosEnableCommand {
	unsigned char  ifname[IFNAMSIZ];
	unsigned short enable_flag;
}QosEnableCommand, *PQosEnableCommand;

typedef struct _tQueueQosEnableCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short enable_flag;
	unsigned int queue_qosenable_mask; // Bit mask of queues on which Qos is enabled
} __attribute__((__packed__)) QueueQosEnableCommand, *PQueueQosEnableCommand;

typedef struct _tQosSchedulerCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short alg;
}QosSchedulerCommand, *PQosSchedulerCommand;

typedef struct _tQosNhighCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short nhigh;
}QosNhighCommand, *PQosNhighCommand;

typedef struct _tQosMaxtxdepthCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short maxtxdepth;
}QosMaxtxdepthCommand, *PQosMaxtxdepthCommand;

typedef struct _tQosMaxqdepthCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short maxqdepth[NUM_QUEUES];
}QosMaxqdepthCommand, *PQosMaxqdepthCommand;

typedef struct _tQosWeightCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short weight[NUM_QUEUES];
}QosWeightCommand, *PQosWeightCommand;

typedef struct _tQosResetCommand {
	unsigned char ifname[IFNAMSIZ];
}QosResetCommand, *PQosResetCommand;

typedef struct _tQosShaperConfigCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short shaper_num;
	unsigned short enable_disable_control;
	unsigned char ifg;
	unsigned char ifg_change_flag;
	unsigned int rate;
	unsigned int bucket_size;
	unsigned int qmask;
}__attribute__((__packed__)) QosShaperConfigCommand, *PQosShaperConfigCommand;

typedef struct _tQosSchedulerConfigCommand {
	unsigned char ifname[IFNAMSIZ];
	unsigned short sched_num;
	unsigned char alg;
	unsigned char alg_change_flag;
	unsigned short pad;
	unsigned int qmask;
}__attribute__((__packed__)) QosSchedulerConfigCommand, *PQosSchedulerConfigCommand;

typedef struct _tQosExptRateCommand {
	unsigned short expt_iftype; // WIFI or ETH or PCAP
	unsigned short pkts_per_msec;
}QosExptRateCommand, *PQosExptRateCommand;

// Data structure passed from CMM to QM containing Rate Limiting configuration information
typedef struct _tQosRlCommand {
    U8	ifname[IFNAMSIZ];	// Ethernet Port
    U16    action;   // Rate_Limiting On or Off
    U32    mask;     // bit mask of rate-limited queues attached to this combination
    U32	aggregate_bandwidth; //Configured Aggregate bandwidth in Kbps
    U32 	bucket_size; // Configurable bucket Sizes in bytes 
}__attribute__((__packed__)) QosRlCommand;

typedef struct _tQosRlQuery
{
	unsigned short action;
	unsigned short mask;
	unsigned int   aggregate_bandwidth;
	unsigned int   bucket_size;	

} __attribute__((packed)) QosRlQuery,*pQosRlQuery;

typedef struct _tQosQueryCommand
{
	U16 action;
	U8  ifname[IFNAMSIZ];
	U32 queue_qosenable_mask;         // bit mask of queues on which Qos is enabled
	U32 max_txdepth;

	U32 shaper_qmask[NUM_SHAPERS];			// mask of queues assigned to this shaper
	U32 shaper_rate[NUM_SHAPERS];		// shaper rate (Kbps)
	U32 bucket_size[NUM_SHAPERS];		// max bucket size in bytes 

	U32 sched_qmask[NUM_SCHEDULERS];
	U8 sched_alg[NUM_SCHEDULERS];				// current scheduling algorithm
	
	U16 max_qdepth[NUM_QUEUES];
	

}__attribute__((packed)) QosQueryCmd, *pQosQueryCmd;

typedef struct _tQosQueryPortInfoCommand
{
	U16 status;
	U8  ifname[IFNAMSIZ];
	U32 queue_qosenable_mask;		// 0 or 0xFFFFFFFF on C2000
	U16 max_txdepth;			// ignored on C2000
	U8 ifg;					// IFG is per-port on C2000
	U8 unused;
}__attribute__((packed)) QosQueryPortInfoCmd, *pQosQueryPortInfoCmd;

typedef struct _tQosQueryQueueCommand
{
	U16 status;
	U8  ifname[IFNAMSIZ];
	U16 queue_num;
	U16 qweight;
	U16 max_qdepth;
	U16 unused;
}__attribute__((packed)) QosQueryQueueCmd, *pQosQueryQueueCmd;

typedef struct _tQosQueryShaperCommand
{
	U16 status;
	U8  ifname[IFNAMSIZ];
	U16 shaper_num;
	U8 enabled;
	U8 unused;				// no per-shaper IFG on C2000
	U32 qmask;				// mask of queues assigned to this shaper
	U32 rate;				// shaper rate (Kbps)
	U32 bucket_size;			// max bucket size in bytes 
}__attribute__((packed)) QosQueryShaperCmd, *pQosQueryShaperCmd;

typedef struct _tQosQuerySchedCommand
{
	U16 status;
	U8  ifname[IFNAMSIZ];
	U16 sched_num;
	U8 alg;
	U8 unused;
	U32 qmask;				// mask of queues assigned to this scheduler
}__attribute__((packed)) QosQuerySchedCmd, *pQosQuerySchedCmd;

int qm_init(void);
void qm_exit(void);
//u32 qm_read_drop_stat(u32 tmu, u32 queue, u32 *total_drops, int do_reset);
//int qm_cal_shaperwts(u32 rate, PQM_ShaperDesc_ctl shaper_ctl);




#define	NUM_DSCP_VALUES		64

typedef struct _tQoSDSCPQmodCommand {
	unsigned short queue ;
	unsigned short num_dscp;
	unsigned char dscp[NUM_DSCP_VALUES];
}QoSDSCPQmodCommand, *PQoSDSCPQmodCommand;

extern U8 DSCP_to_Qmod[NUM_DSCP_VALUES];
extern U8 DSCP_to_Q[NUM_DSCP_VALUES];


#endif /* _MODULE_QM_H_ */
