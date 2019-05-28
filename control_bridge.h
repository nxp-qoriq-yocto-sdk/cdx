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



#ifndef _CONTROL_BRIDGE_H_
#define _CONTROL_BRIDGE_H_

#define BR_COMCERTO_2000 1
#include "types.h"
#include "fe.h"


/* Modes */
#define L2_BRIDGE_MODE_MANUAL		0	
#define L2_BRIDGE_MODE_AUTO		1

/* Timer */
#define L2_BRIDGE_DEFAULT_TIMEOUT	30

/* Status */
#define L2_BRIDGE_TIMED_OUT		0x1
#define L2FLOW_UPDATING			(1 << 0)

//flow table bucket head
struct flow_bucket {
        U32 num_entries;        //num entries in this bucket
	struct hlist_head flowlist;
};

extern struct flow_bucket l2flow_hash_table[NUM_BT_ENTRIES];

struct L2Flow {
        U8 da[6];
        U8 sa[6];
        U16 ethertype;
        U16 session_id;
        U16 svlan_tag; /* TCI */
        U16 cvlan_tag; /* TCI */
};

/* control path SW L2 flow entry */
struct L2Flow_entry {
	struct hlist_node node;
	struct L2Flow l2flow;
	cdx_timer_t last_l2flow_timer;
	char out_ifname[IF_NAME_SIZE];
	char in_ifname[IF_NAME_SIZE];
	U16 status;
	U32 hash;
	struct hw_ct *ct;
	TIMER_ENTRY timer;
};

/* L2 Bridging Enable command */
typedef struct _tL2BridgeEnableCommand {
	U16 interface;
	U16 enable_flag;
	U8 input_name[16];
}L2BridgeEnableCommand, *PL2BridgeEnableCommand;

/* L2 Bridging  Flow entry command */
typedef struct _tL2BridgeL2FlowEntryCommand {
	U16		action;				/*Action to perform*/
	U16		ethertype;			/* If VLAN Tag !=0, ethertype of next header */
	U8		destaddr[6];			/* Dst MAC addr */
	U8		srcaddr[6];			/* Src MAC addr */
	U16		svlan_tag; 			/* S TCI */
	U16		cvlan_tag; 			/* C TCI */
	U16		session_id;			/* Meaningful only if ethertype PPPoE */
	U16		pad1;				
	U8		input_name[IF_NAME_SIZE];	/* Input itf name */
	U8		output_name[IF_NAME_SIZE];	/* Output itf name */
	/* L3-4 optional information*/
	U32		saddr[4];
	U32		daddr[4];
	U16		sport;
	U16		dport;
	U8		proto;
	U8		pad;
	U16		mark;
	U32		timeout;
} L2BridgeL2FlowEntryCommand, *PL2BridgeL2FlowEntryCommand;


/* L2 Bridging Query Entry response */
typedef struct _tL2BridgeQueryEntryResponse {
        U16 ackstatus;
        U16 eof;
        U16 input_interface;
        U16 input_svlan;
        U16 input_cvlan;
        U8 destaddr[6];
        U8 srcaddr[6];
        U16 ethertype;
        U16 output_interface;
        U16 output_svlan;
        U16 output_cvlan;
        U16 pkt_priority;
        U16 svlan_priority;
        U16 cvlan_priority;
        U8 input_name[16];
        U8 output_name[16];
        U16 qmod;
        U16 session_id;
}L2BridgeQueryEntryResponse, *PL2BridgeQueryEntryResponse;


/* L2 Bridging Control command */
typedef struct _tL2BridgeControlCommand {
	U16 mode_timeout;		/* Either set bridge mode or set timeout for flow entries */
}L2BridgeControlCommand, *PL2BridgeControlCommand;

/* Function proto */
int bridge_init(void);
void bridge_exit(void);

#endif /* _CONTROL_BRIDGE_H_ */
