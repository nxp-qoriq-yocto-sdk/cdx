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



#ifndef _CONTROL_PPPOE_H_
#define _CONTROL_PPPOE_H_

#include "cdx_common.h"
#include "control_bridge.h"

#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_IPV6CP	0x8057	/* IPv6 Control Protocol */
#define PPP_PAP		0xc023
#define PPP_CHAP	0xc223

#define PPPOE_TIMER_PERIOD	(1 * HZ)

#define PPPOE_AUTO_MODE  	0x1

typedef struct tPPPoEFrame {
    U16        PPPoE_VerTypeCode;
    U16        PPPoE_SessionID;
    U16        PPPoE_Length;
    U16        PPPoE_Protocol;
    U8         PPPoE_Payload[];
} PPPoEFrame, *pPPPoEFrame;

/* HW Entry for PPPOE Relay Key */
struct pppoe_relay_hw_entry {
	struct L2Flow l2flow;
	char   in_ifname[IF_NAME_SIZE]; /* used by the other session */
	U8     SrcMAC[ETHER_ADDR_LEN];  /* used by the other session */
	struct hw_ct *ct;
};

typedef struct _tPPPoE_Info {
	itf_t itf;

	struct slist_entry list;
	struct _tPPPoE_Info *relay;

	/* store following two items in network order */
	U8 DstMAC[ETHER_ADDR_LEN];
	U16 sessionID;

	TIMER_ENTRY timer;
	U32 ppp_flags;
	U32 last_pkt_rcvd;
	U32 last_pkt_xmit;
	U32 total_packets_received;
	U32 total_packets_transmitted;

	/* HW Details */
	struct pppoe_relay_hw_entry hw_entry;
} PPPoE_Info, *pPPPoE_Info; 

typedef struct _tPPPoECommand {
    U16 action;
    U16 sessionID;
    U8  macAddr[6];
    U8  phy_intf[IF_NAME_SIZE];
    U8  log_intf[IF_NAME_SIZE];
    U16 mode;
} PPPoECommand, *pPPPoECommand;

typedef struct _tPPPoERelayCommand {
    U16 action;      /*Action to perform */
    U8 peermac1[6];
    U8 peermac2[6];
    U8 ipif_mac[6];
    U8 opif_mac[6];
    U8 ipifname[IF_NAME_SIZE];
    U8 opifname[IF_NAME_SIZE];
    U16 sesID;
    U16 relaysesID;
    U16 pad;
}PPPoERelayCommand, *pPPPoERelayCommand;

typedef struct _tPPPoEIdleTimeCmd {
    U8  ppp_intf[IF_NAME_SIZE];
    U32  xmit_idle;
    U32  recv_idle;
  } PPPoEIdleTimeCmd, *pPPPoEIdleTimeCmd;



int pppoe_init(void);
void pppoe_exit(void);

static __inline U32 HASH_PPPOE(U16 session_id, U8 *srcmac)
{
	return ((session_id & 0xff) ^ (session_id >> 8) ^ srcmac[5]) & (NUM_PPPOE_ENTRIES - 1);
}

#endif /* _CONTROL_PPPOE_H_ */
