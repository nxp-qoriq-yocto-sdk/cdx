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


#ifndef _GLOBALS_H_
#define _GLOBALS_H_

// The main module sets DEFINE_GLOBALS

#ifdef DEFINE_GLOBALS
#define GLOBAL_DEFINE
#define GLOBAL_INIT(x) = (x)
#else
#define GLOBAL_DEFINE extern
#define GLOBAL_INIT(x)
#endif

// Global variables

GLOBAL_DEFINE struct _cdx_info *cdx_info;
GLOBAL_DEFINE int ff_enable GLOBAL_INIT(1);
GLOBAL_DEFINE U32 udp_unidir_timeout;
GLOBAL_DEFINE U32 udp_bidir_timeout;
GLOBAL_DEFINE U32 tcp_timeout;
GLOBAL_DEFINE U32 other_proto_timeout;
GLOBAL_DEFINE U32 udp_4o6_unidir_timeout;
GLOBAL_DEFINE U32 udp_4o6_bidir_timeout;
GLOBAL_DEFINE U32 tcp_4o6_timeout;
GLOBAL_DEFINE U32 other_4o6_proto_timeout;

GLOBAL_DEFINE OnifDesc gOnif_DB[L2_MAX_ONIF+1] __attribute__((aligned(32)));
GLOBAL_DEFINE struct physical_port phy_port[MAX_PHY_PORTS];
GLOBAL_DEFINE struct slist_head rt_cache[NUM_ROUTE_ENTRIES] __attribute__((aligned(32)));
GLOBAL_DEFINE struct slist_head ct_cache[NUM_CT_ENTRIES] __attribute__((aligned(32)));
GLOBAL_DEFINE struct slist_head vlan_cache[NUM_VLAN_ENTRIES];
GLOBAL_DEFINE struct slist_head pppoe_cache[NUM_PPPOE_ENTRIES];
GLOBAL_DEFINE struct slist_head tunnel_name_cache[NUM_TUNNEL_ENTRIES];

#define phy_port_get(port)      (&phy_port[port])

#endif /* _GLOBALS_H_ */
