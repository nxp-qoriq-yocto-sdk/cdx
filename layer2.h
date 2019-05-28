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



#ifndef _LAYER2_H_
#define _LAYER2_H_

#include "types.h"
#include "list.h"
#include "fe.h"
#include "system.h"

/**************************************************
* Layer 2 Management 
*
***************************************************/

#define FMAN_IDX		0

#define L2_MAX_ONIF		255
#define L2_INVALID_ONIF		L2_MAX_ONIF

#define INTERFACE_NAME_LENGTH	16

/* FLAGS */
//Routing cache entry
#define UNICAST_L2_HEADER_SIZE	26	// 14 (eth) + 4 (vlan) + 8 (pppoe)

// INTERFACE FLAGS
#define ENTRY_VALID	0x80

#define	IF_TYPE_ETHERNET	(1 << 0)
#define	IF_TYPE_VLAN		(1 << 1)
#define	IF_TYPE_PPPOE		(1 << 2)
#define	IF_TYPE_TUNNEL		(1 << 3)
#define	IF_TYPE_MACVLAN		(1 << 4)
#define IF_TYPE_WLAN		(1 << 5)
#define IF_TYPE_L2TP		(1 << 6)
#define IF_TYPE_PHYSICAL	(1 << 7)
//The following definition will not be used in if structures
//defined here as others are also used in the dpaoffload layers.
#define IF_TYPE_OFPORT		(1 << 8)
#define IF_STATS_ENABLED	(1 << 10)


typedef struct _tRouteEntry {
	struct slist_entry list;
	U16 nbref;
	U16 id;
	struct _itf *itf;
	U8 dstmac[ETHER_ADDR_LEN];
	U16 mtu;
	U16 flags;
	U16 onif_index;
	union
	{
		U32 Daddr_v4;
		U32 Daddr_v6[4];
	};
	struct _itf *input_itf;
	struct _itf *underlying_input_itf;
}RouteEntry, *PRouteEntry;


#define RT_F_EXTRA_INFO 0x1

#define IS_NULL_ROUTE(pRoute) (!(pRoute))
/* In the case of C2000 control or C2000 the structures hw_route and hw_route_4o6 are the same  
till the  first word of the Dstn address, so we can safely typecast the route to type hw_route *
and pass the address of Daddr_v4, even for the 4o6 case. */

#define ROUTE_EXTRA_INFO(rt) ((void *)(&(rt)->Daddr_v4))


typedef struct tOnifDesc {
	U8	name[IF_NAME_SIZE];	// interface name string as managed by linux
	struct _itf *itf;

	U8	flags;
}OnifDesc, *POnifDesc;

extern OnifDesc gOnif_DB[] __attribute__((aligned(32))) ;

PRouteEntry L2_route_get(U32 id);
void L2_route_put(PRouteEntry pRtEntry);
PRouteEntry L2_route_find(U32 id);
int L2_route_remove(U32 id);
PRouteEntry L2_route_add(U32 id, int info_size);


POnifDesc get_onif_by_name(U8 *itf_name);
POnifDesc add_onif(U8 *input_itf_name, struct _itf *itf, struct _itf *phys_itf, U8 type);
void remove_onif_by_name(U8 *itf_name);
void remove_onif_by_index(U32 if_index);
void remove_onif(POnifDesc onif_desc);
U16 itf_get_phys_port(struct _itf *itf);



/**
 * get_onif_by_index()
 *
 *
 */
static __inline POnifDesc get_onif_by_index(U16 index)
{
	return  &gOnif_DB[index];
}

/**
 * get_onif_index()
 *
 *
 */
static __inline U32 get_onif_index(POnifDesc onif_desc)
{
	return onif_desc - &gOnif_DB[0];
}

/**
 * get_onif_name()
 *
 *
 */
static __inline char *get_onif_name(U16 onif_index)
{
	return (char *)gOnif_DB[onif_index].name;
}


static __inline void rte_set_mtu(PRouteEntry prte,U16 mtu) {
  prte->mtu = mtu == 0 ? 0xFFFF : mtu;
}


#endif /* _LAYER2_H_ */

