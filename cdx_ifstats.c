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
 * @file                ifstats.c     
 * @description         interface statistics management routines.
 */

#include "fm_muram_ext.h"
#include "dpaa_eth.h"
#include "fm_ehash.h"
#include "cdx_ioctl.h"
#include "misc.h"
#include "layer2.h"
#include "portdefs.h"
#include "fm_muram_ext.h"

#ifdef INCLUDE_IFSTATS_SUPPORT

//uncomment to enable debug prints fron this file
//#define IFSTATS_DEBUG	1

extern void *get_muram_data(uint32_t *size);

//base of stats area
static void *stats_mem;
//stats area phys addr
uint32_t stats_mem_phys;
//free lists will be manipulated under device locks
//free list all interface other than PPPoE
struct cdx_iface_stats *ifstats_freelist;
//free list for pppoe
struct cdx_pppoe_iface_stats *pppoe_ifstats_freelist;

extern void *FmMurambaseAddr;

//allocate muram and create free lists
int cdxdrv_init_stats(void *muram_handle)
{
	uint32_t ii;
	uint32_t num_log_ifaces;
	struct cdx_pppoe_iface_stats *pppoe_stats;
	struct cdx_iface_stats *ifstats;

	stats_mem = FM_MURAM_AllocMem(muram_handle, 
			(MAX_LOGICAL_INTERFACES * sizeof(struct cdx_iface_stats)), 
			sizeof(uint64_t));
	if (!stats_mem) {
		printk("%s::unable to allocate muram for iface stats, size %ld\n", 
				__FUNCTION__,
				(MAX_LOGICAL_INTERFACES * sizeof(struct cdx_iface_stats)));
		return -1;
	}
	stats_mem_phys = (uint32_t)((uint8_t *)stats_mem - (uint8_t *)FmMurambaseAddr);
#ifdef IFSTATS_DEBUG
	printk("%s::ifstats mem base %p phys %x size %ld\n", __FUNCTION__, stats_mem, stats_mem_phys,
			(MAX_LOGICAL_INTERFACES * sizeof(struct cdx_iface_stats)));
	//fill pppoe stats free lists
	printk("%s::pppoe ifstats at %p\n", __FUNCTION__, stats_mem);
#endif
	pppoe_ifstats_freelist = (struct cdx_pppoe_iface_stats *)stats_mem;
	pppoe_stats = pppoe_ifstats_freelist;
	for (ii = 0; ii < MAX_PPPoE_INTERFACES; ii++) {
		if (ii != (MAX_PPPoE_INTERFACES - 1))
			pppoe_stats->next = (pppoe_stats + 1);
		else
			pppoe_stats->next = NULL;
		pppoe_stats++;
	}
	//align iface stats on suitable boundary 
	ii = ((sizeof(struct cdx_pppoe_iface_stats) * MAX_PPPoE_INTERFACES) / sizeof(struct cdx_iface_stats));
	if ((sizeof(struct cdx_pppoe_iface_stats) * MAX_PPPoE_INTERFACES) % sizeof(struct cdx_iface_stats)) 
		ii++;
	ifstats = (struct cdx_iface_stats *)pppoe_stats;
	//calculate space remaining for other logical interfaces
	num_log_ifaces = (MAX_LOGICAL_INTERFACES - ii); 
#ifdef IFSTATS_DEBUG
	printk("%s::ifstats at %p max log ifaces %d\n", __FUNCTION__, ifstats,
		num_log_ifaces);
#endif
	ifstats_freelist = ifstats;
	//fill other iface stats free lists
	for (ii = 0; ii < num_log_ifaces; ii++) {
		if (ii != (num_log_ifaces - 1))
			ifstats->next = (ifstats + 1);
		else
			ifstats->next = NULL;
		ifstats++;
	} 
	return 0;
	//t_Error FM_MURAM_FreeMem(t_Handle h_FmMuram, void *ptr)
}

//should be called under dev lock
void *alloc_iface_stats(uint32_t dev_type, uint8_t *rx_offset, uint8_t *tx_offset)
{
	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_stats *pppoe_stats;
		pppoe_stats = pppoe_ifstats_freelist;
		if (pppoe_stats) {
			pppoe_ifstats_freelist = pppoe_stats->next;
			memset(pppoe_stats, 0, sizeof(struct cdx_pppoe_iface_stats));
			*rx_offset = (((uint32_t)((uint8_t *)&pppoe_stats->stats.rxstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats_with_ts)) | STATS_WITH_TS);
			*tx_offset = (((uint32_t)((uint8_t *)&pppoe_stats->stats.txstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats_with_ts)) | STATS_WITH_TS);
#ifdef IFSTATS_DEBUG
			printk("%s::allocated pppoe stats %p, rx_offset %x tx_offset %x\n", 
				__FUNCTION__, pppoe_stats, *rx_offset, *tx_offset);
#endif
		}
		return pppoe_stats;
	} else {
		struct cdx_iface_stats *ifstats;
		ifstats = ifstats_freelist;
		if (ifstats) {
			ifstats_freelist = ifstats->next;
			memset(ifstats, 0, sizeof(struct cdx_iface_stats));	
			*rx_offset = ((uint32_t )((uint8_t *)&ifstats->stats.rxstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats));
			*tx_offset = ((uint32_t )((uint8_t *)&ifstats->stats.txstats - 
					(uint8_t *)stats_mem) /
					sizeof(struct en_ehash_stats));
#ifdef IFSTATS_DEBUG
			printk("%s::rxstats %p, txstats %p, mem %p\n", __FUNCTION__,
					&ifstats->stats.rxstats,
					&ifstats->stats.txstats,
					stats_mem);
			printk("%s::allocated stats %p, rxoffset %x txoffet %x\n", __FUNCTION__, 
				ifstats, *rx_offset, *tx_offset);
#endif
		}
		return ifstats;
	}
}

void free_iface_stats(uint32_t dev_type, void *stats)
{	
	if (dev_type == IF_TYPE_PPPOE) {
		struct cdx_pppoe_iface_stats *pppoe_stats;
		pppoe_stats = (struct cdx_pppoe_iface_stats *)stats;
		pppoe_stats->next = pppoe_ifstats_freelist;
		pppoe_ifstats_freelist = pppoe_stats;
	} else {
		struct cdx_iface_stats *ifstats;
		ifstats = (struct cdx_iface_stats *)stats;
		ifstats->next = ifstats_freelist;
		ifstats_freelist = ifstats;
	}
}

uint32_t get_logical_ifstats_base(void)
{
	return (stats_mem_phys);
}
#else
int cdxdrv_init_stats(void *muram_handle) 
{
	printk("%s::interface statistics module disabled\n", __FUNCTION__);
	return SUCCESS;	
}
void *alloc_iface_stats(uint32_t dev_type, uint8_t *rx_offset, uint8_t *tx_offset)
{
	printk("%s::interface statistics disabled for type %x\n", 
			__FUNCTION__, dev_type);
	return FAILURE;	
}
void free_iface_stats(uint32_t dev_type, void *stats)
{
	printk("%s::interface statistics disabled for type %x\n",
			__FUNCTION__, dev_type);

}
uint32_t get_logical_ifstats_base(void)
{
	printk("%s::interface statistics disabled for all types\n", 
		__FUNCTION__);
	return 0;
}
#endif

