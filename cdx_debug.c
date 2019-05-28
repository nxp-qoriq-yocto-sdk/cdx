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
 * @file                cdx_debug.c
 * @description         cdx debug routines.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "misc.h"
#include "layer2.h"
#include "cdx.h"
#include "control_ipv4.h"

//display cdx itf structure
void display_itf(struct _itf *itf)
{
	printk("\nitf entry	\t%p\n", itf);
	printk("type		\t%x\n", itf->type);
	printk("index		\t%d\n", itf->index);
	printk("parent		\t%p\n", itf->phys);
}
EXPORT_SYMBOL(display_itf);

//display cdx route entry
void display_route_entry(PRouteEntry entry)
{
	printk("\nRoute entry	\t%p\n", entry);
	printk("flags 		\t%x\n", entry->flags);
	printk("mtu 		\t%d\n", entry->mtu);
	printk("underlying_input_itf  \t%p\n",entry->underlying_input_itf);
	printk("input_itf  \t%p\n",entry->input_itf);

	printk("dest_mac 	\t");
	display_mac_addr(entry->dstmac);

	if (entry->itf) {
		display_itf(entry->itf);
	} else {
		printk("itf is NULL\n");
	}
}
EXPORT_SYMBOL(display_route_entry);

//display cdx ct entry
void display_ctentry(PCtEntry entry)
{
	printk("<<<<<\nentry	\t%p\n\n", entry);
	printk("status		\t%x\n\n", entry->status);
	if (entry->status & CONNTRACK_ORIG) 
		printk("forward dir, ");
	else
		printk("rev dir, ");
	if (IS_IPV6_FLOW(entry)) {
		printk("ipv6 entry\n");
		printk("source ip	\t");
		display_ipv6_addr((uint8_t *)entry->Saddr_v6);
		printk("dest ip		\t");
		display_ipv6_addr((uint8_t *)entry->Daddr_v6);
		
	} else {
		printk("ipv4 entry\n");
		printk("source ip	\t");
		display_ipv4_addr(entry->Saddr_v4);
		printk("dest ip		\t");
		display_ipv4_addr(entry->Daddr_v4);
	}
	if ((entry->proto == IPPROTOCOL_UDP) ||
	    (entry->proto == IPPROTOCOL_TCP)) {
		printk("protocol	\t%d\n", entry->proto);
		printk("sport		\t%d\n", htons(entry->Sport));
		printk("dport		\t%d\n", htons(entry->Dport));
	}
	printk("twin entry	\t%p\n", entry->twin);
	if (entry->pRtEntry) {
		display_route_entry(entry->pRtEntry);
	} else {
		printk("No route entry\n");
	}
	printk(">>>>>\n");
}
EXPORT_SYMBOL(display_ctentry);

void display_buf(void *buf, uint32_t size)
{
	uint8_t *ptr;
	uint32_t ii;

	ptr = buf;
	for (ii = 0; ii < size; ii++) {
		if ((ii % 16) == 15)
			printk("%02x\n", *ptr);
		else
			printk("%02x ", *ptr);
		ptr++;
	}
	printk("\n");
}

