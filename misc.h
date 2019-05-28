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
 * @file                misc.h
 * @description         helper and other macros  
 */ 

#ifndef MISC_H
#define MISC_H 1

#include "types.h"
#include "fe.h"

#define SUCCESS                 0
#define FAILURE                 -1

//#define CDX_DPA_DEBUG

#define DPA_ERROR(fmt, ...)\
{\
	printk(KERN_CRIT fmt, ## __VA_ARGS__);\
}
#ifdef CDX_DPA_DEBUG
#define DPA_INFO(fmt, ...)\
{\
	printk(KERN_INFO fmt, ## __VA_ARGS__);\
}
#else
#define DPA_INFO(fmt, ...)
#endif // CDX_DPA_DEBUG
#define DPA_PACKED __attribute__ ((packed))

static inline void display_ipv4_addr(uint32_t addr)
{
	printk("%pI4\n", &addr);
}

static inline void display_ipv6_addr(uint8_t *addr)
{
	printk("%pI6c\n", (void *)addr);
}

static inline void display_mac_addr(uint8_t *addr)
{
	printk("%pM\n", (void *)addr);
}

static inline void display_buff_data(uint8_t *ptr, uint32_t len)
{
        uint32_t ii;
        for (ii = 0; ii < len; ii++) {
                if ((ii % 16) == 0)
                        printk("\n");
                printk("%02x ", *(ptr + ii));
        }
	printk("\n");
}

//required by dpa_offload ip address
#define TYPE_IP4	4
#define TYPE_IPV6	6

#define DPA_UNUSED __attribute__((unused))


//used for PCD FQ creation
#define NUM_PKT_DATA_LINES_IN_CACHE     2
#define NUM_ANN_LINES_IN_CACHE          1


#endif
