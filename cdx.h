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

#ifndef _CDX_H_
#define _CDX_H_

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/elf.h>
#include <linux/dmapool.h>
#include <linux/platform_device.h>
#include <asm/byteorder.h>
#include <asm/io.h>
#include "fm_eh_types.h"

//#define CDX_DEBUG_ENABLE

#ifdef CDX_DEBUG_ENABLE
#define DPRINT(fmt, args...) printk(KERN_ERR "%s: " fmt, __func__, ##args)
#else
#define DPRINT(fmt, args...) do { } while(0)
#endif

#define DPRINT_ERROR(fmt, args...) printk(KERN_CRIT "%s: " fmt, __func__, ##args)

#include "types.h"
#include "list.h"
#include "fe.h"
#include "cdx_hal.h"
#include "cdx_common.h"
#include "cdx_ctrl.h"
#include "cdx_ioctl.h"
#include "cdx_timer.h"
#include "cdx_cmdhandler.h"
#include "layer2.h"
#include "globals.h"

#endif /* _CDX_H_ */
