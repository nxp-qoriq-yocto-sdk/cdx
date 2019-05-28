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

#ifndef _CDX_CTRL_H_
#define _CDX_CTRL_H_

struct _cdx_ctrl {
	struct mutex mutex;
	spinlock_t lock;

	void *dma_pool_256;
	void *dma_pool_512;

	struct device *dev;

	struct task_struct *timer_thread;
	struct hlist_head *timer_inner_wheel;
	struct hlist_head *timer_outer_wheel;

	int (*event_cb)(u16, u16, u16*);

	struct list_head msg_list;
	struct work_struct work;	
};

struct _cdx_info {
	unsigned long ddr_phys_baseaddr;
	void *ddr_baseaddr;
	unsigned int ddr_size;
	void *cbus_baseaddr;
	void *apb_baseaddr;
	struct device dev;
	struct _cdx_ctrl ctrl;
};

extern struct _cdx_info *cdx_info;

/* used for asynchronous message transfer to CDX */
#define FPP_MAX_MSG_LENGTH	256 /* expressed in U8 -> 256 bytes*/
struct fpp_msg {
        struct list_head list;
        void (*callback)(unsigned long, int, u16, u16 *);
        unsigned long data;
        u16 fcode;
        u16 length;
        u16 *payload;
};

#endif /* _CDX_CTRL_H_ */
