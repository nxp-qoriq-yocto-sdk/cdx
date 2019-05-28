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


/* OS abstraction functions used by CDX control code */

#include "cdx.h"

HostMessage msg_buf;
static int msg_buf_used = 0;


HostMessage *msg_alloc(void)
{
	if (msg_buf_used)
	{
		printk(KERN_ERR "%s: failed\n", __func__);
		return NULL;
	}

	msg_buf_used = 1;

	return &msg_buf;
}

void msg_free(HostMessage *msg)
{
	if (!msg_buf_used)
		printk(KERN_ERR "%s: freing already free msg buffer\n", __func__);

	msg_buf_used = 0;
}

int msg_send(HostMessage *msg)
{
	struct _cdx_ctrl *ctrl = &cdx_info->ctrl;
	int rc = -1;

	if (!ctrl->event_cb)
		goto out;

	if (ctrl->event_cb(msg->code, msg->length, msg->data) < 0)
		goto out;

	rc = 0;

out:
	msg_free(msg);

	return rc;
}


void *Heap_Alloc(int size)
{
	/* FIXME we may want to use dma API's and use non cacheable memory */
	return kmalloc(size, GFP_KERNEL);
}


void Heap_Free(void *p)
{
	kfree(p);
}
