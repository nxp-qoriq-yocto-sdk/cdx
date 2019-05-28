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


#include "cdx.h"
#include "control_rx.h"

static U16 M_rx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U32  portid;
	U16 acklen;
	U16 ackstatus;
	U8 enable;

	acklen = 2;
	ackstatus = CMD_OK;

	switch (cmd_code)
	{
	case CMD_RX_ENABLE:
		portid = (U8)*pcmd;
		if (portid >= GEM_PORTS) {
			ackstatus = CMD_ERR;
			break;
		}
		break;

	case CMD_RX_DISABLE:
		portid = (U8)*pcmd;
		if (portid >= GEM_PORTS) {
			ackstatus = CMD_ERR;
			break;
		}
		break;

	case CMD_RX_LRO:
		enable = (U8)*pcmd;
		if (enable > 0)
			ackstatus = CMD_ERR;

		break;

	default:
		ackstatus = CMD_ERR;
		break;
	}

	*pcmd = ackstatus;
	return acklen;
}


int rx_init(void)
{
	set_cmd_handler(EVENT_PKT_RX, M_rx_cmdproc);

	ff_enable = 1;

	return 0;
}

void rx_exit(void)
{
}
