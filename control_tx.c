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
#include "control_tx.h"


char IF0_NAME[16] = TOSTR(DEFAULT_NAME_0);
char IF1_NAME[16] = TOSTR(DEFAULT_NAME_1);
char IF2_NAME[16] = TOSTR(DEFAULT_NAME_2);


static void M_tx_port_update(PPortUpdateCommand cmd)
{
	char *if_name = get_onif_name(phy_port[cmd->portid].itf.index);

	strncpy(if_name, cmd->ifname, INTERFACE_NAME_LENGTH);
	if_name[INTERFACE_NAME_LENGTH - 1] = '\0';
}

static U16 M_tx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U32 portid;
	U16 rc;
	U16 retlen = 2;

	portid = *pcmd;

	if (portid >= GEM_PORTS) {
		rc = CMD_ERR;
		goto out;
	}

	switch (cmd_code)
	{
	case CMD_TX_ENABLE:
		if (cmd_len > 2) {
			if (cmd_len > 14) {
				memcpy(phy_port[portid].mac_addr, &(((U8*)pcmd)[14]), 6);
				phy_port[portid].flags |= TX_ENABLED;
			}
		}

		rc = CMD_OK;
		break;

	case CMD_TX_DISABLE:
		phy_port[portid].flags &= ~TX_ENABLED;
#ifdef CDX_TODO_TX
		/*Reset tx enable flag in class and Util for this physical port*/
		for (id = CLASS0_ID; id <= CLASS_MAX_ID; id++)
			pe_dmem_writeb(id, phy_port[portid].flags, virt_to_class_dmem(&phy_port[portid].flags));
		pe_dmem_writeb(UTIL_ID, phy_port[portid].flags, virt_to_util_dmem(&util_phy_port[portid].flags));
#endif

		rc = CMD_OK;
		break;

	case CMD_PORT_UPDATE:

		/* Update the port info in the onif */
		M_tx_port_update((PPortUpdateCommand)pcmd);
		rc = CMD_OK;
		break;

	default:
		rc = CMD_ERR;
		break;
	}

out:
	*pcmd = rc;
	return retlen;
}


int tx_init(void)
{
	int i;

	set_cmd_handler(EVENT_PKT_TX, M_tx_cmdproc);

	for (i = 0; i < MAX_PHY_PORTS; i++) {
		phy_port[i].id = i;
	}

#ifdef CDX_TODO
	add_onif((U8 *)IF0_NAME, &phy_port[0].itf, NULL, IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
	add_onif((U8 *)IF1_NAME, &phy_port[1].itf, NULL, IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
	add_onif((U8 *)IF2_NAME, &phy_port[2].itf, NULL, IF_TYPE_ETHERNET | IF_TYPE_PHYSICAL);
#endif

#ifdef CDX_TODO_BRIDGE
	/* Register interfaces with bridge */
	bridge_interface_register((U8 *) IF0_NAME, 0);
	bridge_interface_register((U8 *) IF1_NAME, 1);
	bridge_interface_register((U8 *) IF2_NAME, 2);
#endif

	return 0;
}

void tx_exit(void)
{
	int i;

	for (i = 0; i < GEM_PORTS; i++)
		remove_onif_by_index(phy_port[i].itf.index);
}
