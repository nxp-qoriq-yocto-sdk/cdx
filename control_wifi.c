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
#include "system.h"
#include "layer2.h"
#include "globals.h"
#include "control_wifi.h"

#ifdef CFG_WIFI_OFFLOAD


struct 	tWifiIfDesc wifiDesc[MAX_WIFI_VAPS];

struct tRX_wifi_context gWifiRxCtx;

extern int dpa_add_wlan_if(char *name, struct _itf *itf, uint32_t vap_id, unsigned char* mac);


static int wifi_vap_entry( U16 *ptr, U16 len )
{
	struct wifiCmd cmd;
	struct tRX_wifi_context *rxc;
	int portid;
	struct physical_port	*port;

	rxc = &gWifiRxCtx;
	//printk("%s:%d\n", __func__, __LINE__);

	if (len != sizeof(struct wifiCmd))
		return ERR_WRONG_COMMAND_SIZE;

	memcpy( &cmd, ptr, sizeof(struct wifiCmd));

	if( cmd.VAPID >= MAX_WIFI_VAPS )
		return ERR_UNKNOWN_ACTION;

	portid = PORT_WIFI_IDX + cmd.VAPID;
	port = phy_port_get(portid);

	switch (cmd.action)
	{
		case WIFI_REMOVE_VAP:
			printk(KERN_INFO "%s:%d Remove entry\n", __func__, __LINE__);
			if( wifiDesc[cmd.VAPID].VAPID == 0XFFFF )
				return ERR_WLAN_DUPLICATE_OPERATION;
			//printk("%s: PHYID:%d vapid:%d\n", __func__, portid, cmd.VAPID);

			wifiDesc[cmd.VAPID].VAPID = 0xFFFF;

			//bridge_interface_deregister(portid);

			remove_onif_by_index(port->itf.index);

			if ( rxc->users  )
				rxc->users--;

			break;

		case WIFI_ADD_VAP:
			if ( rxc->users >= MAX_WIFI_VAPS )
				return CMD_ERR;

			printk(KERN_INFO "%s:%d ADD entry \n", __func__, __LINE__);
			if( wifiDesc[cmd.VAPID].VAPID != 0XFFFF )
				return ERR_WLAN_DUPLICATE_OPERATION;

			if(!add_onif(cmd.ifname, &port->itf, NULL, IF_TYPE_WLAN | IF_TYPE_PHYSICAL))
			{
				return CMD_ERR;
			}

			if (dpa_add_wlan_if(cmd.ifname, &port->itf, cmd.VAPID, cmd.mac_addr)) {
                                remove_onif_by_index(port->itf.index);
				wifiDesc[cmd.VAPID].VAPID = 0xFFFF;
                                return CMD_ERR;
                        }


			wifiDesc[cmd.VAPID].VAPID = cmd.VAPID;
			//bridge_interface_register(cmd.ifname, portid);

			memcpy(port->mac_addr, cmd.mac_addr, 6);
			if ( rxc->users < MAX_WIFI_VAPS )
				rxc->users++;

			break;

		case WIFI_UPDATE_VAP:
			printk(KERN_INFO "%s:%d Update Entry\n", __func__, __LINE__);
			if( wifiDesc[cmd.VAPID].VAPID == 0XFFFF )
				return CMD_ERR;

			memcpy(port->mac_addr, cmd.mac_addr, 6);
			break;

		default:
			return ERR_UNKNOWN_ACTION;


	}

	return NO_ERR;


}


static U16 M_wifi_rx_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 acklen;
	U16 ackstatus;
	U16 i;
	struct tRX_wifi_context *rxc;
	struct physical_port	*port;

	rxc = &gWifiRxCtx;

	acklen = 2;
	ackstatus = CMD_OK;
	printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
	switch (cmd_code)
	{
		case CMD_WIFI_VAP_ENTRY:
			ackstatus = wifi_vap_entry(pcmd, cmd_len);
			break;


		case CMD_WIFI_VAP_QUERY: {
						 wifi_vap_query_response_t *vaps;
						 vaps = (wifi_vap_query_response_t *)pcmd;
						 printk("%s:%d\n", __func__, __LINE__);

						 for (i = 0; i < MAX_WIFI_VAPS; i++)
						 {
							 vaps[i].vap_id = wifiDesc[i].VAPID;
							 if( vaps[i].vap_id != 0xFFFF )
								 vaps[i].phy_port_id = PORT_WIFI_IDX + i;
							 port = phy_port_get(PORT_WIFI_IDX + i);

							 memcpy(vaps[i].ifname, get_onif_name(port->itf.index), IF_NAME_SIZE);
						 }

						 acklen += ( MAX_WIFI_VAPS * sizeof(wifi_vap_query_response_t));
						 break;
					 }

		case CMD_WIFI_VAP_RESET:
					 printk(KERN_INFO "%s:%d\n", __func__, __LINE__);
					 for (i = 0; i < MAX_WIFI_VAPS; i++)
					 {
						 if( wifiDesc[i].VAPID != 0XFFFF )
						 {
							 wifiDesc[i].VAPID = 0xFFFF;
							 port = phy_port_get(PORT_WIFI_IDX + i);

							 remove_onif_by_index(port->itf.index);

							 if ( rxc->users  )
								 rxc->users--;
						 }
					 }
					 break;

		default:
					 ackstatus = CMD_ERR;
					 break;
	}

	*pcmd = ackstatus;
	return acklen;
}



void M_wifi_init_rx(void)
{
	int i;
	struct physical_port	*port;


	set_cmd_handler(EVENT_PKT_WIFIRX, M_wifi_rx_cmdproc);

	for ( i = 0; i < MAX_WIFI_VAPS; i++ )
	{
		wifiDesc[i].VAPID = 0xFFFF;
		port = phy_port_get(PORT_WIFI_IDX + i);
		port->id = PORT_WIFI_IDX + i;
	}
}

int wifi_init(void)
{
	M_wifi_init_rx();

	return 0;
}

void wifi_exit(void)
{
}
#endif /* CFG_WIFI_OFFLOAD */
