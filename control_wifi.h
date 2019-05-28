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

#ifndef _MODULE_WIFI_H_
#define _MODULE_WIFI_H_

#include "types.h"
#include "layer2.h"
#include "system.h"

#ifdef CFG_WIFI_OFFLOAD

typedef struct tWifiIfDesc
{
	int VAPID;
}WifiIfDesc, *PWifiIfDesc;

typedef struct tRX_wifi_context {
   U16 users;
   U16  enabled;
}RX_wifi_context;

typedef struct wifi_vap_query_response
{
        U16       vap_id;
        char      ifname[IF_NAME_SIZE];
        U16       phy_port_id;
}wifi_vap_query_response_t;

struct wifiCmd
{
	U16 action;
	U16 VAPID;
	U8  ifname[IF_NAME_SIZE];
	U8  mac_addr[6];
	U16 wifi_guest_flag;
};
#define WIFI_ADD_VAP       0
#define WIFI_REMOVE_VAP    1
#define WIFI_UPDATE_VAP    2


int wifi_init(void);
void wifi_exit(void);

//void wifi_tx_generate_csum(struct tMetadata *mtd);
//void wifi_rx_validate_csum(struct tMetadata *mtd);
#endif /* CFG_WIFI_OFFLOAD */

#endif /* _MODULE_WIFI_H_ */
