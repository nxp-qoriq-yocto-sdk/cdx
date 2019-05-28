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



#ifndef _CONTROL_TX_H_
#define _CONTROL_TX_H_

#define DEFAULT_NAME_0		eth0
#define DEFAULT_NAME_1		eth2
#define DEFAULT_NAME_2		eth3

typedef struct _tPortUpdateCommand {
	U16 portid;
	char ifname[IF_NAME_SIZE];
} PortUpdateCommand, *PPortUpdateCommand;


int tx_init(void);
void tx_exit(void);


#endif /* _CONTROL_TX_H_ */

