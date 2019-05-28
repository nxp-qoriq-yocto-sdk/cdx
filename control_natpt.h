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



#ifndef _CONTROL_NATPT_H_
#define _CONTROL_NATPT_H_

#define NATPT_CONTROL_6to4	0x0001
#define NATPT_CONTROL_4to6	0x0002


/* control path SW natpt entry */

typedef struct _tNATPT_Stats {
	U64	stat_v6_received;
	U64	stat_v6_transmitted;
	U64	stat_v6_dropped;
	U64	stat_v6_sent_to_ACP;
	U64	stat_v4_received;
	U64	stat_v4_transmitted;
	U64	stat_v4_dropped;
	U64	stat_v4_sent_to_ACP;
} NATPT_Stats, *PNATPT_Stats;

typedef struct _tNATPTOpenCommand {
	U16	socketA;
	U16	socketB;
	U16	control;
	U16	reserved;
}NATPTOpenCommand, *PNATPTOpenCommand;

typedef struct _tNATPTCloseCommand {
	U16	socketA;
	U16	socketB;
}NATPTCloseCommand, *PNATPTCloseCommand;

typedef struct _tNATPTQueryCommand {
	U16	reserved1;
	U16	socketA;
	U16	socketB;
	U16	reserved2;
}NATPTQueryCommand, *PNATPTQueryCommand;

typedef struct _tNATPTQueryResponse {
	U16	retcode;
	U16	socketA;
	U16	socketB;
	U16	control;
	U64	stat_v6_received;
	U64	stat_v6_transmitted;
	U64	stat_v6_dropped;
	U64	stat_v6_sent_to_ACP;
	U64	stat_v4_received;
	U64	stat_v4_transmitted;
	U64	stat_v4_dropped;
	U64	stat_v4_sent_to_ACP;
}NATPTQueryResponse, *PNATPTQueryResponse;

BOOL natpt_init(void);
void natpt_exit(void);

#endif /* _CONTROL_NATPT_H_ */
