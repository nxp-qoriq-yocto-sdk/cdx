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


#ifndef _CONTROL_VLAN_H_
#define _CONTROL_VLAN_H_

/*Internal VLAN entry used by the VLAN engine*/
typedef struct _tVlanEntry {
	itf_t itf;

	struct slist_entry list;

	U16 vlanID;						/*In big endian format*/
}VlanEntry, *PVlanEntry;

/*Structure defining the VLAN ENTRY command*/
typedef struct _tVLANCommand {
	U16 action;		 	/*Action to perform*/
	U16 vlanID;
	U8 vlanifname[IF_NAME_SIZE];
	U8 phyifname[IF_NAME_SIZE];
}VlanCommand, *PVlanCommand;

int Vlan_Get_Next_Hash_Entry(PVlanCommand pVlanCmd, int reset_action);

int vlan_init(void);
void vlan_exit(void);


/** Vlan entry hash calculation (based on vlan id).
*
* @param entry	vlan_id VLAN ID in network by order
*
* @return	vlan hash index
*
*/
static __inline U32 HASH_VLAN(U16 vlan_id)
{
	vlan_id = ntohs(vlan_id);
	return ((vlan_id >> 12) ^ (vlan_id >> 8) ^ (vlan_id)) & (NUM_VLAN_ENTRIES - 1);
}

#endif /* _CONTROL_VLAN_H_ */

