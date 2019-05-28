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
#include "control_vlan.h"



static PVlanEntry vlan_alloc(void)
{
	return kzalloc(sizeof(VlanEntry), GFP_KERNEL);
}

static void vlan_free(PVlanEntry pEntry)
{
	kfree(pEntry);
}

static void vlan_add(PVlanEntry pEntry)
{
	U32 hash;

	hash = HASH_VLAN(pEntry->vlanID);

	/* Add to our local hash */
	slist_add(&vlan_cache[hash], &pEntry->list);
}

static void vlan_remove(PVlanEntry pEntry)
{
	struct slist_entry *prev;
	U32 hash;

	/*Tell the Interface Manager to remove the Vlan IF*/
	remove_onif_by_index(pEntry->itf.index);

	hash = HASH_VLAN(pEntry->vlanID);

#ifdef CDX_TODO_VLAN
	/* remove the hardware entry */
#endif

	/* Remove from our local table */
	prev = slist_prev(&vlan_cache[hash], &pEntry->list);
	slist_remove_after(prev);
}


static U16 Vlan_handle_reset(void)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	int i;

	/* free VLAN entries */
	for(i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_for_each_safe(pEntry, entry, &vlan_cache[i], list)
		{
			vlan_remove(pEntry);
			vlan_free(pEntry);
		}
	}

	return NO_ERR;
}

extern int dpa_add_vlan_if(char *name, struct _itf *itf, struct _itf *phys_itf, 
                uint16_t vlan_id);
static U16 Vlan_handle_entry(U16 * p,U16 Length)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	VlanCommand vlancmd;
	POnifDesc phys_onif;
	int reset_action = 0;
	U32 hash;

	// Check length
	if (Length != sizeof(VlanCommand))
		return ERR_WRONG_COMMAND_SIZE;
	
	memcpy((U8*)&vlancmd, (U8*)p,  sizeof(VlanCommand));
	hash = HASH_VLAN(htons(vlancmd.vlanID));

	switch(vlancmd.action)
	{
		case ACTION_DEREGISTER: 

			slist_for_each(pEntry, entry, &vlan_cache[hash], list)
			{
				if ((pEntry->vlanID == htons(vlancmd.vlanID & 0xfff)) && (strcmp(get_onif_name(pEntry->itf.index), (char *)vlancmd.vlanifname) == 0))
					goto found;
			}

			return ERR_VLAN_ENTRY_NOT_FOUND;

		found:
			vlan_remove(pEntry);
			vlan_free(pEntry);

			break;

		case ACTION_REGISTER: 

			if (get_onif_by_name(vlancmd.vlanifname))
				return ERR_VLAN_ENTRY_ALREADY_REGISTERED;

			slist_for_each(pEntry, entry, &vlan_cache[hash], list)
			{
				if ((pEntry->vlanID == htons(vlancmd.vlanID & 0xfff)) && (strcmp(get_onif_name(pEntry->itf.index), (char *)vlancmd.vlanifname) == 0) )
					return ERR_VLAN_ENTRY_ALREADY_REGISTERED; //trying to add exactly the same vlan entry
			}

			if ((pEntry = vlan_alloc()) == NULL)
			{
			  	return ERR_NOT_ENOUGH_MEMORY;
			}
			
			pEntry->vlanID = htons(vlancmd.vlanID & 0xfff);

			/*Check if the Physical interface is known by the Interface manager*/
			phys_onif = get_onif_by_name(vlancmd.phyifname);
			if (!phys_onif)
			{
				vlan_free(pEntry);
				return ERR_UNKNOWN_INTERFACE;
			}

			/*Now create a new interface in the Interface Manager and remember the index*/
			if (!add_onif(vlancmd.vlanifname, &pEntry->itf, phys_onif->itf, IF_TYPE_VLAN))
			{
				vlan_free(pEntry);
				return ERR_CREATION_FAILED;
			}
			if (dpa_add_vlan_if(vlancmd.vlanifname, &pEntry->itf,
				phys_onif->itf, pEntry->vlanID)) {
				remove_onif_by_index(pEntry->itf.index);
				vlan_free(pEntry);
				return ERR_CREATION_FAILED;
			}
			vlan_add(pEntry);

			break;
			
		case ACTION_QUERY:
			reset_action = 1;
		case ACTION_QUERY_CONT:
		{
			PVlanCommand pVlan = (VlanCommand*)p;
			int rc;
			
			rc = Vlan_Get_Next_Hash_Entry(pVlan, reset_action);
			return rc;
		}
		
			
		default:
			return ERR_UNKNOWN_ACTION;
	}

	return NO_ERR;
}


static U16 M_vlan_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc;
	U16 retlen = 2;
	U16 action;

	switch (cmd_code)
	{
		case CMD_VLAN_ENTRY:
			action = *pcmd;
			rc = Vlan_handle_entry(pcmd, cmd_len);
			if (rc == NO_ERR && (action == ACTION_QUERY || action == ACTION_QUERY_CONT))
				retlen += sizeof (VlanCommand);
			break;

		case CMD_VLAN_ENTRY_RESET:
			rc = Vlan_handle_reset();
			break;

		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;
	return retlen;
}


int vlan_init(void)
{
	int i;

	set_cmd_handler(EVENT_VLAN, M_vlan_cmdproc);

	for(i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_head_init(&vlan_cache[i]);
	}

	return 0;
}


void vlan_exit(void)
{
	PVlanEntry pEntry;
	struct slist_entry *entry;
	int i;

	for (i = 0; i < NUM_VLAN_ENTRIES; i++)
	{
		slist_for_each_safe(pEntry, entry, &vlan_cache[i], list)
		{
			vlan_remove(pEntry);
			vlan_free(pEntry);
		}
	}

}


/* This function returns total vlan interfaces configured in FPP */
static int Vlan_Get_Hash_Entries(int vlan_hash_index)
{
	int tot_vlans=0;
	struct slist_entry *entry;

	slist_for_each_entry(entry, &vlan_cache[vlan_hash_index])
		tot_vlans++;

	return tot_vlans;
}


/* This function fills in the snapshot of all Vlan entries of a VLAN cache */

static int Vlan_Get_Hash_Snapshot(int vlan_hash_index, int vlan_entries, PVlanCommand pVlanSnapshot)
{
	int tot_vlans=0;
	PVlanEntry pVlanEntry;
	struct slist_entry *entry;

	slist_for_each(pVlanEntry, entry, &vlan_cache[vlan_hash_index], list)
	{
		pVlanSnapshot->vlanID = ntohs(pVlanEntry->vlanID);
		strcpy((char *)pVlanSnapshot->vlanifname, get_onif_name(pVlanEntry->itf.index));
		strcpy((char *)pVlanSnapshot->phyifname, get_onif_name(pVlanEntry->itf.phys->index));

		pVlanSnapshot++;
		tot_vlans++;

		if (--vlan_entries <= 0)
			break;
	}

	return tot_vlans;
	
}


   
int Vlan_Get_Next_Hash_Entry(PVlanCommand pVlanCmd, int reset_action)
{
    int total_vlan_entries;
	PVlanCommand pVlan;
	static PVlanCommand pVlanSnapshot = NULL;
	static int vlan_hash_index = 0, vlan_snapshot_entries =0, vlan_snapshot_index=0, vlan_snapshot_buf_entries = 0;

	if(reset_action)
	{
		vlan_hash_index = 0;
		vlan_snapshot_entries =0;
		vlan_snapshot_index=0;
		if(pVlanSnapshot)
		{
			Heap_Free(pVlanSnapshot);
			pVlanSnapshot = NULL;
		}
		vlan_snapshot_buf_entries = 0;
	}
	
    if (vlan_snapshot_index == 0)
    {
    	while( vlan_hash_index < NUM_VLAN_ENTRIES)
		{
        	total_vlan_entries = Vlan_Get_Hash_Entries(vlan_hash_index);
        	if (total_vlan_entries == 0)
        	{
        		vlan_hash_index++;
        		continue;
        	}
        
        	if(total_vlan_entries > vlan_snapshot_buf_entries)
        	{
        		if(pVlanSnapshot)
        			Heap_Free(pVlanSnapshot);
        		
        		pVlanSnapshot = Heap_Alloc(total_vlan_entries * sizeof(VlanCommand));
			
				if (!pVlanSnapshot)
				{
					vlan_hash_index = 0;
					vlan_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;	
				}
				vlan_snapshot_buf_entries = total_vlan_entries;
        	}
	
		
			vlan_snapshot_entries = Vlan_Get_Hash_Snapshot(vlan_hash_index,total_vlan_entries,pVlanSnapshot);
			break;
		
		}
		if (vlan_hash_index >= NUM_VLAN_ENTRIES)
		{
			vlan_hash_index = 0;
			if(pVlanSnapshot)
			{
				Heap_Free(pVlanSnapshot);
				pVlanSnapshot = NULL;
			}
			vlan_snapshot_buf_entries = 0;
			return ERR_VLAN_ENTRY_NOT_FOUND;
		}
    }
    
   	pVlan = &pVlanSnapshot[vlan_snapshot_index++];
   	
   	memcpy(pVlanCmd, pVlan, sizeof(VlanCommand));
	if (vlan_snapshot_index == vlan_snapshot_entries)
	{
	    vlan_snapshot_index = 0;
	    vlan_hash_index++;
	}
	
	return NO_ERR;
}

