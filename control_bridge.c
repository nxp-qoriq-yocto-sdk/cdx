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



#include <linux/module.h>
#include <linux/kernel.h>
#include "cdx.h"
#include "control_bridge.h"
#include "jenk_hash.h"
#include "misc.h"
#include "cdx_ioctl.h"
#include "cdx_common.h"

//#define CONTROL_BRIDGE_DEBUG 1


//l2 flow hash table
struct flow_bucket l2flow_hash_table[NUM_BT_ENTRIES];

//flow timer infrastructure
U32 L2Bridge_timeout;

extern int delete_l2br_entry_classif_table(struct hw_ct *);
extern int rx_Get_Next_Hash_L2FlowEntry(PL2BridgeL2FlowEntryCommand pL2FlowCmd, int reset_action);

#ifdef CONTROL_BRIDGE_DEBUG
static void display_flow_tuples(struct L2Flow *entry)
{
	printk("destmac: ");
	display_mac_addr(&entry->da[0]);
	printk("srcmac: ");
	display_mac_addr(&entry->sa[0]);
	printk("ethertype\t0x%x\n", entry->ethertype);
	printk("session id\t%d\n", entry->session_id);
	printk("svlan tag\t0x%x\n", entry->svlan_tag);
	printk("cvlan tag\t0x%x\n", entry->cvlan_tag);
}

static void display_flow_entry(struct L2Flow_entry *entry)
{
	printk("entry %p\ntuples:\n", entry);
	display_flow_tuples(&entry->l2flow);
	printk("last timer %d\n", entry->last_l2flow_timer);
	printk("output if %s\n", entry->out_ifname);
	printk("input if %s\n", entry->in_ifname);
	printk("status %d\n", entry->status);
	printk("hwflow %p\n", entry->ct);
}
#endif


static void l2flow_remove(struct L2Flow_entry *entry)
{
	U32 hash = entry->hash;

	cdx_timer_del(&entry->timer);
#ifdef CONTROL_BRIDGE_DEBUG
	display_flow_entry(entry);
#endif
	//remove from hw tables
	if (delete_l2br_entry_classif_table(entry->ct)) {
		DPA_ERROR("%s::failed to remove entry\n",
			__FUNCTION__);
		return;
	}
	l2flow_hash_table[hash].num_entries--;
	kfree(entry->ct);
	hlist_del(&entry->node);
#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::entry removed from flow table, count%d\n",
			__FUNCTION__, l2flow_hash_table[hash].num_entries);
#endif
	kfree(entry);
}

static int M_bridge_expire_l2_flow_entry(struct L2Flow_entry *entry)
{
	L2BridgeL2FlowEntryCommand *message;
	HostMessage *pmsg;

	// Send indication message
	pmsg = msg_alloc();
	if (!pmsg)
		goto err;

	message = (L2BridgeL2FlowEntryCommand *)pmsg->data;

	// Prepare indication message
	memset(message, 0 , sizeof(*message));
	message->action =  ACTION_REMOVED;
	memcpy(message->destaddr, entry->l2flow.da, 2 * ETHER_ADDR_LEN);
	message->ethertype = entry->l2flow.ethertype;
	message->svlan_tag = entry->l2flow.svlan_tag;
	message->cvlan_tag = entry->l2flow.cvlan_tag;
	message->session_id = entry->l2flow.session_id;

	pmsg->code = CMD_RX_L2BRIDGE_FLOW_ENTRY;
	pmsg->length = sizeof(*message);

	if (msg_send(pmsg) < 0)
		goto err;

	//l2flow_remove(entry);
	return 0;

err:
	printk("%s::err in msg send\n", __FUNCTION__);
	entry->status |= L2_BRIDGE_TIMED_OUT;
	return 1;
}

extern void hw_ct_get_active(struct hw_ct *);
static void br_timer_refresh(struct L2Flow_entry *pEntry)
{
        struct hw_ct *ct;
        if ((ct = pEntry->ct) != NULL)
        {
                hw_ct_get_active(ct);
                pEntry->last_l2flow_timer = (cdx_timer_t)ct->timestamp;
        }
}

cdx_timer_t br_get_time_remaining(struct L2Flow_entry *pEntry)
{
	cdx_timer_t latest_time;
	cdx_timer_t elapsed_time;
	TIMER_ENTRY *timer = &pEntry->timer;

	br_timer_refresh(pEntry);
	latest_time = pEntry->last_l2flow_timer; 
	elapsed_time = ct_timer - latest_time;	

	return elapsed_time >= timer->timerdata ? 0 : timer->timerdata - elapsed_time;
}

void br_timer_update(struct L2Flow_entry *pEntry)
{
        TIMER_ENTRY *timer = &pEntry->timer;
        cdx_timer_t oldtimer = timer->timerdata;
        timer->timerdata =  L2Bridge_timeout;
        // Only update timer if first time or new period is less than old
        if (oldtimer == 0 || timer->timerdata < oldtimer)
        {
                cdx_timer_t newtimeout;
                if (oldtimer == 0)
                        newtimeout = ct_timer + timer->timerdata;
                else
                        newtimeout = timer->timeout - oldtimer + timer->timerdata;
                //DPRINT_ERROR("oldtimer=%u, timer->timerdata=%u, ct_timer=%u, newtimeout=%u\n", oldtimer, timer->timerdata, ct_timer, newtimeout);
                cdx_timer_del(timer);
                cdx_timer_add(timer, TIME_BEFORE(newtimeout, ct_timer) ? 1 : newtimeout - ct_timer);
        }
}



int L2Bridge_timer(TIMER_ENTRY *timer)
{
	int rc;
	struct L2Flow_entry *entry = container_of(timer, typeof(struct L2Flow_entry), timer);

	//check activity bit from hw flow
	timer->period = br_get_time_remaining(entry);

	//if ((time_elapsed >= L2Bridge_timeout) || (entry->status & L2_BRIDGE_TIMED_OUT)) {
	if ( (timer->period == 0) || (entry->status & L2_BRIDGE_TIMED_OUT) )
	{
		rc = M_bridge_expire_l2_flow_entry(entry);
		if (rc == 0)
			return 0;

		printk("%s::M_bridge_expire_l2_flow_entry failed\n", __FUNCTION__);		
		timer->period = 1;
	}
	return 1;
}


static struct L2Flow_entry *l2flow_find_entry(U32 hash, struct L2Flow *l2flow)
{
        struct L2Flow_entry *entry;

#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::entry hash %x flow table %p, head %p count %d\n",
				__FUNCTION__, hash,
				&l2flow_hash_table[hash].flowlist,
				l2flow_hash_table[hash].flowlist.first,
				l2flow_hash_table[hash].num_entries);
#endif
	hlist_for_each_entry(entry, &l2flow_hash_table[hash].flowlist, node)
	{
		if (memcmp(l2flow, &entry->l2flow, sizeof(struct L2Flow)) == 0) 
			return entry;
	}
	return NULL;
}

extern int add_l2flow_to_hw(struct L2Flow_entry *entry);

static int l2flow_add(struct L2Flow_entry *entry, U32 hash)
{
	INIT_HLIST_NODE(&entry->node);
	entry->hash = hash;

	//add to hw table
	if (add_l2flow_to_hw(entry)) {
		return -1;
	}
        /* Add software entry to local hash */
	hlist_add_head(&entry->node, &l2flow_hash_table[hash].flowlist);
	//add time stamp to flow
	entry->last_l2flow_timer = ct_timer;
	//added entries to flow list
	l2flow_hash_table[hash].num_entries++;
#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::entry added to flow table %p head %p count %d\n",
				__FUNCTION__, 
				&l2flow_hash_table[hash].flowlist,
				l2flow_hash_table[hash].flowlist.first,
				l2flow_hash_table[hash].num_entries);
#endif
	cdx_timer_init(&entry->timer, L2Bridge_timer);
	br_timer_update(entry);
	//cdx_timer_add(&entry->timer, L2Bridge_timeout);
        return 0;
}

static void l2flow_update(struct L2Flow_entry *entry)
{
	printk("%s::implement this\n", __FUNCTION__);
}


static int M_bridge_handle_l2flow(U16 *p, U16 Length)
{
	U16 ackstatus = CMD_OK;
	POnifDesc pOnif = NULL;
	POnifDesc pInif = NULL;
	U32 hash = 0;
	struct L2Flow l2flow;
	struct L2Flow_entry *l2flow_entry = NULL;
	char reset_action = 0;
	PL2BridgeL2FlowEntryCommand pcmd;

	if(Length != sizeof(L2BridgeL2FlowEntryCommand))
		return ERR_WRONG_COMMAND_SIZE;
	pcmd = (PL2BridgeL2FlowEntryCommand)p;

	if ((pcmd->action == ACTION_QUERY) || (pcmd->action == ACTION_QUERY_CONT))
		goto skip_fill;
	
	if (pcmd->proto) {
		printk("%s::l3 flows not supported now\n", __FUNCTION__);
		return ERR_WRONG_COMMAND_PARAM;
	}
	//fill flow params from command
	memcpy(&l2flow.da[0], pcmd->destaddr, 6);
	memcpy(&l2flow.sa[0], pcmd->srcaddr, 6);
	l2flow.ethertype = pcmd->ethertype;
	l2flow.session_id = pcmd->session_id;
	l2flow.svlan_tag = pcmd->svlan_tag;
	l2flow.cvlan_tag = pcmd->cvlan_tag;

	//compute hash and check if this flow exists
        hash = compute_jenkins_hash((uint8_t *)&l2flow, 
		sizeof(struct L2Flow), 0);
	hash &= NUM_BT_ENTRIES - 1;
	l2flow_entry = l2flow_find_entry(hash, &l2flow);
skip_fill:
	switch(pcmd->action) {
		case ACTION_REGISTER:
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::ACTION_REGISTER\n", __FUNCTION__);
#endif
			if (l2flow_entry) {
				printk("%s::flow exists, trying to add again\n", __FUNCTION__);
				ackstatus = ERR_BRIDGE_ENTRY_ALREADY_EXISTS;
				goto func_ret;
			}
			//allocate new entry if it is register action
			l2flow_entry = (struct L2Flow_entry *)
				kzalloc(sizeof(struct L2Flow_entry), GFP_KERNEL);
			if (l2flow_entry == NULL) {
				ackstatus = ERR_NOT_ENOUGH_MEMORY;
				goto func_ret;
			}
			if((pOnif = get_onif_by_name(pcmd->output_name)) == NULL) {
				kfree(l2flow_entry);
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			if ((pInif = get_onif_by_name(pcmd->input_name)) == NULL) {
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			strcpy(&l2flow_entry->out_ifname[0], pcmd->output_name);
			strcpy(&l2flow_entry->in_ifname[0], pcmd->input_name);
			memcpy(&l2flow_entry->l2flow, &l2flow, sizeof(struct L2Flow));
			l2flow_entry->last_l2flow_timer = ct_timer;
			//TODO: add mark / qos code back in
			//l2flow_entry->mark = pcmd->mark;
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::output_name %s\n", __FUNCTION__,
					pcmd->output_name);
			printk("%s::input_name %s\n", __FUNCTION__,
					pcmd->input_name);
#endif
			if (l2flow_add(l2flow_entry, hash)) {
				ackstatus = ERR_BRIDGE_ENTRY_ADD_FAILURE;
				kfree(l2flow_entry);
				goto func_ret;
			}
			break;

		case ACTION_UPDATE:
			//l2flow_entry->mark = pcmd->mark;
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::ACTION_UPDATE\n", __FUNCTION__);
#endif
			if (!l2flow_entry) {
				ackstatus = ERR_BRIDGE_ENTRY_NOT_FOUND;
				goto func_ret;
			}
			if((pOnif = get_onif_by_name(pcmd->output_name)) == NULL) {
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			if ((pInif = get_onif_by_name(pcmd->input_name)) == NULL) {
				ackstatus = ERR_UNKNOWN_INTERFACE;
				goto func_ret;
			}
			strcpy(&l2flow_entry->out_ifname[0], pcmd->output_name);
			strcpy(&l2flow_entry->in_ifname[0], pcmd->input_name);
			l2flow_update(l2flow_entry);
			break;

		case ACTION_DEREGISTER:
#ifdef CONTROL_BRIDGE_DEBUG
			printk("%s::ACTION_DEREGISTER\n", __FUNCTION__);
#endif
			if (!l2flow_entry) {
#ifdef CONTROL_BRIDGE_DEBUG
				printk("%s::ACTION_DEREGISTER flow not found\n", __FUNCTION__);
#endif
				ackstatus = ERR_BRIDGE_ENTRY_NOT_FOUND;
				goto func_ret;
			}
			l2flow_remove(l2flow_entry);
			break;

		case ACTION_QUERY:
			reset_action = 1;
			/* fallthrough */
		case ACTION_QUERY_CONT:
			ackstatus = rx_Get_Next_Hash_L2FlowEntry(pcmd, reset_action);
			return ackstatus;
		default:
			ackstatus = ERR_UNKNOWN_ACTION;
			break;
	}//End switch
func_ret:
	return ackstatus;
}

static int M_bridge_handle_control(U16 code, U16 *p, U16 Length)
{
	U16 ackstatus = CMD_OK;
	PL2BridgeControlCommand prsp = (PL2BridgeControlCommand)p;

	switch (code) {
		case CMD_RX_L2BRIDGE_FLOW_TIMEOUT: 
			{
				U32 timeout;
				
				timeout = (prsp->mode_timeout * HZ);
				if (L2Bridge_timeout != timeout) {
					L2Bridge_timeout = timeout;
					printk("%s::timeout changed to %d\n", __FUNCTION__, 
							timeout);
				}
				break;
			}

		case CMD_RX_L2BRIDGE_MODE:
			if (prsp->mode_timeout != L2_BRIDGE_MODE_AUTO) {
				printk("%s::manual mode not supported\n", __FUNCTION__);
				ackstatus = ERR_WRONG_COMMAND_PARAM;
			}
			break;

		default:
			ackstatus = ERR_UNKNOWN_COMMAND;
			break;
	}
	return ackstatus;
}

U16 M_bridge_cmdproc(U16 cmd_code, U16 cmd_len, U16 *p)
{
	U16 acklen;
	U16 ackstatus;
	U32 action;

	acklen = 2;
	ackstatus = CMD_OK;

#ifdef CONTROL_BRIDGE_DEBUG
	printk("%s::cmd code %x p %p\n", __FUNCTION__, cmd_code, p);
#endif
	switch (cmd_code)
	{
		case CMD_RX_L2BRIDGE_ENABLE: 
		case CMD_RX_L2BRIDGE_ADD: 
		case CMD_RX_L2BRIDGE_REMOVE: 
		case CMD_RX_L2BRIDGE_QUERY_STATUS: 
		case CMD_RX_L2BRIDGE_FLOW_RESET:
			break;
		case CMD_RX_L2BRIDGE_QUERY_ENTRY: 
			{
				PL2BridgeQueryEntryResponse prsp = (PL2BridgeQueryEntryResponse)p;
				prsp->eof = 1;
				acklen = sizeof(L2BridgeQueryEntryResponse);
			}
			break;
		case CMD_RX_L2BRIDGE_FLOW_ENTRY:
			action = *p;
			ackstatus = M_bridge_handle_l2flow(p, cmd_len);
			if(ackstatus == NO_ERR && ((action == ACTION_QUERY) || (action == ACTION_QUERY_CONT)))
				acklen += sizeof(L2BridgeL2FlowEntryCommand);
			break;
		
		case CMD_RX_L2BRIDGE_FLOW_TIMEOUT:
		case CMD_RX_L2BRIDGE_MODE: 
			ackstatus = M_bridge_handle_control(cmd_code, p, cmd_len);
			break;
		default:
			ackstatus = ERR_UNKNOWN_COMMAND;
			break;
	}
	*p = ackstatus;
	return acklen;
}



int bridge_interface_deregister( U16 phy_port_id )
{
	printk(KERN_CRIT "%s\n", __FUNCTION__);
	return 0;
}

int bridge_interface_register( uint8_t *name, U16 phy_port_id )
{

	printk(KERN_CRIT "%s\n", __FUNCTION__);
	return 0;
}

static int  M_bridge_handle_reset(void)
{
        U16 ackstatus = CMD_OK;
	printk("%s::implement this\n", __FUNCTION__);
        return ackstatus;
}

int bridge_init(void)
{
	int i;
	set_cmd_handler(EVENT_BRIDGE, M_bridge_cmdproc);
	L2Bridge_timeout = L2_BRIDGE_DEFAULT_TIMEOUT * HZ;
	for (i = 0; i < NUM_BT_ENTRIES; i++)
		INIT_HLIST_HEAD(&l2flow_hash_table[i].flowlist);
	return 0;
}

void bridge_exit(void)
{
	M_bridge_handle_reset();
}

