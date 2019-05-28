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
#include "control_stat.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_socket.h"
#include "control_bridge.h"
#include "control_tunnel.h"

extern int cdx_get_ipr_v4_stats(void *stats);
extern int cdx_get_ipr_v6_stats(void *stats);

#ifdef TODO_STATS

static void stats_queue_reset(U8 interface, U8 queue)
{
	STATISTICS_SET(emitted_pkts[interface][queue], 0);
	STATISTICS_SET(dropped_pkts[interface][queue], 0);
	STATISTICS_SET(peak_queue_occ[interface][queue], 0);
}

static void stats_queue_get(U8 interface, U8 queue, PStatQueueResponse rsp, U32 do_reset)
{
	STATISTICS_GET(emitted_pkts[interface][queue], rsp->emitted_pkts);
	STATISTICS_GET(dropped_pkts[interface][queue], rsp->dropped_pkts);
	STATISTICS_GET(peak_queue_occ[interface][queue], rsp->peak_queue_occ);
	if (do_reset)
		stats_queue_reset(interface, queue);
}

static void stats_interface_pkt_reset(U8 interface)
{
	STATISTICS_SET(total_bytes_received[interface], 0);
	STATISTICS_SET(total_pkts_received[interface], 0);

	STATISTICS_SET(total_bytes_transmitted[interface], 0);
	STATISTICS_SET(total_pkts_transmitted[interface], 0);
}

static void stats_interface_pkt_get(U8 interface, PStatInterfacePktResponse rsp, U32 do_reset)
{
	STATISTICS_GET_LSB(total_bytes_received[interface], rsp->total_bytes_received[0], U32);
	STATISTICS_GET_MSB(total_bytes_received[interface], rsp->total_bytes_received[1], U32);

	STATISTICS_GET(total_pkts_received[interface], rsp->total_pkts_received);

	STATISTICS_GET_LSB(total_bytes_transmitted[interface], rsp->total_bytes_transmitted[0], U32);
	STATISTICS_GET_MSB(total_bytes_transmitted[interface], rsp->total_bytes_transmitted[1], U32);
	STATISTICS_GET(total_pkts_transmitted[interface], rsp->total_pkts_transmitted);

	if (do_reset)
		stats_interface_pkt_reset(interface);
}


static U16 stats_queue(U8 action, U8 queue, U8 interface, PStatQueueResponse statQueueRsp, U16 *acklen)
{
	U16 ackstatus = CMD_OK;

	if(action & FPP_STAT_QUERY)
	{
		stats_queue_get(interface, queue, statQueueRsp, action & FPP_STAT_RESET);

		*acklen = sizeof(StatQueueResponse);
	}
	else if(action & FPP_STAT_RESET)
	{
		stats_queue_reset(interface, queue);
	}
	else
		ackstatus = ERR_WRONG_COMMAND_PARAM;

	return ackstatus;
}

static U16 stats_interface_pkt(U8 action, U8 interface, PStatInterfacePktResponse statInterfacePktRsp, U16 *acklen)
{
	U16 ackstatus = CMD_OK;

	if(action & FPP_STAT_QUERY)
	{
		stats_interface_pkt_get(interface, statInterfacePktRsp, action & FPP_STAT_RESET);

		statInterfacePktRsp->rsvd1 = 0;
		*acklen = sizeof(StatInterfacePktResponse);
	}
	else if(action & FPP_STAT_RESET)
	{
		stats_interface_pkt_reset(interface);
	}
	else
		ackstatus = ERR_WRONG_COMMAND_PARAM;

	return ackstatus;
}



static U16 stats_connection(U16 action, PStatConnResponse statConnRsp, U16 *acklen)
{
	U16 ackstatus = CMD_OK;

	if(action & FPP_STAT_QUERY)
	{
		STATISTICS_CTRL_GET(max_active_connections, statConnRsp->max_active_connections);
		STATISTICS_CTRL_GET(num_active_connections, statConnRsp->num_active_connections);
		*acklen = sizeof(StatConnResponse);
	}
	else
		ackstatus = ERR_WRONG_COMMAND_PARAM;

	return ackstatus;
}
#endif	// TODO_STATS


extern void hw_ct_get_active(struct hw_ct *);

U32 stats_bitmask_enable_g = 0;

void stat_ct_flow_get(struct hw_ct *ct, U64 *pkts, U64 *bytes, int do_reset)
{
	if (!ct)
	{
		*pkts = 0;
		*bytes = 0;
		return;
	}
	hw_ct_get_active(ct);
	*pkts = ct->pkts - ct->reset_pkts;
	*bytes = ct->bytes - ct->reset_bytes;
	if (do_reset)
	{
		ct->reset_pkts = ct->pkts;
		ct->reset_bytes = ct->bytes;
	}
}

void stat_ct_flow_reset(struct hw_ct *ct)
{
	U64 pkts;
	U64 bytes;

	stat_ct_flow_get(ct, &pkts, &bytes, TRUE);

	return;
}

/**
 * This function resets all IPv4 and IPv6 connections statistics counters
 */
static void ResetAllFlowStats(void)
{
	PCtEntry pCtEntry;
	struct slist_entry *entry;
	int ct_hash_index;

	for (ct_hash_index = 0; ct_hash_index < NUM_CT_ENTRIES; ct_hash_index++)
	{
		slist_for_each(pCtEntry, entry, &ct_cache[ct_hash_index], list)
		{
			stat_ct_flow_reset(pCtEntry->ct);
		}
	}
}

static U16 Get_Flow_stats(PStatFlowEntryResp flowStats, int do_reset)
{
	PCtEntry pEntry;

	if (flowStats->ip_family == 4)
	{
		pEntry = IPv4_find_ctentry(flowStats->Saddr, flowStats->Daddr, flowStats->Sport, flowStats->Dport, flowStats->Protocol);
		if (!pEntry)
		{
			printk("No connection for flow: saddr=%pI4 daddr=%pI4 sport=%u dport=%u proto=%u\n",
					&flowStats->Saddr, &flowStats->Daddr, htons(flowStats->Sport), htons(flowStats->Dport), flowStats->Protocol);
			return ERR_FLOW_ENTRY_NOT_FOUND;
		}
		stat_ct_flow_get(pEntry->ct, &flowStats->TotalPackets, &flowStats->TotalBytes, do_reset);
	}
	else if (flowStats->ip_family == 6)
	{
		pEntry = IPv6_find_ctentry(flowStats->Saddr_v6, flowStats->Daddr_v6, flowStats->Sport, flowStats->Dport, flowStats->Protocol);
		if (!pEntry)
		{
			printk("No connection for flow: saddr=%pI6c daddr=%pI6c sport=%u dport=%u proto=%u\n",
					flowStats->Saddr_v6, flowStats->Daddr_v6, htons(flowStats->Sport), htons(flowStats->Dport), flowStats->Protocol);
			return ERR_FLOW_ENTRY_NOT_FOUND;
		}
		stat_ct_flow_get(pEntry->ct, &flowStats->TotalPackets, &flowStats->TotalBytes, do_reset);
	}
	else
	{
		printk("ERROR: Invalid IP address family <0x%x>\n", flowStats->ip_family);
		return ERR_INVALID_IP_FAMILY;
	}

	return NO_ERR;
}

/**
 * M_stat_cmdproc
 *
 *
 *
 */
static U16 M_stat_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 acklen;
	U16 ackstatus;
	U16 action;

	acklen = 2;
	ackstatus = CMD_OK;

	switch (cmd_code)
	{

	case CMD_STAT_ENABLE:
	{
		StatEnableCmd statcmd;

		memcpy((U8*)&statcmd, (U8*)pcmd, sizeof(StatEnableCmd));
		if (statcmd.bitmask == STAT_FLOW_BITMASK)
		{
			if (statcmd.action == 1)
			{
				stats_bitmask_enable_g |= STAT_FLOW_BITMASK;
			}
			else
			{
				stats_bitmask_enable_g &= ~STAT_FLOW_BITMASK;
			}
		}

		// Stats are now always enabled
		break;
	}

#ifdef TODO_STATS
	case CMD_STAT_QUEUE:
	{
		U16 queue;
		U16 interface;
		StatQueueCmd queueCmd;
		PStatQueueResponse statQueueRsp;

		// Ensure alignment
		memcpy((U8*)&queueCmd, (U8*)pcmd, sizeof(StatQueueCmd));
		action = queueCmd.action;
		queue = queueCmd.queue;
		interface = queueCmd.interface;
		statQueueRsp = 	(PStatQueueResponse)pcmd;
		ackstatus = stats_queue(action, queue, interface, statQueueRsp, &acklen);
		break;
	}

	case CMD_STAT_INTERFACE_PKT:
	{
		U16 interface;
		StatInterfaceCmd intPktCmd;
		PStatInterfacePktResponse statInterfacePktRsp;

		// Ensure alignment
		memcpy((U8*)&intPktCmd, (U8*)pcmd, sizeof(StatInterfaceCmd));
		interface = intPktCmd.interface;
		action = intPktCmd.action;
		statInterfacePktRsp = (PStatInterfacePktResponse)pcmd;
		ackstatus = stats_interface_pkt(action, interface, statInterfacePktRsp, &acklen);
		break;
	}

	case CMD_STAT_CONN:
	{
		StatConnectionCmd connCmd;
		PStatConnResponse statConnRsp;
		
		// Ensure alignment
		memcpy((U8*)&connCmd, (U8*)pcmd, sizeof(StatConnectionCmd));
		action = connCmd.action;
		statConnRsp = (PStatConnResponse)pcmd;
		ackstatus = stats_connection(action, statConnRsp, &acklen);
		break;
	}
	
	case CMD_STAT_PPPOE_STATUS:
	{
		int x;
		struct slist_entry *entry;
		pPPPoE_Info pEntry;
		StatPPPoEStatusCmd pppoeStatusCmd;

		// Ensure alignment
		memcpy((U8*)&pppoeStatusCmd, (U8*)pcmd, sizeof(StatPPPoEStatusCmd));

		action = pppoeStatusCmd.action;

		if (action == FPP_STAT_RESET)
		{
			/* Reset the packet counters for all PPPoE Entries */
			for (x = 0; x < NUM_PPPOE_ENTRIES; x++)
			{
				slist_for_each(pEntry, entry, &pppoe_cache[x], list)
					stat_pppoe_reset(pEntry);
			}
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatPPPoEQueryStatus = 0;
			if (action == FPP_STAT_QUERY_RESET)
				gStatPPPoEQueryStatus |= STAT_PPPOE_QUERY_RESET;

			stat_PPPoE_Get_Next_SessionEntry((PStatPPPoEEntryResponse)pcmd, 1);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}


	case CMD_STAT_PPPOE_ENTRY:{
		int result;

		PStatPPPoEEntryResponse prsp = (PStatPPPoEEntryResponse)pcmd;

		result = stat_PPPoE_Get_Next_SessionEntry(prsp, 0);
		if (result != NO_ERR)
		{
			prsp->eof = 1;
		}

		acklen = sizeof(StatPPPoEEntryResponse);
		break;
	}


	case CMD_STAT_BRIDGE_STATUS:
	{
#if 0
		int x;
		struct slist_entry *entry;
		PL2Bridge_entry pEntry;
		StatBridgeStatusCmd bridgeStatusCmd;

                if((L2_BRIDGE_MODE_MANUAL == l2bridge_get_mode()) && (gFpCtrlStatFeatureBitMask & STAT_BRIDGE_BITMASK)) {
		
			// Ensure alignment
			memcpy((U8*)&bridgeStatusCmd, (U8*)pcmd, sizeof(StatBridgeStatusCmd));

			action = bridgeStatusCmd.action;

			if(action == FPP_STAT_RESET)
			{
				/* Reset the packet counter for all Bridge Entries */	
				for(x=0; x<NUM_BT_ENTRIES;x++) {

					slist_for_each(pEntry, entry, &bridge_cache[x], list)
					{
						pEntry->total_packets_transmitted = 0;
					}			
				}

			}
			else if( (action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
			{
				gStatBridgeQueryStatus = 0;
				if(action == FPP_STAT_QUERY_RESET)
					gStatBridgeQueryStatus |= STAT_BRIDGE_QUERY_RESET;
				rx_Get_Next_Hash_Stat_BridgeEntry((PStatBridgeEntryResponse)pcmd, 1);
			}
			else
				ackstatus = ERR_WRONG_COMMAND_PARAM;
		}
		else
#endif
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;

		break;
	}


	case CMD_STAT_BRIDGE_ENTRY:{
#if 0
		int result;
		
		PStatBridgeEntryResponse prsp = (PStatBridgeEntryResponse)pcmd;

                if((L2_BRIDGE_MODE_MANUAL == l2bridge_get_mode()) && (gFpCtrlStatFeatureBitMask & STAT_BRIDGE_BITMASK)) {
			
			result = rx_Get_Next_Hash_Stat_BridgeEntry(prsp, 0);
			if (result != NO_ERR )
			{
				prsp->eof = 1;
			}
			acklen = sizeof(StatBridgeEntryResponse);
		}
		else
#endif
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		
		break;
	}



	case CMD_STAT_IPSEC_STATUS:
	{
		int x;
		PSAEntry pEntry;
		struct slist_entry *entry;
		StatIpsecStatusCmd ipsecStatusCmd;

		// Ensure alignment
		memcpy((U8*)&ipsecStatusCmd, (U8*)pcmd, sizeof(StatIpsecStatusCmd));

		action = ipsecStatusCmd.action;

		if(action == FPP_STAT_RESET)
		{
			/* Reset the packet counter for all SA Entries */	
			for(x=0; x<NUM_SA_ENTRIES;x++) {

				slist_for_each(pEntry, entry, &sa_cache_by_h[x], list_h)
				{
					#if !defined(COMCERTO_2000)
						pEntry->total_pkts_processed = 0;
						pEntry->total_bytes_processed = 0;
					#endif
				}
			}

		}
		else if( (action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatIpsecQueryStatus = 0;
			
			if(action == FPP_STAT_QUERY_RESET)
			{
				gStatIpsecQueryStatus |= STAT_IPSEC_QUERY_RESET;
			}
			
			/* This function just initializes the static variables and returns */
			stat_Get_Next_SAEntry((PStatIpsecEntryResponse)pcmd, 1);
			
		}

		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}


	case CMD_STAT_IPSEC_ENTRY:
	{
		int  result; 
		//PSAEntry pEntry;
		PStatIpsecEntryResponse prsp = (PStatIpsecEntryResponse)pcmd;

		result = stat_Get_Next_SAEntry(prsp, 0);
		if (result != NO_ERR)
		{
			prsp->eof = 1;
		}

		acklen = sizeof(StatIpsecEntryResponse);

		break;
	}
	
	case CMD_STAT_VLAN_STATUS:
	{
		int x;
		PVlanEntry pEntry;
		struct slist_entry *entry;
		StatVlanStatusCmd vlanStatusCmd;	

		// Ensure alignment
		memcpy((U8*)&vlanStatusCmd, (U8*)pcmd, sizeof(StatVlanStatusCmd));

		action = vlanStatusCmd.action;

		if (action == FPP_STAT_RESET)
		{
			/* Reset the packet counters for all VLAN Entries */
			for (x = 0; x < NUM_VLAN_ENTRIES; x++)
			{
				slist_for_each(pEntry, entry, &vlan_cache[x], list)
					stat_vlan_reset(pEntry);
			}
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatVlanQueryStatus = 0;
			if (action == FPP_STAT_QUERY_RESET)
				gStatVlanQueryStatus |= STAT_VLAN_QUERY_RESET;

			stat_VLAN_Get_Next_SessionEntry((PStatVlanEntryResponse)pcmd, 1);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;

		break;
	}


	case CMD_STAT_VLAN_ENTRY:
	{
		int result;
		
		PStatVlanEntryResponse prsp = (PStatVlanEntryResponse)pcmd;

		result = stat_VLAN_Get_Next_SessionEntry(prsp, 0);
		if (result != NO_ERR)
		{
			prsp->eof = 1;
		}

		acklen = sizeof(StatVlanEntryResponse);
		break;
	}

	case CMD_STAT_TUNNEL_STATUS:
	{
		int x;
		PTnlEntry pEntry;
		struct slist_entry *entry;
		StatTunnelStatusCmd tunnelStatusCmd;

		// Ensure alignment
		memcpy((U8*)&tunnelStatusCmd, (U8*)pcmd, sizeof(StatTunnelStatusCmd));

		action = tunnelStatusCmd.action;
		if (action == FPP_STAT_RESET)
		{
			/* Reset the packet counters for all Tunnel Entries */
			for (x = 0; x < NUM_GRE_TUNNEL_ENTRIES; x++)
			{
				slist_for_each(pEntry, entry, &gre_tunnel_cache[x], list)
					stat_tunnel_reset(pEntry);
			}
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			gStatTunnelQueryStatus = 0;
			if (action == FPP_STAT_QUERY_RESET)
				gStatTunnelQueryStatus |= STAT_TUNNEL_QUERY_RESET;

			stat_tunnel_Get_Next_SessionEntry((PStatTunnelEntryResponse)pcmd, 1);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}


	case CMD_STAT_TUNNEL_ENTRY:
	{
		int result;

		PStatTunnelEntryResponse prsp = (PStatTunnelEntryResponse)pcmd;

		result = stat_tunnel_Get_Next_SessionEntry(prsp, 0);
		if (result != NO_ERR)
		{
			prsp->eof = 1;
		}
		acklen = sizeof(StatTunnelEntryResponse);
		break;
	}

#else	// TODO_STATS

#endif	// TODO_STATS

	case CMD_STAT_FLOW:
	{
		StatFlowStatusCmd flowEntryCmd;
		PStatFlowEntryResp pflowEntryResp;
		int i;

		if (!(stats_bitmask_enable_g & STAT_FLOW_BITMASK))
		{
			ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
			*pcmd = ackstatus;
			return acklen;
		}
		memcpy((U8*)&flowEntryCmd, (U8*)pcmd, sizeof(StatFlowStatusCmd));
		pflowEntryResp = (PStatFlowEntryResp)pcmd;

		action = flowEntryCmd.action;
		if (action == FPP_STAT_RESET)
		{
			ResetAllFlowStats();	/* Reset the statistics for all IPv4/IPv6 Entries */	
		}
		else if ((action == FPP_STAT_QUERY) || (action == FPP_STAT_QUERY_RESET))
		{
			pflowEntryResp->ip_family = flowEntryCmd.ip_family;
			if (pflowEntryResp->ip_family == 4)
			{
				pflowEntryResp->Saddr = flowEntryCmd.Saddr;
				pflowEntryResp->Daddr = flowEntryCmd.Daddr;
			}
			else
			{
				for (i = 0; i < 4; i++)
				{
					pflowEntryResp->Saddr_v6[i] = flowEntryCmd.Saddr_v6[i];
					pflowEntryResp->Daddr_v6[i] = flowEntryCmd.Daddr_v6[i];
				}
			}
			pflowEntryResp->Sport = flowEntryCmd.Sport;
			pflowEntryResp->Dport = flowEntryCmd.Dport;
			pflowEntryResp->Protocol = flowEntryCmd.Protocol;
			if ((ackstatus = Get_Flow_stats(pflowEntryResp, action == FPP_STAT_QUERY_RESET)) == NO_ERR)
				acklen = sizeof(StatFlowEntryResp);
		}
		else
			ackstatus = ERR_WRONG_COMMAND_PARAM;
		break;
	}
	
	case FPP_CMD_IPR_V4_STATS:
		{
			int rc;
			rc = cdx_get_ipr_v4_stats((void *)pcmd);
			if (rc  == -1)
				ackstatus = ERR_WRONG_COMMAND_PARAM;		
			else
				acklen = (U16)rc;

		}
		break;

	case FPP_CMD_IPR_V6_STATS:
		{
			int rc;
			rc = cdx_get_ipr_v6_stats((void *)pcmd);
			if (rc  == -1)
				ackstatus = ERR_WRONG_COMMAND_PARAM;		
			else
				acklen = (U16)rc;
		}
		break;
	default:
		ackstatus = ERR_STAT_FEATURE_NOT_ENABLED;
		break;
	}

	*pcmd = ackstatus;
	return acklen;
}


int statistics_init(void)
{
	set_cmd_handler(EVENT_STAT, M_stat_cmdproc);

	return 0;
}

void statistics_exit(void)
{

}


