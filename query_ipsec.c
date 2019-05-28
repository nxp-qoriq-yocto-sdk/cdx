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


#ifdef DPA_IPSEC_OFFLOAD 
//#include "module_ipsec.h"
//#include "module_tunnel.h"
#include "cdx.h"
#include "cdx_common.h"
#include "fe.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_ipsec.h"
#include "cdx_dpa_ipsec.h"

/*
 * Codes  - copied from module-ipsec_c2000.h 
 * look like cmm -c query SA depend on this
 * numbers for algo.
 */
#define ELP_HMAC_NULL	0
#define ELP_HMAC_MD5	1
#define ELP_HMAC_SHA1	2
#define ELP_HMAC_SHA2	3
#define ELP_GCM64	4
#define ELP_GCM96	5
#define ELP_GCM128	6

#define ELP_CIPHER_NULL 0
#define ELP_CIPHER_DES	 1
#define ELP_CIPHER_3DES 2
#define ELP_CIPHER_AES128 3
#define ELP_CIPHER_AES192 4
#define ELP_CIPHER_AES256 5
#define ELP_CIPHER_AES128_GCM 6
#define ELP_CIPHER_AES192_GCM 7
#define ELP_CIPHER_AES256_GCM 8
#define ELP_CIPHER_AES128_CTR 9
#define ELP_CIPHER_AES192_CTR 10
#define ELP_CIPHER_AES256_CTR 11

/* This function returns total SA entries configured with a given handle */
static int IPsec_Get_Hash_SAEntries(int sa_handle_index)
{
	
	int tot_sa_entries = 0;
	PSAEntry  pSAEntry;
	struct slist_entry *entry;
	
	slist_for_each(pSAEntry, entry, &sa_cache_by_h[sa_handle_index], list_h)
	{
		tot_sa_entries++;
	}
		

	return tot_sa_entries;

}
static int Ipsec_Get_SAalgo(PSAEntry  pSAEntry, U8  *key_algo)  
{
 U8 auth_algo;
 U8 cipher_algo;
  
        switch (pSAEntry->pSec_sa_context->cipher_data.cipher_type) {
                case OP_PCL_IPSEC_AES_CTR:
                        //cipher_algo = SADB_X_EALG_AESCTR ;
                        cipher_algo =ELP_CIPHER_AES128_CTR ;
                        break;
                case OP_PCL_IPSEC_AES_CBC:
                        if (pSAEntry->pSec_sa_context->cipher_data.cipher_key_len == 128/8)
                                cipher_algo = ELP_CIPHER_AES128;
                        else if (pSAEntry->pSec_sa_context->cipher_data.cipher_key_len == 192/8)
                                cipher_algo = ELP_CIPHER_AES192;
                        else if (pSAEntry->pSec_sa_context->cipher_data.cipher_key_len == 256/8)
                                cipher_algo = ELP_CIPHER_AES256;
                        else
                                return -1;
           //             cipher_algo =SADB_X_EALG_AESCBC ;
                        break;
                case OP_PCL_IPSEC_3DES:
                        //cipher_algo =SADB_EALG_3DESCBC ;
                        cipher_algo = ELP_CIPHER_3DES ;
                        break;
                case OP_PCL_IPSEC_DES:
                        //cipher_algo =SADB_EALG_DESCBC ;
                        cipher_algo = ELP_CIPHER_DES;
                        break;
                case OP_PCL_IPSEC_NULL_ENC:
                        //cipher_algo  =SADB_EALG_NULL ;
                        cipher_algo  = ELP_CIPHER_NULL ;
                        break;
                default:
                        return -1;
        }
	switch (pSAEntry->pSec_sa_context->auth_data.auth_type) {
                case OP_PCL_IPSEC_HMAC_MD5_96 :
                        //auth_algo = SADB_AALG_MD5HMAC;
                        auth_algo = ELP_HMAC_MD5;
                        break;
                case OP_PCL_IPSEC_HMAC_SHA1_96:
                        //auth_algo = SADB_AALG_SHA1HMAC ;
                        auth_algo = ELP_HMAC_SHA1 ;
                        break;
                case OP_PCL_IPSEC_HMAC_SHA2_256_128:
                        //auth_algo = SADB_X_AALG_SHA2_256HMAC ;
                        auth_algo = ELP_HMAC_SHA2;
                        break;
                case OP_PCL_IPSEC_HMAC_NULL:
                        //auth_algo = SADB_X_AALG_NULL ;
                        auth_algo = ELP_HMAC_NULL ;
                        break;
                default:
                        return -1;
        }
	*key_algo   = (( cipher_algo << 4) | auth_algo);
	return NO_ERR;	

}
/* This function fillgo;
ls the snapshot of SA entries in a given handle hash index */
static int IPsec_SA_Get_Handle_Snapshot(int sa_handle_index, int sa_entries, PSAQueryCommand pSAHandleSnapshot)
{
	
	int tot_sa_entries=0;
	PSAEntry pSAEntry;
	struct slist_entry *entry;
			
	slist_for_each(pSAEntry, entry, &sa_cache_by_h[sa_handle_index], list_h)
	{

	    pSAHandleSnapshot->src_ip[0] = pSAEntry->id.saddr[0];
	    pSAHandleSnapshot->src_ip[1] = pSAEntry->id.saddr[1];
	    pSAHandleSnapshot->src_ip[2] = pSAEntry->id.saddr[2];
	    pSAHandleSnapshot->src_ip[3] = pSAEntry->id.saddr[3];
	    pSAHandleSnapshot->dst_ip[0] = pSAEntry->id.daddr.a6[0];
	    pSAHandleSnapshot->dst_ip[1] = pSAEntry->id.daddr.a6[1];
	    pSAHandleSnapshot->dst_ip[2] = pSAEntry->id.daddr.a6[2];
	    pSAHandleSnapshot->dst_ip[3] = pSAEntry->id.daddr.a6[3];
	    pSAHandleSnapshot->spi       = pSAEntry->id.spi;
	    pSAHandleSnapshot->sa_type 	 = pSAEntry->id.proto;
	    pSAHandleSnapshot->family 	 = pSAEntry->family;
	    pSAHandleSnapshot->handle 	 = pSAEntry->handle;
	    pSAHandleSnapshot->mtu	 	 = pSAEntry->mtu;
	    pSAHandleSnapshot->state 	 = pSAEntry->state;
	    pSAHandleSnapshot->flags = pSAEntry->flags;
	    	
	    	if (pSAEntry->flags & SA_ALLOW_SEQ_ROLL)
	       		pSAHandleSnapshot->replay_window = 0x1;
	    	else
	    		pSAHandleSnapshot->replay_window = 0x0;
	    if(pSAEntry->pSec_sa_context)
	    {
		Ipsec_Get_SAalgo( pSAEntry, &pSAHandleSnapshot->key_alg );  
        	memcpy(&pSAHandleSnapshot->auth_key[0],
			pSAEntry->pSec_sa_context->auth_data.auth_key,
                	pSAEntry->pSec_sa_context->auth_data.auth_key_len);

        	memcpy(&pSAHandleSnapshot->cipher_key[0],
			pSAEntry->pSec_sa_context->cipher_data.cipher_key,
               		pSAEntry->pSec_sa_context->cipher_data.cipher_key_len);


	    }
	    if (pSAEntry->mode == SA_MODE_TUNNEL)
	    {
	    	pSAHandleSnapshot->mode = SA_MODE_TUNNEL;
	    	if (pSAEntry->header_len == IPV4_HDR_SIZE)
	    	{
			pSAHandleSnapshot->tunnel_proto_family = PROTO_FAMILY_IPV4;
			pSAHandleSnapshot->tnl.ipv4.DestinationAddress = pSAEntry->tunnel.ip4.DestinationAddress;	    		
			pSAHandleSnapshot->tnl.ipv4.SourceAddress = pSAEntry->tunnel.ip4.SourceAddress;
			pSAHandleSnapshot->tnl.ipv4.TypeOfService   = pSAEntry->tunnel.ip4.TypeOfService;
			pSAHandleSnapshot->tnl.ipv4.Protocol = pSAEntry->tunnel.ip4.Protocol;
			pSAHandleSnapshot->tnl.ipv4.TotalLength = pSAEntry->tunnel.ip4.TotalLength;	
	    	}
	    	else
	    	{
			pSAHandleSnapshot->tunnel_proto_family = PROTO_FAMILY_IPV6;
			pSAHandleSnapshot->tnl.ipv6.DestinationAddress[0] = pSAEntry->tunnel.ip6.DestinationAddress[0];
			pSAHandleSnapshot->tnl.ipv6.DestinationAddress[1] = pSAEntry->tunnel.ip6.DestinationAddress[1];
			pSAHandleSnapshot->tnl.ipv6.DestinationAddress[2] = pSAEntry->tunnel.ip6.DestinationAddress[2];
			pSAHandleSnapshot->tnl.ipv6.DestinationAddress[3] = pSAEntry->tunnel.ip6.DestinationAddress[3];
				
			pSAHandleSnapshot->tnl.ipv6.SourceAddress[0] = pSAEntry->tunnel.ip6.SourceAddress[0];
			pSAHandleSnapshot->tnl.ipv6.SourceAddress[1] = pSAEntry->tunnel.ip6.SourceAddress[1];
			pSAHandleSnapshot->tnl.ipv6.SourceAddress[2] = pSAEntry->tunnel.ip6.SourceAddress[2];
			pSAHandleSnapshot->tnl.ipv6.SourceAddress[3] = pSAEntry->tunnel.ip6.SourceAddress[3];
			IPV6_SET_TRAFFIC_CLASS(&pSAHandleSnapshot->tnl.ipv6, IPV6_GET_TRAFFIC_CLASS(&pSAEntry->tunnel.ip6));
			IPV6_SET_VERSION(&pSAHandleSnapshot->tnl.ipv6, IPV6_GET_VERSION(&pSAEntry->tunnel.ip6));
			IPV6_COPY_FLOW_LABEL(&pSAHandleSnapshot->tnl.ipv6, &pSAEntry->tunnel.ip6);
	    	}
	    }
	    
	   
	    pSAHandleSnapshot->soft_byte_limit = pSAEntry->lft_conf.soft_byte_limit;
	    pSAHandleSnapshot->hard_byte_limit = pSAEntry->lft_conf.hard_byte_limit;
	    pSAHandleSnapshot->soft_packet_limit = pSAEntry->lft_conf.soft_packet_limit;
	    pSAHandleSnapshot->hard_packet_limit = pSAEntry->lft_conf.hard_packet_limit;

	    	
	    
	    pSAHandleSnapshot++;
	    tot_sa_entries++;
	    if(--sa_entries <= 0)
		break;
	}
		
	
	return tot_sa_entries;

}


/* This function creates the snapshot memory  for SAs and returns the 
   next SA entry from the snapshot of the SA entries of a
   single handle to the caller  */
   
int IPsec_Get_Next_SAEntry(PSAQueryCommand  pSAQueryCmd, int reset_action)
{
	int ipsec_sa_hash_entries;
	PSAQueryCommand pSACmd;
	static PSAQueryCommand pSASnapshot = NULL;
	static int sa_hash_index = 0, sa_snapshot_entries =0, sa_snapshot_index=0 , sa_snapshot_buf_entries = 0;
	
	if(reset_action)
	{
		sa_hash_index = 0;
		sa_snapshot_entries =0;
		sa_snapshot_index=0;
		if(pSASnapshot)
		{
			Heap_Free(pSASnapshot);
			pSASnapshot = NULL;
		}
		sa_snapshot_buf_entries = 0;
	}
	
	if (sa_snapshot_index == 0)
	{
		while( sa_hash_index < NUM_SA_ENTRIES)
		{
		
			ipsec_sa_hash_entries = IPsec_Get_Hash_SAEntries(sa_hash_index);
			if(ipsec_sa_hash_entries == 0)
			{
				sa_hash_index++;
				continue;
			}
	   	
	   		if(ipsec_sa_hash_entries > sa_snapshot_buf_entries)
	   		{
	   			if(pSASnapshot)
	   				Heap_Free(pSASnapshot);
	   			   		
				pSASnapshot = Heap_Alloc(ipsec_sa_hash_entries * sizeof(SAQueryCommand));
			
				if (!pSASnapshot)
				{
			    	sa_hash_index = 0;
			    	sa_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				sa_snapshot_buf_entries = ipsec_sa_hash_entries;
	   		}
			sa_snapshot_entries = IPsec_SA_Get_Handle_Snapshot(sa_hash_index , ipsec_sa_hash_entries,pSASnapshot);
			
			break;
		}
		
		if (sa_hash_index >= NUM_SA_ENTRIES)
		{
			sa_hash_index = 0;
			if (pSASnapshot)
			{
				Heap_Free(pSASnapshot);
				pSASnapshot = NULL;	
			}
			sa_snapshot_buf_entries = 0;
			return ERR_SA_ENTRY_NOT_FOUND;
		}
		   
	}


	pSACmd = &pSASnapshot[sa_snapshot_index++];
	memcpy(pSAQueryCmd, pSACmd, sizeof(SAQueryCommand));
	if (sa_snapshot_index == sa_snapshot_entries)
	{
		sa_snapshot_index = 0;
		sa_hash_index ++;
	}

	
	return NO_ERR;	
		
}



#ifdef CFG_STATS
extern int ExternalHashTableEntryGetStatsAndTS(void *tbl_entry,
                                struct dpa_cls_tbl_entry_stats *stats);

/* This function fills the snapshot of SA entries 
   in a given hash index, statReset = 1 resets the stats of SA. */

static int stat_Get_SA_Hash_Snapshot(int sa_hash_index, int sa_entries,
                                     PStatIpsecEntryResponse pStatSASnapshot)
{
	
	int tot_sa_entries=0;
	PSAEntry pSAEntry;
	struct slist_entry *entry;
	u32 last_bytes, last_bytes_up32;
	struct dpa_cls_tbl_entry_stats stats;

		
	slist_for_each(pSAEntry, entry, &sa_cache_by_h[sa_hash_index], list_h)
	{
		pStatSASnapshot->spi  		= ntohl(pSAEntry->id.spi);
		pStatSASnapshot->proto		= pSAEntry->id.proto;
		pStatSASnapshot->family		= pSAEntry->family;
		pStatSASnapshot->dstIP[0] 	= pSAEntry->id.daddr.a6[0];
		pStatSASnapshot->dstIP[1] 	= pSAEntry->id.daddr.a6[1];
		pStatSASnapshot->dstIP[2] 	= pSAEntry->id.daddr.a6[2];
		pStatSASnapshot->dstIP[3] 	= pSAEntry->id.daddr.a6[3];
		
		memset(&stats, 0, sizeof(struct dpa_cls_tbl_entry_stats));
		if(pSAEntry->ct){
			ExternalHashTableEntryGetStatsAndTS(pSAEntry->ct->handle, &stats);
              		pStatSASnapshot->total_pkts_processed  = stats.pkts;
                	pStatSASnapshot->total_bytes_processed[0]       =
                                   stats.bytes  & 0xffffffff;

                	pStatSASnapshot->total_bytes_processed[1]       =
                                    (stats.bytes  >> 32) & 0xffffffff;
				(unsigned long)stats.pkts,(unsigned long)stats.bytes );
		}
		pStatSASnapshot->eof = 0;
		pStatSASnapshot->sagd = pSAEntry->handle;
		pStatSASnapshot++;
		tot_sa_entries++;

		if(--sa_entries <= 0)
			break;

	}
		
	printk (KERN_ERR "total_sa_entries:%x\n", tot_sa_entries);
	return tot_sa_entries;

}

/* This function creates the snapshot memory and returns the 
   next SA entry from the snapshop of the SA entries of a
   single hash to the caller (statReset = 1 resets the stats) */

int stat_Get_Next_SAEntry(PStatIpsecEntryResponse pSACmd, int reset_action)
{
	int stat_sa_hash_entries;
	PStatIpsecEntryResponse pSA;
	static PStatIpsecEntryResponse pStatSASnapshot = NULL;
	static int stat_sa_hash_index = 0, stat_sa_snapshot_entries =0, stat_sa_snapshot_index=0, stat_sa_snapshot_buf_entries = 0;
	
	if(reset_action)
	{
		stat_sa_hash_index = 0;
		stat_sa_snapshot_entries =0;
		stat_sa_snapshot_index=0;
		if(pStatSASnapshot)
		{
			Heap_Free(pStatSASnapshot);
			pStatSASnapshot = NULL;	
		}
		stat_sa_snapshot_buf_entries = 0;
		return NO_ERR;
	}
	
	if (stat_sa_snapshot_index == 0)
	{
		while( stat_sa_hash_index < NUM_SA_ENTRIES)
		{
		
			stat_sa_hash_entries = IPsec_Get_Hash_SAEntries(stat_sa_hash_index);
			if(stat_sa_hash_entries == 0)
			{
				stat_sa_hash_index++;
				continue;
			}
		   	
		   	if (stat_sa_hash_entries > stat_sa_snapshot_buf_entries)
		   	{
		   		if(pStatSASnapshot)
					Heap_Free(pStatSASnapshot);	   	
				pStatSASnapshot = Heap_Alloc(stat_sa_hash_entries * sizeof(StatIpsecEntryResponse));
			
				if (!pStatSASnapshot)
				{
			    	stat_sa_hash_index = 0;
			    	stat_sa_snapshot_buf_entries = 0;
					return ERR_NOT_ENOUGH_MEMORY;
				}
				stat_sa_snapshot_buf_entries = 	stat_sa_hash_entries;
		   	}
			stat_sa_snapshot_entries = stat_Get_SA_Hash_Snapshot(stat_sa_hash_index , stat_sa_hash_entries, pStatSASnapshot);
			break;
		}
		
		if (stat_sa_hash_index >= NUM_SA_ENTRIES)
		{
			stat_sa_hash_index = 0;
			if(pStatSASnapshot)
			{
				Heap_Free(pStatSASnapshot);
				pStatSASnapshot = NULL;
			}
			stat_sa_snapshot_buf_entries = 0;
			return ERR_SA_ENTRY_NOT_FOUND;
		}
		   
	}
	
	pSA = &pStatSASnapshot[stat_sa_snapshot_index++];
	memcpy(pSACmd, pSA, sizeof(StatIpsecEntryResponse));
	if (stat_sa_snapshot_index == stat_sa_snapshot_entries)
	{
		stat_sa_snapshot_index = 0;
		stat_sa_hash_index ++;
	}
		
	
	return NO_ERR;	
}

#endif /* CFG_STATS */
#endif  // DPA_IPSEC_OFFLOAD
