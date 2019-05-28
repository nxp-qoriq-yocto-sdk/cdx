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
#include "dpaa_eth_common.h"
#include "cdx.h"
#include "cdx_common.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "layer2.h"
//#include "module_hidrv.h"
#include "control_ipsec.h"
#include "cdx_dpa_ipsec.h"
//#include "module_socket.h"

//#define CONTROL_IPSEC_DEBUG 1

#define SOCKET_NATT	0

TIMER_ENTRY sa_timer;
int IPsec_Get_Next_SAEntry(PSAQueryCommand  pSAQueryCmd, int reset_action);
//static int IPsec_Free_Natt_socket_v6(PSAEntry sa);
//static int IPsec_Free_Natt_socket_v4(PSAEntry sa);

U16 M_ipsec_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd);
static int IPsec_handle_CREATE_SA(U16 *p, U16 Length);
static int IPsec_handle_DELETE_SA(U16 *p, U16 Length);
static int IPsec_handle_FLUSH_SA(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_KEYS(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_TUNNEL(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_NATT(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_STATE(U16 *p, U16 Length);
static int IPsec_handle_SA_SET_LIFETIME(U16 *p, U16 Length);
static int IPsec_handle_FRAG_CFG(U16 *p, U16 Length);
struct slist_head sa_cache_by_spi[NUM_SA_ENTRIES];
struct slist_head sa_cache_by_h[NUM_SA_ENTRIES];

struct slist_head dpa_sa_context_list;
#ifdef PRINT_OFFLOAD_PKT_COUNT 
extern void print_ipsec_offload_pkt_count(void);
#endif
extern void print_ipsec_exception_pkt_cnt(void);
extern int ExternalHashTableEntryGetStatsAndTS(void *tbl_entry,
                                struct en_tbl_entry_stats *stats);

static void sa_free(PSAEntry pSA)
{
	Heap_Free(pSA);
}

static PSAEntry sa_alloc(void)
{
	PSAEntry pSA = NULL;
	pSA = Heap_Alloc_ARAM(sizeof(SAEntry));	
        if(pSA)
		memset(pSA, 0, sizeof(SAEntry));
	return (pSA);
}

static int sa_add(PSAEntry pSA)
{
	/* TODO
         * We should alloc A DPA Sec SA context here. - Rajendran 6 Oct  2016
         */
	slist_add(&sa_cache_by_h[pSA->hash_by_h], &pSA->list_h);
	slist_add(&sa_cache_by_spi[pSA->hash_by_spi], &pSA->list_spi);

	return NO_ERR;
}

static void sa_remove(PSAEntry pSA, U32 hash_by_h, U32 hash_by_spi)
{

	slist_remove(&sa_cache_by_h[hash_by_h], &pSA->list_h);
	slist_remove(&sa_cache_by_spi[hash_by_spi], &pSA->list_spi);
#if 0
      /* TODO
       *   We will handle the NATT case later - Rajendran 06 Oct 2016
       */ 
	/* Delete NATT Socket attached */
	if ((pSA->header_len == IPV6_HDR_SIZE) && (pSA->natt.socket))
		IPsec_Free_Natt_socket_v6(pSA);
	/* Delete NATT Socket attached */
	else if ((pSA->header_len == IPV4_HDR_SIZE) && (pSA->natt.socket))
		IPsec_Free_Natt_socket_v4(pSA);
#endif
	/*
        * remove the table entry and free the Sec_SA context
        */
        cdx_ipsec_release_sa_resources(pSA);
	sa_free(pSA);
}

void*  M_ipsec_get_sa_netdev( U16 handle)
{
        U16 hash = handle & (NUM_SA_ENTRIES -1);
        PSAEntry pEntry;
        struct net_device *net_dev = NULL;
        struct slist_entry *entry;

        slist_for_each(pEntry, entry, &sa_cache_by_h[hash], list_h)
        {
                if (pEntry->handle == handle)
                        net_dev = pEntry->netdev;
        }
        return net_dev;
}

void*  M_ipsec_sa_cache_lookup_by_h( U16 handle)
{
	U16 hash = handle & (NUM_SA_ENTRIES -1);
	PSAEntry pEntry;
	PSAEntry pSA = NULL;
	struct slist_entry *entry;

	slist_for_each(pEntry, entry, &sa_cache_by_h[hash], list_h)
	{
		if (pEntry->handle == handle)
			pSA = pEntry;
	}
	return pSA;
}

void* M_ipsec_sa_cache_lookup_by_spi(U32 *daddr, U32 spi, U8 proto, U8 family)
{
	U32     hash_key_sa;
	PSAEntry pSA = NULL;
	PSAEntry pEntry;
	struct slist_entry *entry;

	hash_key_sa = HASH_SA(daddr, spi, proto, family);
	slist_for_each(pEntry, entry, &sa_cache_by_spi[hash_key_sa], list_spi)
	{
		if ( (pEntry->id.proto == proto) &&
				(pEntry->id.spi == spi) &&
				(pEntry->id.daddr.a6[0] == daddr[0]) &&
				(pEntry->id.daddr.a6[1] == daddr[1]) &&
				(pEntry->id.daddr.a6[2] == daddr[2]) &&
				(pEntry->id.daddr.a6[3] == daddr[3])&&
				(pEntry->family != family))
		{
			pSA = pEntry;
		}


	}

	return pSA;
}


static int M_ipsec_sa_set_digest_key(PSAEntry sa, U16 key_alg, U16 key_bits, U8* key)
{
	U16      algo;

	switch (key_alg) {
		case SADB_AALG_MD5HMAC:
			algo =OP_PCL_IPSEC_HMAC_MD5_96;
			break;
		case SADB_AALG_SHA1HMAC:
			algo = OP_PCL_IPSEC_HMAC_SHA1_96;
			break;
		case SADB_X_AALG_SHA2_256HMAC:
			algo = OP_PCL_IPSEC_HMAC_SHA2_256_128;
			break;
		case SADB_X_AALG_NULL:
			algo  =OP_PCL_IPSEC_HMAC_NULL;
			break;
		default:
			return -1;
	}
	sa->pSec_sa_context->auth_data.auth_type = algo;
 	sa->pSec_sa_context->auth_data.auth_key_len = (key_bits/8);
        memcpy(sa->pSec_sa_context->auth_data.auth_key,
               key, (key_bits/8));
      /* Generate the split key from the normal auth key */
	cdx_ipsec_generate_split_key(&sa->pSec_sa_context->auth_data );
	return 0;
}


static int M_ipsec_sa_set_cipher_key(PSAEntry sa, U16 key_alg, U16 key_bits, U8* key)
{
	U16      algo;

	switch (key_alg) {
		case SADB_X_EALG_AESCTR:
			algo = OP_PCL_IPSEC_AES_CTR;
			break;
		case SADB_X_EALG_AESCBC:
#if 0
			if (key_bits == 128)
				algo = ELP_CIPHER_AES128;
			else if (key_bits == 192)
				algo = ELP_CIPHER_AES192;
			else if (key_bits == 256)
				algo = ELP_CIPHER_AES256;
			else
				return -1;
#endif
			algo = OP_PCL_IPSEC_AES_CBC;
			sa->blocksz = 16;
			break;
		case SADB_EALG_3DESCBC:
			algo = OP_PCL_IPSEC_3DES;
			sa->blocksz = 8;
			break;
		case SADB_EALG_DESCBC:
			algo = OP_PCL_IPSEC_DES;
			sa->blocksz = 8;
			break;
		case SADB_EALG_NULL:
			algo  = OP_PCL_IPSEC_NULL_ENC;
			sa->blocksz = 0;
			break;
		default:
			return -1;
	}
	sa->pSec_sa_context->cipher_data.cipher_type =algo ;
	sa->pSec_sa_context->cipher_data.cipher_key_len =
                (key_bits/8);
        memcpy(sa->pSec_sa_context->cipher_data.cipher_key,
               key, (key_bits/8));

	return 0;
}
#if 0
/* NAT-T modifications*/
static PSock6Entry IPsec_create_Natt_socket_v6(PSAEntry sa)
{
	PSock6Entry natt_socket;
	int res;

	//natt_socket = (PNatt_Socket_v6)Heap_Alloc(sizeof (Natt_Socket_v6));
	natt_socket = socket6_alloc();

	if(natt_socket == NULL)
		return NULL;

	memset(natt_socket , 0, sizeof(Sock6Entry));
	natt_socket->SocketFamily = PROTO_IPV6;
	natt_socket->SocketType = SOCKET_TYPE_FPP;
	natt_socket->owner_type = SOCK_OWNER_NATT;
	natt_socket->Dport = cpu_to_be16(sa->natt.dport);
	natt_socket->Sport = cpu_to_be16(sa->natt.sport);
	natt_socket->proto = IPPROTOCOL_UDP;
	natt_socket->connected = 1; /* Connected socket use 5 tuples */
	natt_socket->SocketID = SOCKET_NATT; /* Need to use some socket which is not used at all */
	if (sa->mode == SA_MODE_TUNNEL) {
		memcpy((U8*)&natt_socket->Saddr_v6[0],(U8*) &sa->tunnel.ip6.SourceAddress[0], IPV6_ADDRESS_LENGTH);
		memcpy((U8*)&natt_socket->Daddr_v6[0], (U8*)&sa->tunnel.ip6.DestinationAddress[0], IPV6_ADDRESS_LENGTH);
	}
	else if (sa->mode == SA_MODE_TRANSPORT) {
		memcpy((U8*)&natt_socket->Saddr_v6[0],(U8*) &sa->id.saddr[0], IPV6_ADDRESS_LENGTH);
		memcpy((U8*)&natt_socket->Daddr_v6[0], (U8*)&sa->id.daddr.a6[0], IPV6_ADDRESS_LENGTH);
	}
	natt_socket->hash = HASH_SOCK6( natt_socket->Daddr_v6[IP6_LO_ADDR], natt_socket->Dport, natt_socket->proto);
	natt_socket->hash_by_id = HASH_SOCKID( natt_socket->SocketID);

	res = socket6_add(natt_socket);
	if (res != NO_ERR)
	{
		socket6_free(natt_socket);
		return NULL;
	}
	return (natt_socket);
}


static int IPsec_Free_Natt_socket_v6(PSAEntry sa)
{
	PSock6Entry natt_socket;
	U32 hash, hash_by_id;

	natt_socket = (PSock6Entry)sa->natt.socket;
	if (natt_socket == NULL)
		return ERR_SA_SOCK_ENTRY_NOT_FOUND;

	hash = HASH_SOCK6(natt_socket->Daddr_v6[IP6_LO_ADDR], natt_socket->Dport, natt_socket->proto);
	hash_by_id = HASH_SOCKID(natt_socket->SocketID);

	socket6_remove(natt_socket, hash, hash_by_id);

	return NO_ERR;
}

static PSockEntry IPsec_create_Natt_socket_v4(PSAEntry sa)
{
	PSockEntry natt_socket;
	int res;

	natt_socket = socket4_alloc();

	if (natt_socket == NULL)
		return NULL;

	memset(natt_socket , 0, sizeof(SockEntry));
	natt_socket->SocketFamily = PROTO_IPV4;
	natt_socket->SocketType = SOCKET_TYPE_FPP;
	natt_socket->owner_type = SOCK_OWNER_NATT;
	natt_socket->Dport = cpu_to_be16(sa->natt.dport);
	natt_socket->Sport = cpu_to_be16(sa->natt.sport);
	natt_socket->proto = IPPROTOCOL_UDP;
	natt_socket->connected = 1; /* Connected socket use 5 tuples */
	natt_socket->SocketID = SOCKET_NATT; /* DUMMY SOCKET for NATT */

	if (sa->mode == SA_MODE_TUNNEL) {
		natt_socket->Saddr_v4 = sa->tunnel.ip4.SourceAddress;
		natt_socket->Daddr_v4 = sa->tunnel.ip4.DestinationAddress;
	}
	else if (sa->mode == SA_MODE_TRANSPORT) {
		natt_socket->Saddr_v4 = sa->id.saddr[0];
		natt_socket->Daddr_v4 = sa->id.daddr.a6[0];
	}

	natt_socket->hash = HASH_SOCK(natt_socket->Daddr_v4, natt_socket->Dport, natt_socket->proto);
	natt_socket->hash_by_id = HASH_SOCKID(natt_socket->SocketID);

	res = socket4_add(natt_socket);
	if (res != NO_ERR)
	{
		socket4_free(natt_socket);
		return NULL;
	}
	return (natt_socket);
}

static int IPsec_Free_Natt_socket_v4(PSAEntry sa)
{
	PSockEntry natt_socket;
	U32 hash, hash_by_id;

	natt_socket = (PSockEntry)sa->natt.socket;
	if (natt_socket == NULL)
		return ERR_SA_SOCK_ENTRY_NOT_FOUND;

	hash = HASH_SOCK(natt_socket->Daddr_v4, natt_socket->Dport, natt_socket->proto);
	hash_by_id = HASH_SOCKID(natt_socket->SocketID);

	socket4_remove(natt_socket,hash,hash_by_id);
	return NO_ERR;
}
#endif 
void* M_ipsec_sa_cache_create(U32 *saddr,U32 *daddr, U32 spi, U8 proto, U8 family, U16 handle, U8 replay, U8 esn, U16 mtu, U16 dev_mtu, U8 dir)
{
	U32     hash_key_sa;
	PSAEntry sa;


	//sa = Heap_Alloc_ARAM(sizeof(SAEntry));
	sa = sa_alloc();
	if (sa) {
		memset(sa, 0, sizeof(SAEntry));
		hash_key_sa = HASH_SA(daddr, spi, proto, family);
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_INFO "%s hash_key_sa:%d\n", __func__,hash_key_sa);
#endif
		sa->id.saddr[0] = saddr[0];
		sa->id.saddr[1] = saddr[1];
		sa->id.saddr[2] = saddr[2];
		sa->id.saddr[3] = saddr[3];

		sa->id.daddr.a6[0] = daddr[0];
		sa->id.daddr.a6[1] = daddr[1];
		sa->id.daddr.a6[2] = daddr[2];
		sa->id.daddr.a6[3] = daddr[3];
		sa->id.spi = spi;
		sa->id.proto = proto;
		sa->family = family;
		sa->handle = handle;
		sa->mtu = mtu;
		sa->dev_mtu = dev_mtu;
		sa->state = SA_STATE_INIT;
		if (dir)
			sa->direction = CDX_DPA_IPSEC_INBOUND;
		else
			sa->direction = CDX_DPA_IPSEC_OUTBOUND;
		/* Look like staring seq number is not passed
		   In the shared descriptor we need to set this value.
		   hence for the time being setting to zero*/
		sa->seq = 0;
		sa->pSec_sa_context=cdx_ipsec_sec_sa_context_alloc(handle);
          	if(!sa->pSec_sa_context)
		{
			sa_free(sa);
			return NULL;
		}
		if (!replay)
			sa->flags |= SA_ALLOW_SEQ_ROLL;

		//Per RFC 4304 - Should be used by default for IKEv2, unless specified by SA configuration.

		sa->pSec_sa_context->auth_data.auth_type = OP_PCL_IPSEC_HMAC_NULL;
		sa->pSec_sa_context->cipher_data.cipher_type =OP_PCL_IPSEC_NULL_ENC;
		if(esn)
			sa->flags |= SA_ALLOW_EXT_SEQ_NUM;
		sa->hash_by_spi = hash_key_sa;
		sa->hash_by_h   =  handle & (NUM_SA_ENTRIES - 1);
#ifdef CONTROL_IPSEC_DEBUG
		printk("%s::sa %p, context %p handle %d dir %d\n",
			__FUNCTION__, sa, sa->pSec_sa_context, sa->hash_by_h, sa->direction);
#endif
		if (sa_add(sa) != NO_ERR)
		{
#ifdef CONTROL_IPSEC_DEBUG
			printk(KERN_INFO "%s sa_add failed\n", __func__);
#endif
			return NULL;

		}

	}
	return sa;
}

static int M_ipsec_sa_cache_delete(U16 handle)
{
	U32     hash_key_sa_by_spi;
	U32	hash_key_sa_by_h = handle & (NUM_SA_ENTRIES-1);
	PSAEntry pSA;


	pSA = M_ipsec_sa_cache_lookup_by_h(handle);
	if (!pSA)
		return ERR_SA_UNKNOWN;

	hash_key_sa_by_spi = HASH_SA(pSA->id.daddr.top, pSA->id.spi, pSA->id.proto, pSA->family);

	sa_remove(pSA , hash_key_sa_by_h , hash_key_sa_by_spi);
	return NO_ERR;
}


int IPsec_handle_CREATE_SA(U16 *p, U16 Length)
{
	CommandIPSecCreateSA cmd;
	U8 family;

	/* Check length */
	if (Length != sizeof(CommandIPSecCreateSA))
		return ERR_WRONG_COMMAND_SIZE;

	memset(&cmd, 0, sizeof(CommandIPSecCreateSA));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif
	family = (cmd.said.proto_family == PROTO_FAMILY_IPV4) ? PROTO_IPV4 : PROTO_IPV6;
	if (M_ipsec_sa_cache_lookup_by_spi((U32*) cmd.said.dst_ip , cmd.said.spi, cmd.said.sa_type , family)) {
		return ERR_SA_DUPLICATED;
	}
	if (M_ipsec_sa_cache_lookup_by_h(cmd.sagd)) {
		return ERR_SA_DUPLICATED;
	}

	if (M_ipsec_sa_cache_create((U32*)cmd.said.src_ip, (U32*)cmd.said.dst_ip , cmd.said.spi, cmd.said.sa_type , family, cmd.sagd, cmd.said.replay_window, (cmd.said.flags & NLKEY_SAFLAGS_ESN), cmd.said.mtu, cmd.said.dev_mtu, (cmd.said.flags & NLKEY_SAFLAGS_INBOUND))) {
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_CRIT "%s::spi %x, type %d, dstip %08x, sagd %d family %d flags %d\n",
        		    __FUNCTION__, cmd.said.spi, cmd.said.sa_type, cmd.said.dst_ip[0], 
            		cmd.sagd, cmd.said.proto_family, cmd.said.flags);
#endif
		return NO_ERR;
	}
	else
		return ERR_CREATION_FAILED;

}



static int IPsec_handle_DELETE_SA(U16 *p, U16 Length)
{
	CommandIPSecDeleteSA cmd;
	int rc;

	/* Check length */
	if (Length != sizeof(CommandIPSecDeleteSA))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecDeleteSA));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::sagd %d\n", __func__,
		cmd.sagd);
#endif

	rc = M_ipsec_sa_cache_delete(cmd.sagd);

	return (rc);

}
int cdx_ipsec_handle_get_inbound_sagd(U32 spi, U16 * sagd )
{
	PSAEntry pEntry;
	int i;

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::\n", __func__);
#endif
	// scan sa_cache and retrun matching handle
	for(i = 0; i < NUM_SA_ENTRIES; i++)
	{
		struct slist_entry *entry;
		slist_for_each_safe(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			//if((pEntry->direction == CDX_DPA_IPSEC_INBOUND) &&
			//	(pEntry->id.spi == spi)) { 
			if(pEntry->direction == CDX_DPA_IPSEC_INBOUND){ 
				*sagd = pEntry->handle ;
				return NO_ERR;
			}
		}
	}

	return ERR_CT_ENTRY_INVALID_SA;
}

static int IPsec_handle_FLUSH_SA(U16 *p, U16 Length)
{
	PSAEntry pEntry;
	int i;

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::\n", __func__);
#endif
	// scan sa_cache and delete sa
	for(i = 0; i < NUM_SA_ENTRIES; i++)
	{
		struct slist_entry *entry;
		slist_for_each_safe(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			U32  hash_key_sa_by_h = pEntry->handle & (NUM_SA_ENTRIES-1);
			U32  hash_key_sa_by_spi = HASH_SA(pEntry->id.daddr.top, pEntry->id.spi, pEntry->id.proto, pEntry->family);

			sa_remove(pEntry, hash_key_sa_by_h, hash_key_sa_by_spi);
		}
	}
	memset(sa_cache_by_h, 0, sizeof(struct slist_head)*NUM_SA_ENTRIES);
	memset(sa_cache_by_spi, 0, sizeof(struct slist_head)*NUM_SA_ENTRIES);
	return NO_ERR;
}

int IPsec_handle_SA_SET_KEYS(U16 *p, U16 Length)
{
	CommandIPSecSetKey cmd;
	PIPSec_key_desc key;
	PSAEntry sa;
	int i;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetKey))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecSetKey));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;
	for (i = 0;i<cmd.num_keys;i++) {
		key = (PIPSec_key_desc)&cmd.keys[i];
		if (key->key_type) {
			if (M_ipsec_sa_set_cipher_key(sa, key->key_alg, key->key_bits, key->key))
				return ERR_SA_INVALID_CIPHER_KEY;
		}
		else if (M_ipsec_sa_set_digest_key(sa, key->key_alg, key->key_bits, key->key))
			return ERR_SA_INVALID_DIGEST_KEY;
	}

	return NO_ERR;
}

int IPsec_handle_SA_SET_TUNNEL(U16 *p, U16 Length)
{
	CommandIPSecSetTunnel cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetTunnel))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecSetTunnel));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;
	if (cmd.proto_family == PROTO_FAMILY_IPV4) {
		sa->header_len = IPV4_HDR_SIZE;
		memcpy(&sa->tunnel.ip4, &cmd.h.ipv4h, sa->header_len);
		sa->tunnel.ip4.Protocol = IPPROTOCOL_ESP;
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_ERR "%s IPV4 Tunnel header, length= %d \n", __func__,sa->header_len);
	  printk(KERN_ERR " version %02x tos  %02x length  %04x \n ",cmd.h.ipv4h.Version_IHL,cmd.h.ipv4h.TypeOfService, cmd.h.ipv4h.TotalLength);
	  printk(KERN_ERR " Identification  %04x Flag_Frag %04x \n",cmd.h.ipv4h.Identification,cmd.h.ipv4h.Flags_FragmentOffset);
	  printk(KERN_ERR " TTL %02x protocol  %02x header check sum  %04x\n ",cmd.h.ipv4h.TTL,cmd.h.ipv4h.Protocol, cmd.h.ipv4h.HeaderChksum );
	  printk(KERN_ERR " Source %08x \n dest %08x \n ",cmd.h.ipv4h.SourceAddress,cmd.h.ipv4h.DestinationAddress );
#endif
	}
	else {
		sa->header_len = IPV6_HDR_SIZE;
		memcpy(&sa->tunnel.ip6, &cmd.h.ipv6h, sa->header_len);
		sa->tunnel.ip6.NextHeader = IPPROTOCOL_ESP;
	}

	sa->mode = SA_MODE_TUNNEL;
#if 0
       /* TODO
        * 
        * We need to add dpa specific logic here
        */  
	sa_update(sa);
#endif
	return NO_ERR;

}

static int IPsec_handle_SA_SET_NATT(U16 *p, U16 Length)
{
	CommandIPSecSetNatt  cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetNatt))
		return ERR_WRONG_COMMAND_SIZE;

	// NAT-T modifications
	memset(&cmd, 0, sizeof(CommandIPSecSetNatt));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::sagd %d\n", __func__,
		cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;

	// Add the socket information
	sa->natt.sport = htons(cmd.sport);
	sa->natt.dport = htons(cmd.dport);
	sa->natt.socket = NULL;

#if 0
        /* TODO
         *  NATT is currenly explored. 
         * Probabaly we should add UDP baseed Entry into In port classifcation table and should have the UDp header removed
         * before queuing packet to Sec
         **/
	if ((sa->family == PROTO_IPV6) && (sa->natt.sport) && (sa->natt.dport))
	{
		sa->natt.socket = IPsec_create_Natt_socket_v6(sa);
		if (sa->natt.socket == NULL)
		{
			sa->natt.sport = 0;
			sa->natt.dport = 0;
			return ERR_CREATION_FAILED;
		}
	}
	else if ((sa->family == PROTO_IPV4) && (sa->natt.sport) &&(sa->natt.dport))
	{
		sa->natt.socket = IPsec_create_Natt_socket_v4(sa);
		if (sa->natt.socket == NULL)
		{
			sa->natt.sport = 0;
			sa->natt.dport = 0;
			return ERR_CREATION_FAILED;
		}
	}
	sa_update(sa);
	// NAT-T configuration ends.
#endif
	return NO_ERR;
}

static int IPsec_handle_SA_SET_TNL_ROUTE(U16 *p, U16 Length)
{
	CommandIPSecSetTunnelRoute  cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetTunnelRoute))
		return ERR_WRONG_COMMAND_SIZE;

	memset(&cmd, 0, sizeof(CommandIPSecSetTunnelRoute));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;

	if (sa->mode != SA_MODE_TUNNEL)
		return ERR_SA_INVALID_MODE;

	if (sa->pRtEntry)
	{
		L2_route_put(sa->pRtEntry);
		sa->pRtEntry = NULL;
	}

	sa->route_id = cmd.route_id;
	sa->pRtEntry = L2_route_get(sa->route_id);
#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO " %s : route id = %d sa->pRtEntry = %p \n ",__func__ ,sa->route_id,sa->pRtEntry);
#endif
#if 0
        /* TODO
         * We need see how we can use this route information in case of DPA
         *                          - Rajendran 6 Oct 2016
         */
	sa_route_update(sa);
#endif
	return NO_ERR;
}

int IPsec_handle_SA_SET_STATE(U16 *p, U16 Length)
{
	CommandIPSecSetState cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetState))
		return ERR_WRONG_COMMAND_SIZE;
	memset(&cmd, 0, sizeof(CommandIPSecSetState));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s sagd %d\n", __func__, cmd.sagd);
#endif

	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;
#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "set_state:%x-%x\n", cmd.state , sa->state);
#endif
	if ((cmd.state == XFRM_STATE_VALID) &&  (sa->state == SA_STATE_INIT)) {
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_INFO "valid:\n");
#endif
	/* SA information is populated in various commands.
	* This will be the final command in the sequnce.  
	* So here we can push all the relevent information to DPAA.
	* a) populate  algorithm, key, tunnel header to shared descriptor.
	* b) create flow entry for encrypted traffic. 
	* For ipsec enabled traffic there will be total of 4 flows (considering  both 
	* directions). Two flows will get added during  SA creation time. 
	* Other two will get added when the connection tracker add the flow. 
	* The entry added during sa will be used by all the connections which will 
	* use this SA.  
	*       - for inbound SA flow entry  will be added to WAN interface's ESP
	*	  classification table.
	*	- for outbound SA,flow entry will be added to offline port's ESP
	*         classification table. 
	*/

		if (cdx_ipsec_add_classification_table_entry(sa)) 	
			return ERR_CREATION_FAILED;
		sa->state = SA_STATE_VALID;

#ifndef COMCERTO_100
		sa->flags |= SA_ENABLED;
#if	!defined(ELP_HW_BYTECNT) || (ELP_HW_BYTECNT == 0)
		sa->lft_cur.bytes = 0;
#endif
#else
		sa->lft_cur.bytes = 0;
#endif

		sa->lft_cur.packets = 0;
	}
	else if (cmd.state != XFRM_STATE_VALID) {
#ifdef CONTROL_IPSEC_DEBUG
		printk(KERN_INFO "not valid:\n");
#endif
		sa->state = SA_STATE_DEAD;
#ifndef COMCERTO_100
		sa->flags &= ~SA_ENABLED;
#endif
		M_ipsec_sa_cache_delete(sa->handle);
		return NO_ERR;
	}
//	consistent_elpctl(sa->elp_sa, 1);
#ifndef COMCERTO_100
#if defined(IPSEC_DEBUG) && (IPSEC_DEBUG) 
	if (sa->elp_sa->flags & ESPAH_ENABLED)
		gIpSecHWCtx.flush_enable_count += 1;
	else
		gIpSecHWCtx.flush_disable_count += 1;
#endif
#endif
#if 0 
        /* TODO
         * how use state information in case of dpa offload 
         */
	sa_update(sa);
#endif
	return NO_ERR;
}


int IPsec_handle_SA_SET_LIFETIME(U16 *p, U16 Length)
{
	CommandIPSecSetLifetime cmd;
	PSAEntry sa;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetLifetime))
		return ERR_WRONG_COMMAND_SIZE;

	memset(&cmd, 0, sizeof(CommandIPSecSetLifetime));
	memcpy((U8*)&cmd, (U8*)p,  Length);

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s::sagd %d\n", __func__,
		cmd.sagd);
#endif
	sa = M_ipsec_sa_cache_lookup_by_h(cmd.sagd);

	if (sa == NULL)
		return ERR_SA_UNKNOWN;

	sa->lft_conf.soft_byte_limit =  (U64)cmd.soft_time.bytes[0] + ((U64)cmd.soft_time.bytes[1] << 32);
	sa->lft_conf.soft_packet_limit = cmd.soft_time.allocations;
	sa->lft_conf.hard_byte_limit =  (U64)cmd.hard_time.bytes[0] + ((U64)cmd.hard_time.bytes[1] << 32);
	sa->lft_conf.hard_packet_limit = cmd.hard_time.allocations;

#ifdef CONTROL_IPSEC_DEBUG
	printk (KERN_INFO "set_lifetime:bytes:%llu - %llu\n",sa->lft_conf.soft_byte_limit, sa->lft_conf.hard_byte_limit);
#endif
#if 0
	sa_update(sa);
	hw_sa_set_lifetime(&cmd,sa);
#endif
	return NO_ERR;
}

static int IPsec_handle_FRAG_CFG(U16 *p, U16 Length)
{
	CommandIPSecSetPreFrag cmd;

	/* Check length */
	if (Length != sizeof(CommandIPSecSetPreFrag))
		return ERR_WRONG_COMMAND_SIZE;
#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s .. Started..\n", __func__);
#endif

	memset(&cmd, 0, sizeof(CommandIPSecSetPreFrag));
	memcpy((U8*)&cmd, (U8*)p,  Length);
#if 0
       /* TODO
        * How do we hanlde frag in dpaa offload
        */
	ipsec_set_pre_frag(cmd.pre_frag_en);
#endif
	return NO_ERR;

}
//#define PRINT_SA_INFO 1

#ifdef PRINT_SA_INFO 
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

void display_sa_info(PSAEntry pSA)
{
	struct dpa_cls_tbl_entry_stats stats;


	memset(&stats, 0, sizeof(struct dpa_cls_tbl_entry_stats));
	printk("===========================================\n");
        printk("SA information::(spi = 0x%x SAGD = %d  )\n",htonl(pSA->id.spi),pSA->handle);	
	printk("===========================================\n");
        printk("SA direction : %d\n",pSA->direction);
        printk("SA route id = %d and route pointer = %p\n", pSA->route_id,pSA->pRtEntry);
	if(pSA->ct){

		printk("Classification table %p and handle = %p\n",pSA->ct->td,
				pSA->ct->handle);
#ifndef USE_ENHANCED_EHASH
		printk("Classification entry fqid = %d\n ",pSA->ct->entry_fqid);
		if (dpa_classif_table_get_entry_stats_by_ref(
					pSA->ct->td, 
					pSA->ct->dpa_handle, 
					&stats))
  		{
            		printk("get stats for ref %p failed\n", 
                        			pSA->ct->dpa_handle);
       		}
		else
#else
		printk("index = %d\n ",pSA->ct->index);
		ExternalHashTableEntryGetStatsAndTS(pSA->ct->handle, &stats);
#endif
		{
			printk(" entry pkt count = %lu and byte count = %lu\n ",
				(unsigned long)stats.pkts,(unsigned long)stats.bytes );
		}
	}else{
		printk("Hardware ct is NULL\n");
	}
}
extern void display_fq_info(void *handle);
int IPsec_print_SAEntrys(PSAQueryCommand  pSAQueryCmd, int reset_action)
{
        int ipsec_sa_hash_entries;
        int sa_hash_index;

        sa_hash_index = 0;
        while( sa_hash_index < NUM_SA_ENTRIES)
        {
                ipsec_sa_hash_entries = IPsec_Get_Hash_SAEntries(sa_hash_index);
                if(!ipsec_sa_hash_entries) {
                        sa_hash_index++;
                        continue;
                }
                {
                        PSAEntry pSAEntry;
                        struct slist_entry *entry;
			
                        slist_for_each(pSAEntry, entry, &sa_cache_by_h[sa_hash_index], list_h)
                        {
                                display_sa_info(pSAEntry);
                                display_fq_info(pSAEntry->pSec_sa_context->dpa_ipsecsa_handle);
                        }
                }
		sa_hash_index++;
        }
#ifdef PRINT_OFFLOAD_PKT_COUNT 
 	print_ipsec_offload_pkt_count();
#endif
	print_ipsec_exception_pkt_cnt();
        return NO_ERR;
}

#endif

/**
 * M_ipsec_cmdproc
 *
 *
 *
 */
U16 M_ipsec_cmdproc(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16 rc = ERR_UNKNOWN_COMMAND;
	U16 retlen = 2;
//	printk(KERN_DEBUG "%s: cmd_code=0x%04x, cmd_len=%d\n", __func__, cmd_code, cmd_len);
//	printk(KERN_ERR "%s: cmd_code=0x%04x, cmd_len=%d\n", __func__, cmd_code, cmd_len);

	switch (cmd_code)
	{
		case CMD_IPSEC_SA_CREATE:
			rc = IPsec_handle_CREATE_SA(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_DELETE:
			rc = IPsec_handle_DELETE_SA(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_FLUSH:
			rc = IPsec_handle_FLUSH_SA(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_KEYS:
			rc = IPsec_handle_SA_SET_KEYS(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_TUNNEL:
			rc = IPsec_handle_SA_SET_TUNNEL(pcmd, cmd_len);
			break;
                 /* Could not find defintion for CMD_IPSEC_SA_SET_TNL_ROUTE 
                  * deifed some tmp value in cdx_cmdhandler.h file
		  * time being - Rajendran 6 Oct 2016  
		  */
		case CMD_IPSEC_SA_SET_TNL_ROUTE:
			rc = IPsec_handle_SA_SET_TNL_ROUTE(pcmd, cmd_len);
			break;
		case CMD_IPSEC_SA_SET_NATT:
			rc = IPsec_handle_SA_SET_NATT(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_STATE:
			rc = IPsec_handle_SA_SET_STATE(pcmd, cmd_len);
			break;

		case CMD_IPSEC_SA_SET_LIFETIME:
			rc = IPsec_handle_SA_SET_LIFETIME(pcmd, cmd_len);
			break;
		case CMD_IPSEC_SA_ACTION_QUERY:
		case CMD_IPSEC_SA_ACTION_QUERY_CONT:
#ifdef PRINT_SA_INFO 
			if(cmd_code == CMD_IPSEC_SA_ACTION_QUERY)
				IPsec_print_SAEntrys((PSAQueryCommand)pcmd, 0);
#endif
			rc = IPsec_Get_Next_SAEntry((PSAQueryCommand)pcmd, cmd_code == CMD_IPSEC_SA_ACTION_QUERY);
			if (rc == NO_ERR)
				retlen += sizeof (SAQueryCommand);
			break;

		case CMD_IPSEC_FRAG_CFG:
			rc = IPsec_handle_FRAG_CFG(pcmd, cmd_len);
			break;

		default:
			rc = ERR_UNKNOWN_COMMAND;
			break;
	}

	*pcmd = rc;

	return retlen;
}

#if 0
#if !defined(COMCERTO_2000)
static void ipsec_common_soft_init(IPSec_hw_context *sc) {
	// Local portion of initialization
	// Only do things, which can be undone,
	// such as init of private memory

#if     defined(IPSEC_DEBUG) && (IPSEC_DEBUG)
	memset(sc->inbound_counters,0,64);
	memset(sc->outbound_counters,0,64);
#endif
#if	defined(IPSEC_DDRC_WA) && (IPSEC_DDRC_WA)
	L1_dc_invalidate(DDR_FLUSH_ADDR, DDR_FLUSH_ADDR);
#endif	/* defined(IPSEC_DDRC_WA) && (IPSEC_DDRC_WA) */
	sc->in_pe.wq_avail = 1; // Cause inbound processing to be available for passthrough to exception path
}

BOOL M_ipsec_pre_inbound_init(void)
{
	//set_event_handler(EVENT_IPS_IN, M_ipsec_inbound_entry);
	set_cmd_handler(EVENT_IPS_IN, M_ipsec_in_cmdproc);

	//gIpsec_available = 0;
	//ipsec_common_soft_init(&gIpSecHWCtx);

	return 0;
}

BOOL M_ipsec_post_inbound_init(void)
{
	//set_event_handler(EVENT_IPS_IN_CB, M_ipsec_inbound_callback);
	set_cmd_handler(EVENT_IPS_IN_CB, M_ipsec_debug);

	//  ipsec_common_soft_init(&gIpSecHWCtx);
	return 0;
}

BOOL M_ipsec_pre_outbound_init(void)
{
	//set_event_handler(EVENT_IPS_OUT, M_ipsec_outbound_entry);
	set_cmd_handler(EVENT_IPS_OUT, M_ipsec_debug);

	return 0;
}


BOOL M_ipsec_post_outbound_init(void)
{
	//set_event_handler(EVENT_IPS_OUT_CB, M_ipsec_outbound_callback);
	set_cmd_handler(EVENT_IPS_OUT_CB, NULL);

	return 0;
}
#endif
#endif

static __inline int M_ipsec_sa_expire_notify(PSAEntry sa, int hard)
{
	struct _tCommandIPSecExpireNotify *message;
	HostMessage *pmsg;

	pmsg = msg_alloc();
	if (!pmsg)
		goto err;

#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "sending an event:%x:%x\n",hard,sa->handle);
#endif
	message = (struct _tCommandIPSecExpireNotify *)	pmsg->data;

	/*Prepare indication message*/
	message->sagd = sa->handle;
	message->action = (hard) ? IPSEC_HARD_EXPIRE : IPSEC_SOFT_EXPIRE;
	pmsg->code = CMD_IPSEC_SA_NOTIFY;
	pmsg->length = sizeof(*message);

	if (msg_send(pmsg) < 0)
		goto err;

	return 0;

err:
	return 1;
}


static int M_ipsec_sa_timer(struct timer_entry_t *timer_node)
{
	PSAEntry pEntry;
	int i;
	struct en_tbl_entry_stats stats;

	/* Check if classification table entire's  byte/packet count exceed the limit
	 * set in SA 
	*/
	for(i = 0; i < NUM_SA_ENTRIES; i++)
	{
		struct slist_entry *entry;

		slist_for_each(pEntry, entry, &sa_cache_by_h[i], list_h)
		{
			if ((pEntry->ct) && 
			     (pEntry->lft_conf.hard_byte_limit ||
			      pEntry->lft_conf.hard_packet_limit ||
			      pEntry->lft_conf.soft_packet_limit || 
			      pEntry->lft_conf.soft_byte_limit))
			{
#ifndef USE_ENHANCED_EHASH
				if (dpa_classif_table_get_entry_stats_by_ref(
							pEntry->ct->td, 
							pEntry->ct->dpa_handle, 
							&stats))
        			{
#ifdef CONTROL_IPSEC_DEBUG
                			printk("%s::get stats for ref %d failed\n", 
						__FUNCTION__,
                        			pEntry->ct->dpa_handle);
#endif
                			continue;
        			}
#else
				ExternalHashTableEntryGetStatsAndTS(pEntry->ct->handle, &stats);
#endif

				if ((pEntry->state == SA_STATE_VALID ||
				     pEntry->state == SA_STATE_DYING) && 
				 ((pEntry->lft_conf.hard_byte_limit && 
				  (stats.bytes >= pEntry->lft_conf.hard_byte_limit))||
				 (pEntry->lft_conf.hard_packet_limit && 
				(stats.pkts >= pEntry->lft_conf.hard_packet_limit)))) 
				{
#ifdef CONTROL_IPSEC_DEBUG
				printk("%s:: entry pkt count = %lu and byte count = %lu\n SA pkt count = %lu and byte count = %lu \n",__func__,
				(unsigned long)stats.pkts,(unsigned long)stats.bytes , (unsigned long)pEntry->lft_conf.hard_packet_limit,(unsigned long) pEntry->lft_conf.hard_byte_limit);
					printk(KERN_INFO "E");
#endif
					pEntry->state = SA_STATE_EXPIRED;
					pEntry->notify = 1;
				}
				if ((pEntry->state == SA_STATE_VALID) && 
				    ((pEntry->lft_conf.soft_byte_limit && 
				(stats.bytes >= pEntry->lft_conf.soft_byte_limit))
 			         ||(pEntry->lft_conf.soft_packet_limit &&
				(stats.pkts >= pEntry->lft_conf.soft_packet_limit))))
				{
#ifdef CONTROL_IPSEC_DEBUG
				printk("%s:: entry pkt count = %lu and byte count = %lu\n SA pkt count = %lu and byte count = %lu \n",__func__,
				(unsigned long)stats.pkts,(unsigned long)stats.bytes , (unsigned long)pEntry->lft_conf.soft_packet_limit,(unsigned long) pEntry->lft_conf.soft_byte_limit);
					printk(KERN_INFO "D");
#endif
					pEntry->state = SA_STATE_DYING;
					pEntry->notify = 1;
				}
			}

			if (pEntry->notify)
			{
				int rc;

				if (pEntry->state == SA_STATE_EXPIRED)
					rc = M_ipsec_sa_expire_notify(pEntry, 1);
				else if (pEntry->state == SA_STATE_DYING)
					rc = M_ipsec_sa_expire_notify(pEntry, 0);
				else
					rc = 0;

				if (rc == 0)
					pEntry->notify = 0;
			}
		}

	}
	//printk("%s initializing timer \n", __func__);
        /*
         * Please check whether adding the same timer node in the timer 
	* hanler is an issue or not.
	*/
	cdx_timer_add(&sa_timer, SA_TIMER_INTERVAL);
	return 0;
}

static struct qman_fq *cdx_ethernet_ipsec_hookfunc(struct net_device *dev, struct sk_buff *skb,
		uint32_t handle)
{
	PSAEntry sa;
	PDpaSecSAContext pSec_sa_context; 

#ifdef CDX_DPA_DEBUG	
	printk(KERN_CRIT "%s::netdev %p, skb %p, handle %d\n", 
		__FUNCTION__, dev, skb, handle);
#endif 

	if ((sa = M_ipsec_sa_cache_lookup_by_h(handle ))== NULL) {
		printk(KERN_CRIT "%s:: could find a SA with handle %d\n",__FUNCTION__,handle); 
		return NULL;
	}
	if(sa->direction != CDX_DPA_IPSEC_OUTBOUND ){
#ifdef CDX_DPA_DEBUG	
		printk(KERN_CRIT "%s:: SA direction not out bound \n",__FUNCTION__); 
#endif 
		return NULL;
	}
	pSec_sa_context =sa->pSec_sa_context; 
#ifdef CDX_DPA_DEBUG	
	printk(KERN_CRIT "%s::SA %p context %p handle %d encryption Sec fqid is %d \n",__FUNCTION__, 
			sa, pSec_sa_context, handle, pSec_sa_context->to_sec_fqid) ; 
#endif 
	
	return get_to_sec_fq(pSec_sa_context->dpa_ipsecsa_handle); 

}
#if 0
BOOL ipsec_init(void)
{
	int i;

	for (i = 0; i < NUM_SA_ENTRIES; i++)
	{
		slist_head_init(&sa_cache_by_h[i]);
		slist_head_init(&sa_cache_by_spi[i]);
	}
       /* TODO
        *  Here We need to add logic for following 
        *       - Add function cdx_dpa.c  which will pre allocate fqid pair and shared desriptor for Max number of SA 
        *       - Allocate DPA Sec SA context stuture and store these fqid pair and shared desciptor and put it in a single linked list
        *       - Initialise sa_cache_by h and sa_achceby spi linted list table.  
       */
       
	/* initialize a singled list for puting the sec sa context with the pair of fqid
         * and the shared descriptor and other memory if any required by Sec. 
         */
	cdx_ipsec_init();
#ifdef CONTROL_IPSEC_DEBUG
	printk(KERN_INFO "%s timer is initialized \n", __func__);
#endif
	cdx_timer_init(&sa_timer, M_ipsec_sa_timer);
	cdx_timer_add(&sa_timer, SA_TIMER_INTERVAL);
        
	set_cmd_handler(EVENT_IPS_IN, M_ipsec_cmdproc);
	//register hook function for intercepting ipsec packets from ethernet driver
	if (dpa_register_eth_ipsec_hook(cdx_ethernet_ipsec_hookfunc)) {
		printk(KERN_INFO "%s unable to registeri ipsec hook func\n", 
			__func__);
		return -1;
	}

	return 0;
}

void ipsec_exit(void)
{
	cdx_timer_del(&sa_timer);
#if defined(COMCERTO_2000)
	/** Initialize  all SA lists .
	* This function cleans/frees the h/w and s/w hash tables, timers.
	* and removes the pointers from  the lists of the h/w and s/w SAs .
	*/
	struct pfe_ctrl *ctrl = &pfe->ctrl;
	struct dlist_head *entry;
	struct _t_hw_sa_entry *hw_sa;
	int i;


	/* pe's must be stopped by now, remove all pending entries */
	for (i = 0; i < NUM_SA_ENTRIES; i++)
	{
		dlist_for_each_safe(hw_sa, entry, &hw_sa_active_list_h[i], list_h)
		{
			dlist_remove(&hw_sa->list_h);
			dma_pool_free(ctrl->dma_pool, hw_sa, be32_to_cpu(hw_sa->dma_addr));
		}
	}

	dlist_for_each_safe(hw_sa, entry, &hw_sa_removal_list, list_h)
	{
		dlist_remove(&hw_sa->list_h);
		dma_pool_free(ctrl->dma_pool, hw_sa, be32_to_cpu(hw_sa->dma_addr));
	}
#endif
}
#endif
#if 0
U16 M_ipsec_debug(U16 cmd_code, U16 cmd_len, U16 *pcmd)
{
	U16   rc;
	U16   retlen = 2;
	U16   i16;

	switch (cmd_code)
	{
		case  CMD_TRC_DMEM:
			{
				PDMCommand dmcmd = (PDMCommand) pcmd;
				i16 = dmcmd->length;            // Length;
				if (i16 > 224)
					i16 = 224;
				if (i16) {
					dmcmd->length = i16; // Send back effective length
					memcpy(&(pcmd[sizeof(*dmcmd)/sizeof(unsigned short)]),(void*) dmcmd->address, i16);
					rc = CMD_OK;
					retlen = i16 + sizeof(DMCommand);

				} else {
					rc = CMD_TRC_ERR;
				}
			}
			break;

		default:
			rc = CMD_TRC_UNIMPLEMENTED;
			break;
	}
	*pcmd = rc;
	return retlen;
}
#endif  // if 0 for function M_ipsec_debug 
#endif  // DPA_IPSEC_OFFLOAD
