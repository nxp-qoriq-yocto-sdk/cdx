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


#ifndef _MODULE_IPSEC_H_
#define _MODULE_IPSEC_H_

#include "fe.h"
#include "dpa_ipsec.h"
//#include "common_hdrs.h"        /* For ipv4 header structure */
/*
 *  * IPSEC_DEBUG - if not defined or defined to 0 disables debug instrumentation such as drop counters
 *   * */
#if     !defined(IPSEC_DEBUG)
#define IPSEC_DEBUG     0
#endif


/* Codes for proto_family:
It copies from linux and equal to AF_INET/AF_INET6
*/
#define	PROTO_FAMILY_IPV4 2
#define PROTO_FAMILY_IPV6 10

#define IPSEC_MAX_KEY_SIZE (256 /8)
#define IPSEC_MAX_NUM_KEYS 2

/******************************
 * * IPSec API Command strutures
 * *
 * ******************************/



/* Authentication algorithms */
#define SADB_AALG_NONE                  0
#define SADB_AALG_MD5HMAC               2
#define SADB_AALG_SHA1HMAC              3
#define SADB_X_AALG_SHA2_256HMAC        5
#define SADB_X_AALG_SHA2_384HMAC        6
#define SADB_X_AALG_SHA2_512HMAC        7
#define SADB_X_AALG_RIPEMD160HMAC       8
#define SADB_X_AALG_AES_XCBC_MAC        9
#define SADB_X_AALG_NULL                251     /* kame */
#define SADB_AALG_MAX                   251

/* Encryption algorithms */
#define SADB_EALG_NONE                  0
#define SADB_EALG_DESCBC                2
#define SADB_EALG_3DESCBC               3
#define SADB_X_EALG_CASTCBC             6
#define SADB_X_EALG_BLOWFISHCBC         7
#define SADB_EALG_NULL                  11
#define SADB_X_EALG_AESCBC              12
#define SADB_X_EALG_AESCTR              13
#define SADB_X_EALG_AES_CCM_ICV8        14
#define SADB_X_EALG_AES_CCM_ICV12       15
#define SADB_X_EALG_AES_CCM_ICV16       16
#define SADB_X_EALG_AES_GCM_ICV8        18
#define SADB_X_EALG_AES_GCM_ICV12       19
#define SADB_X_EALG_AES_GCM_ICV16       20

/* AESGCM - 18/19/20 */
#define SADB_X_EALG_CAMELLIACBC         22
#define SADB_EALG_MAX                   253 /* last EALG */
/* private allocations should use 249-255 (RFC2407) */
#define SADB_X_EALG_SERPENTCBC  252     /* draft-ietf-ipsec-ciph-aes-cbc-00 */
#define SADB_X_EALG_TWOFISHCBC  253     /* draft-ietf-ipsec-ciph-aes-cbc-00 */

typedef struct _tIPSec_said {
	unsigned int spi;
	unsigned char sa_type;
	unsigned char proto_family;
	unsigned char replay_window;
#define NLKEY_SAFLAGS_ESN       0x1
#define NLKEY_SAFLAGS_INBOUND   0x2
	unsigned char flags;
	unsigned int dst_ip[4];
	unsigned int src_ip[4];		// added for NAT-T transport mode
	unsigned short mtu;
	unsigned short dev_mtu;
}IPSec_said, *PIPSec_said;

typedef struct _tIPSec_key_desc {
	unsigned short key_bits;
	unsigned char key_alg;
	unsigned char  key_type;
	unsigned char key[IPSEC_MAX_KEY_SIZE];
}IPSec_key_desc, *PIPSec_key_desc;

typedef struct _tIPSec_lifetime {
	unsigned int allocations;
	unsigned int bytes[2];
}IPSec_lifetime, *PIPSec_lifetime;


typedef struct _tCommandIPSecCreateSA {
	unsigned short sagd;
	unsigned short rsvd;
	IPSec_said said;
}CommandIPSecCreateSA, *PCommandIPSecCreateSA;

typedef struct _tCommandIPSecDeleteSA {
	unsigned short sagd;
	unsigned short rsvd;
}CommandIPSecDeleteSA, *PCommandIPSecDeleteSA;

typedef struct _tCommandIPSecSetKey {
	unsigned short sagd;
	unsigned short rsvd;
	unsigned short num_keys;
	unsigned short rsvd2;
	IPSec_key_desc keys[IPSEC_MAX_NUM_KEYS];
}CommandIPSecSetKey, *PCommandIPSecSetKey;

typedef struct _tCommandIPSecSetNatt {
	unsigned short sagd;
	unsigned short sport;
	unsigned short dport;
	unsigned short rsvd;
}CommandIPSecSetNatt, *PCommandIPSecSetNatt;

typedef struct _tCommandIPSecSetState {
	unsigned short sagd;
	unsigned short rsvd;
	unsigned short state;
	unsigned short rsvd2;
}CommandIPSecSetState, *PCommandIPSecSetState;

typedef struct _tCommandIPSecSetTunnel {
	unsigned short sagd;
	unsigned char rsvd;
	unsigned char proto_family;
	union {
		ipv4_hdr_t   ipv4h;
		ipv6_hdr_t   ipv6h;
	} h;
}CommandIPSecSetTunnel, *PCommandIPSecSetTunnel;

typedef struct _tCommandIPSecSetTunnelRoute {
        unsigned short sagd;
        unsigned short route_id;
}CommandIPSecSetTunnelRoute, *PCommandIPSecSetTunnelRoute;


typedef struct _tCommandIPSecSetLifetime{
	unsigned short sagd;
	unsigned short rsvd;
	IPSec_lifetime  hard_time;
	IPSec_lifetime  soft_time;
	IPSec_lifetime  current_time;
}CommandIPSecSetLifetime, *PCommandIPSecSetLifetime;


typedef struct _tCommandIPSecExpireNotify{
	unsigned short sagd;
	unsigned short rsvd;
	unsigned int  action;
}CommandIPSecExpireNotify, *PCommandIPSecExpireNotify;

typedef struct _tCommandIPSecSetPreFrag {
		unsigned short pre_frag_en;		
		unsigned short reserved;
} CommandIPSecSetPreFrag, *PCommandIPSecSetPreFrag;

typedef struct _tSAQueryCommand {
  unsigned short action;
  unsigned short handle; /* handle */ 
  /*SPI information */
  unsigned short mtu;    /* mtu configured */ 
  unsigned short rsvd1;
  unsigned int spi;      /* spi */ 
  unsigned char sa_type; /* SA TYPE Prtocol ESP/AH */
  unsigned char family; /* Protocol Family */
  unsigned char mode; /* Tunnel/Transport mode */
  unsigned char replay_window; /* Replay Window */
  unsigned int dst_ip[4];
  unsigned int src_ip[4];
  
  /* Key information */
  unsigned char key_alg;
  unsigned char state; /* SA VALID /EXPIRED / DEAD/ DYING */
  unsigned short flags; /* ESP AH enabled /disabled */
  
  unsigned char cipher_key[32];
  unsigned char auth_key[20];
  unsigned char ext_auth_key[12];
     
  /* Tunnel Information */
  unsigned char tunnel_proto_family;
  unsigned char rsvd[3];
  union  {
	ipv4_hdr_t ipv4;
	ipv6_hdr_t ipv6;
  } __attribute__((packed)) tnl;

  U64	soft_byte_limit;
  U64	hard_byte_limit;
  U64	soft_packet_limit;
  U64	hard_packet_limit;
  
} __attribute__((packed)) SAQueryCommand, *PSAQueryCommand;





/* Debugging */
/*
Display memory command
*/
typedef struct _tDMCommand {
  unsigned short pad_in_rc_out; /* Padding - retcode */
  unsigned short length;        /* Lenght of memory to display < 224 bytes 
				** returns length being displayed in response */
  unsigned int address;         /* msp address of memory to display 
			** returns address being displayed in response */
} DMCommand, *PDMCommand;


U16 M_ipsec_debug(U16 cmd_code, U16 cmd_len, U16 *pcmd);
__inline  void read_random(unsigned char *p_result, unsigned int rlen);

#if     defined(IPSEC_DEBUG) && (IPSEC_DEBUG)
#       define IPSEC_DBG(x) do { x} while(0)
#else
#       define IPSEC_DBG(x)
#endif



/****** IPSEC related common structures *****/
static __inline U16 HASH_SA(U32 *Daddr, U32 spi, U16 Proto, U8 family)
{
        U16 sum;
        U32 tmp32;

        tmp32 = ntohl(Daddr[0]) ^ ntohl(Daddr[1]) ^ ntohl(spi);
        sum = (tmp32 >> 16) + (tmp32 & 0xffff) + Proto;
        return ((sum ^ (sum >> 8)) & (NUM_SA_ENTRIES - 1));
}


#define SA_MAX_OP		2	// maximum of stackable SA (ESP+AH)

typedef  struct  AH_HDR_STRUCT
{
        U8  nexthdr;
        U8  hdrlen;             /* This one is measured in 32 bit units! */
        U16 reserved;
        U32 spi;
        U32 seq_no;             /* Sequence number */
        U8  auth_data[4];       /* Variable len but >=4. Mind the 64 bit alignment! */
} ip_ah_hdr ;


typedef  struct  ESP_HDR_STRUCT
{
        U32 spi;
        U32 seq_no;
        U32 enc_data[1];
} ip_esp_hdr;


#if 0  // redeclarations 
/* from Linux XFRM stack... (should we use PF_KEY value instead ?) */
enum {
	XFRM_STATE_VOID,
	XFRM_STATE_ACQ,
	XFRM_STATE_VALID,
	XFRM_STATE_ERROR,
	XFRM_STATE_EXPIRED,
	XFRM_STATE_DEAD
};
#endif // 0 

#define SA_MODE_TUNNEL 0x1
#define SA_MODE_TRANSPORT 0x0

typedef struct _tSA_lft_conf {
	U64	soft_byte_limit;
	U64	hard_byte_limit;
	U64	soft_packet_limit;
	U64	hard_packet_limit;
} SA_lft_conf, *PSA_lft_conf;

/*
* Scatter/Gather data descriptor table.
*/
struct elp_ddtdesc {
	/* volatile  */U32	frag_addr;		
	/* volatile  */U32	frag_size;		
};



#ifdef CFG_STATS
typedef struct _tSAStatEntry {
       U32 total_pkts_processed;
       U32 last_pkts_processed;
       U64 total_bytes_processed;
       U64 last_bytes_processed;
}SAStatEntry , *PSAStatEntry;
#endif


typedef struct _tSA_lft_cur {
        U64     bytes;
        U64     packets;
}SA_lft_cur, *PSA_lft_cur;


typedef struct _tSAID {	
	union
	{
	       /*Unused	U32		a4; */
		U32 			a6[4];
		U32			top[4]; // alias
	} daddr;		
	U32		saddr[4];	// added for NAT-T transport mode
	U32		spi;
	U8		proto;
	U8		unused[3];
} SAID, *PSAID;	


#define SA_STATE_INIT		0x1
#define SA_STATE_VALID		0x2
#define SA_STATE_DEAD		0x3
#define SA_STATE_EXPIRED	0x4
#define SA_STATE_DYING		0x5


/*
 * _TSAEntry.flags values
 */
#define SA_NOECN	1
#define SA_DECAP_DSCP	2
#define SA_NOPMTUDISC	4
#define SA_WILDRECV	8
/* Local mirror of the sa flags.  */
#define	SA_ENABLED 	0x10		
#define SA_ALLOW_SEQ_ROLL 0x20
#define SA_ALLOW_EXT_SEQ_NUM 0x40

#define SA_HDR_COPY_TOS  1
#define SA_HDR_DEC_TTL   2
#define SA_HDR_COPY_DF   4

/*Adding the below defintion to resolve some compilation issue for the time being
 * Should resolve later with proper value Rajendran 06/Oct/2016.
*/ 
#define IPV4_HDR_SIZE  20
#define CDX_DPA_IPSEC_INBOUND     1
#define CDX_DPA_IPSEC_OUTBOUND    0


struct cipher_params {
        U16 cipher_type;    /* Algorithm type as defined by SEC driver   */
        U8 *cipher_key;     /* Address to the encryption key             */
        U32 cipher_key_len; /* Length in bytes of the normal key         */
};

/* DPA IPsec Authentication Parameters */
struct auth_params {
        U16 auth_type;     /* Algorithm type as defined by SEC driver    */
        U8 *auth_key;      /* Address to the normal key                  */
        U32 auth_key_len;  /* Length in bytes of the normal key          */
        U8 *split_key;     /* Address to the generated split key         */
        U32 split_key_len; /* Length in bytes of the split key           */
        U32 split_key_pad_len;/* Length in bytes of the padded split key */
};


typedef struct dpa_sec_sa_context_s{

	U32   to_sec_fqid;
	U32   from_sec_fqid;
        void  *dpa_ipsecsa_handle;
	struct cipher_params cipher_data;   /* Encryption parameters          */
        struct auth_params auth_data;       /* Authentication key parameters  */
        struct sec_descriptor  *sec_desc; /* 64 byte aligned address where is
                                          * computed the SEC 4.x descriptor
                                          * according to the SA information.
                                          * do not free this pointer!         */
        U32  *sec_desc_extra_cmds_unaligned;
        U32   *sec_desc_extra_cmds; /* aligned to CORE cache line size     */
        BOOL   sec_desc_extended; /* true if SEC descriptor is extended     */
        U32   *rjob_desc_unaligned;
	U32 *rjob_desc; /* replacement job descriptor address            */
        U8  job_desc_len; /* Number of words CAAM Job Descriptor occupies
                                * form the CAAM Descriptor length
                                * MAX_CAAM_DESCSIZE                           */

	U16           	alg_suite;
} DpaSecSAContext , *PDpaSecSAContext;

typedef struct _tSAEntry {
	struct slist_entry      list_spi;
	struct slist_entry      list_h;
	U16			hash_by_h;
        U16			hash_by_spi;
        struct _tSAID           id;             // SA 3-tuple
        U8                      family;         // v4/v6
        U8                      header_len;     // ipv4/ipv6 tunnel header
        U8                      mode;           // Tunnel / transport mode
        U8                      flags;          // ECN, TOS ...
        struct _tSA_lft_cur lft_cur;
        struct _tSA_lft_conf lft_conf;
        U8                      direction;      // inbound / outbound
	U8			state:7;          // valid / expired / dead / dying
	U8			notify:1;
        U8                      blocksz;
        U8                      icvzs;
        U16                     handle;
        U16                     mtu;            // used for Transport mode
        union                           // keep union 32 bits aligned !!!
        {
                ipv4_hdr_t      ip4;
                ipv6_hdr_t      ip6;
        } tunnel;
        U16                             dev_mtu;
        /*NAT-T modifications*/
        struct
        {
                unsigned short sport;
                unsigned short dport;
                void*          socket;
        }natt;
	PDpaSecSAContext 	pSec_sa_context;    /*pointer to the context entry for fqid pair */
	U32 			route_id;
	PRouteEntry 		pRtEntry;
	U64 			seq;
        U8                      enable_stats;
        U8                      hdr_flags;          // copy DF,TOS  
        U16                     stats_offset;
	struct hw_ct 		*ct;
	U16                    	stats_indx;
	U16                    	next_cmd_indx;
	void 			*netdev; 
} SAEntry, *PSAEntry;

void* M_ipsec_sa_cache_lookup_by_spi(U32 *daddr, U32 spi, U8 proto, U8 family);
void* M_ipsec_sa_cache_lookup_by_h(U16 handle);
extern struct slist_head sa_cache_by_spi[];
extern struct slist_head sa_cache_by_h[];


/* NAT-T implementation */

//extern PNatt_Socket_v6 gNatt_Sock_v6_cache[];
//extern PNatt_Socket_v4 gNatt_Sock_v4_cache[];



/****** IPSEC related common structures *****/

/*
 *  * Codes
 *  */
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



/* Fixed mapping between source and destination ddts */
#define DST_DDTE(src_ddte) (&(src_ddte[ELP_MAX_DDT_PER_PKT]))



/* SA flags (oxffest 0x7e) bits  */
#define ESPAH_ENABLED			0x0001
#define ESPAH_SEQ_ROLL_ALLOWED		0x0002
#define ESPAH_TTL_ENABLE		0x0004	
#define ESPAH_TTL_TYPE			0x0008 /* 0:byte 1:time */
#define ESPAH_AH_MODE			0x0010 /* 0:ESP 1:AH */
#define ESPAH_ANTI_REPLAY_ENABLE 	0x0080
#define ESPAH_COFF_EN			0x0400 /* 1:Crypto offload enable */
#define ESPAH_COFF_MODE			0x0800 /* Crypto offload mode: 0: ECB cypher or raw hash, 1 CBC cypher or HMAC hash */
#define ESPAH_IPV6_ENABLE 		0x1000 /* 1:IPv6 SA */ 
#define ESPAH_DST_OP_MODE 		0x2000 /* IPv6 dest opt treatment EDN-0277 page 16 */ 
#define ESPAH_EXTENDED_SEQNUM   	0x4000


/* STAT codes that go into the STAT_RET_CODE  of a register */
#define ESPAH_STAT_OK          	0
#define ESPAH_STAT_BUSY       	1
#define ESPAH_STAT_SOFT_TTL    	2
#define ESPAH_STAT_HARD_TTL    	3
#define ESPAH_STAT_SA_INACTIVE 	4
#define ESPAH_STAT_REPLAY      	5
#define ESPAH_STAT_ICV_FAIL    	6
#define ESPAH_STAT_SEQ_ROLL    	7
#define ESPAH_STAT_MEM_ERROR   	8
#define ESPAH_STAT_VERS_ERROR  	9
#define ESPAH_STAT_PROT_ERROR  	10
#define ESPAH_STAT_PYLD_ERROR  	11
#define ESPAH_STAT_PAD_ERROR   	12
#define ESPAH_DUMMY_PKT   	13


 
/****** IPSEC HW related common structures *****/

// Dummy ip headers are presently non-cachable hence flushing them is not needed
// // If they become cachable change flush definition below.
#define IPSEC_flush_ipv4h(start,end) 
//#define IPSEC_flush_if_cachable(start,end) L1_dc_flush(start,end)


/* SA notifications */
#define IPSEC_SOFT_EXPIRE 0
#define IPSEC_HARD_EXPIRE 1
#if 0
static __inline void consistent_elpctl(PElliptic_SA elp_sa_ptr, int sa_cache_flush)
{
#if !defined (COMCERTO_2000)
	U8 *end_ptr = ((U8*) (elp_sa_ptr + 1)) - 1;
	/* Make sure memory is settled*/
	L1_dc_clean(elp_sa_ptr, end_ptr);
#elif defined(COMCERTO_2000_CONTROL)
	wmb();
#endif
	/*  DSB(); - done as a part of cleaning */
	/* sa_cache_flush should be always 0 for C100 */
	hw_sa_cache_flush(elp_sa_ptr , sa_cache_flush);

}
#endif 

int M_ipsec_ttl_check_time(void);

extern struct tIPSec_hw_context gIpSecHWCtx;
extern int gIpsec_available;
void M_ipsec_outbound_entry(void);
void M_ipsec_outbound_callback(void);
void M_ipsec_inbound_entry(void);
void M_ipsec_inbound_callback(void);

#if 0
BOOL ipsec_init(void);
void ipsec_exit(void);
#endif
void ipsec_standalone_init(void);
#endif
