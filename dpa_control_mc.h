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

#define MC4_NUM_HASH_ENTRIES 16
#define MC6_NUM_HASH_ENTRIES 16
#define MC4_MIN_COMMAND_SIZE	32+12 /* with one listener entry using 1 interface name */
#define MC6_MIN_COMMAND_SIZE	64+12 /* with one listener entry using 1 interface name */
#define MC_MAX_LISTENERS_IN_QUERY    5
#define MC4_MAX_LISTENERS_IN_QUERY    MC_MAX_LISTENERS_IN_QUERY
#define MC6_MAX_LISTENERS_IN_QUERY    MC_MAX_LISTENERS_IN_QUERY
#define MC_MAX_LISTENERS_PER_GROUP 8
#define MC4_MAX_LISTENERS_PER_GROUP  MC_MAX_LISTENERS_PER_GROUP
#define MC6_MAX_LISTENERS_PER_GROUP  MC_MAX_LISTENERS_PER_GROUP

typedef struct _tMC4Output {
        U32             timer;
        U8              output_device_str[IF_NAME_SIZE];
        U8              shaper_mask;
        U8              uc_bit:1,
                        q_bit:1,
                        rsvd:6;
        U8              uc_mac[6];
        U8              queue;
        U8              new_output_device_str[IF_NAME_SIZE];
        U8              if_bit:1,
                        unused:7;
        U8              padding[2];
}__attribute__((__packed__)) MC4Output, MC6Output, *PMC4Output,*PMC6Output;


typedef struct _tMC4Command {
        U16             action;
        U8              src_addr_mask;
        U8              mode : 1,
                        queue : 5,
                        rsvd : 2;
        U32             src_addr;
        U32             dst_addr;
        U32             num_output;
        U8              input_device_str[IF_NAME_SIZE];
        MC4Output output_list[MC4_MAX_LISTENERS_IN_QUERY];
}__attribute__((__packed__)) MC4Command, *PMC4Command;

typedef struct _tMC6Command {
	U16		action;
	U8 		mode : 1,
	     		queue : 5,
	     		rsvd : 2;
	U8		src_mask_len;
	U32		src_addr[4];
	U32		dst_addr[4];
	U32		num_output;
        U8              input_device_str[IF_NAME_SIZE];
	MC6Output output_list[MC6_MAX_LISTENERS_IN_QUERY];
}__attribute__((__packed__)) MC6Command, *PMC6Command;

struct mcast_group_member
{
  int member_id;
  char if_info[IF_NAME_SIZE];
  char bIsValidEntry;
#ifndef USE_ENHANCED_EHASH
  struct hm_chain_info *hm_info;
#else
  //struct en_exthash_tbl_entry *tbl_entry;
  void *tbl_entry;
#endif // USE_ENHANCED_EHASH
} ;

struct mcast_group_info
{
  struct list_head list;
  union
  {
    struct
    {
      uint32_t ipv4_saddr;     //ipv4 source addr
      uint32_t ipv4_daddr;     //ipv4 dest addr
    };
    struct
    {
      uint32_t ipv6_saddr[4];  //ipv6 src addr
      uint32_t ipv6_daddr[4];  //ipv6 dest addr
    };
  };
  int grpid;
  unsigned int uiListenerCnt;
  struct mcast_group_member members[MC_MAX_LISTENERS_PER_GROUP];
  struct _tCtEntry *pCtEntry;  
  char ucIngressIface[IF_NAME_SIZE];
  uint8_t mctype;
};

#define CDX_MC_ACTION_ADD			0
#define CDX_MC_ACTION_REMOVE			1
#define CDX_MC_ACTION_UPDATE       		2
#define CDX_MC_ACTION_REMOVE_LOCAL       	11

int GetMcastGrpId( struct mcast_group_info *pMcastGrpInfo);
#ifndef USE_ENHANCED_EHASH
extern int create_hm_chain_for_mcast_member(RouteEntry *pRtEntry, struct ins_entry_info
                 *pInsEntry, struct hm_chain_info **pphm_info,
                 int mtu,char *InIface, int IsFirstMem, int bIsIPv6);
extern int insert_mcast_entry_in_classif_table(struct _tCtEntry *pCtEntry, int mc_grpid);
#else
extern int insert_mcast_entry_in_classif_table(struct _tCtEntry *pCtEntry, 
						unsigned int num_members, uint64_t first_member_flow_addr,
						void *first_listener_entry);
#endif // USE_ENHANCED_EHASH
extern int insert_entry_in_classif_table(PCtEntry entry);
extern int dpa_get_fm_port_index(uint32_t itf_index, uint32_t underlying_iif_index , 
			uint32_t *fm_index, uint32_t *port_index, uint32_t *portid);
extern void *dpa_get_pcdhandle(uint32_t fm_index);
extern int dpa_get_tx_info_by_itf(PRouteEntry rt_entry, struct dpa_l2hdr_info *l2_info,
		struct dpa_l3hdr_info *l3_info, PRouteEntry tnl_rt_entry, uint32_t queue);
extern void AddToMcastGrpList(struct mcast_group_info *pMcastGrpInfo);
extern struct list_head mc4_grp_list[MC4_NUM_HASH_ENTRIES];
extern struct list_head mc6_grp_list[MC6_NUM_HASH_ENTRIES];
int cdx_delete_mcast_group_member( void *mcast_cmd, int bIsIPv6);

struct mcast_group_info* GetMcastGrp( struct mcast_group_info *pMcastGrpInfo);
int delete_entry_from_classif_table(PCtEntry entry);
#ifndef USE_ENHANCED_EHASH
void delete_entry_from_hm_hash_table(struct hm_chain_info *hm_info);
#endif // USE_ENHANCED_EHASH
int dpa_classif_mcast_free_group(int grpd);
int MC4_Get_Next_Hash_Entry(PMC4Command pMC4Cmd, int reset_action);
int MC6_Get_Next_Hash_Entry(PMC6Command pMC6Cmd, int reset_action);
int cdx_update_mcast_group(void *mcast_cmd, int bIsIPv6);

static inline u32 HASH_MC4(u32 destaddr)  // pass in IPv4 dest addr
{
  u32 hash;
  destaddr = ntohl(destaddr);
  hash = destaddr + (destaddr >> 16);
  hash = hash ^ (hash >> 4) ^ (hash >> 8) ^ (hash >> 12);
  return hash & (MC4_NUM_HASH_ENTRIES - 1);
}

static inline u32 HASH_MC6(void *pdestaddr)  // pass in ptr to IPv6 dest addr
{
  u16 *p = (u16 *)pdestaddr;
  u32 hash;
  hash = ntohs(p[4]) + ntohs(p[5]) + ntohs(p[6]) + ntohs(p[7]);
  hash = hash ^ (hash >> 4) ^ (hash >> 8) ^ (hash >> 12);
  return hash & (MC6_NUM_HASH_ENTRIES - 1);
}
