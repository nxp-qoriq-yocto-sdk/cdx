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

        
/**     
 * @file                cdx_ioctl.h
 * @description         cdx driver ioctl structures and definitions
 */

#ifndef CDX_IOCTL_H
#define CDX_IOCTL_H 1

#define CDX_RTP_RELAY // RTP relay support

#define CDX_CTRL_CDEVNAME       "cdx_ctrl"
#define CDX_CTRL_CLS_CDEVNAME   CDX_CTRL_CDEVNAME
#define CDX_IOC_MAGIC           0xbe

//table create ioctl
#define CDX_CTRL_TBL_NAME_LEN	64
#define CDX_CTRL_PORT_NAME_LEN	32	

//max number of fwd manip nodes
#define MAX_FW_MANIP_NODES		64
//max number of nat addr translation manip nodes
#define MAX_IPV4ADDR_NAT_NODES		64
//max number of nat port translation manip nodes
#define MAX_PORT_NAT_NODES		64

#if 0
//type field in table_info
enum {
        //IPV4_TCPFLAGS_TABLE,
        IPV4_UDP_TABLE,
        IPV4_TCP_TABLE,
        IPV6_UDP_TABLE,
        IPV6_TCP_TABLE,
        //IPV4_PPPoE_TABLE,
        ESP_IPV4_TABLE,
        ESP_IPV6_TABLE,
        IPV4_MULTICAST_TABLE,
        IPV6_MULTICAST_TABLE,
        PPPOE_RELAY_TABLE,
        ETHERNET_TABLE,
#ifdef CDX_RTP_RELAY // RTP relay feature
        IPV4_3TUPLE_UDP_TABLE,
        IPV4_3TUPLE_TCP_TABLE,
        IPV6_3TUPLE_UDP_TABLE,
        IPV6_3TUPLE_TCP_TABLE,
#endif //CDX_RTP_RELAY
        MAX_MATCH_TABLES
};
#endif

//type field in cdx_dist_info
enum {
        IPV4_TCP_DIST,
        IPV4_UDP_DIST,
        IPV6_TCP_DIST,
        IPV6_UDP_DIST,
        IPV4_ESP_DIST,
        IPV6_ESP_DIST,
        IPV4_MULTICAST_DIST,
        IPV6_MULTICAST_DIST,
        PPPOE_DIST, 
        ETHERNET_DIST,
#ifdef CDX_RTP_RELAY // RTP relay feature
        IPV4_3TUPLE_UDP_DIST,
        IPV4_3TUPLE_TCP_DIST,
        IPV6_3TUPLE_UDP_DIST,
        IPV6_3TUPLE_TCP_DIST,
#endif //CDX_RTP_RELAY
	IPV4_FRAG_DIST,
        IPV6_FRAG_DIST,
        MAX_DIST_TYPES
};

//port distribution info
struct cdx_dist_info {
	uint32_t type;		//ipsec, udp4, ethernet etc
	void *handle;		//distribution handle
	uint32_t base_fqid;	//base fqid
	uint32_t count;		//num fqs from base
};


//port information
struct cdx_port_info {
	uint32_t fm_index;	//fman index 0 based that controls this port
	uint32_t index;		//port index within fman, 0 based
	uint32_t portid;	//portid provided in xml file
	uint32_t type;		//1G, 10G port (speed)
	uint32_t max_dist;	//max number of distribution entries for  port
	struct cdx_dist_info *dist_info; //pointer to array of distributions
	char name[CDX_CTRL_PORT_NAME_LEN]; //port name as seen by OS
};

#define	TABLE_NAME_SIZE 64 
//classification table information
struct table_info {
        char name[TABLE_NAME_SIZE]; //name of table in pcd file
	uint32_t dpa_type;	//type of dpa table, exact match etc
	uint32_t port_idx;	//port_index to which table is attached
	uint32_t type;		//type of table, see enum
        uint32_t num_keys;      //num keys in exact match table
	struct {
		uint32_t num_sets; //number of buckets in int/ext table
		uint32_t num_ways; //number way in int hash table
	};
        uint32_t key_size;      //sizeof key in bytes
        void *id;               //id for handle
//	int td;               	//kernel table desc for id, used, filled by LKM
};

//fman information
struct cdx_fman_info {
	void *fm_handle;
	uint32_t index;		//0 based index within DPAA
	uint32_t max_ports;	//max ports with this fman
	struct cdx_port_info *portinfo; //array of port info
	uint32_t num_tables;	//max tables for this fman
	struct table_info *tbl_info; //array of table information
	//struct cdx_dist_info *dist;
	void *pcd_handle;	//handle to fm_pcd device for this fman
	void *muram_handle; 
	uint64_t   physicalMuramBase; 
	uint32_t   fmMuramMemSize; 
};

//ipv4 reassembly configuration
struct cdx_ipr_info {
	uint32_t timeout;
	uint32_t max_frags;
	uint32_t min_frag_size;
	uint32_t max_contexts;
	uint32_t ipr_ctx_bsize;
	uint32_t ipr_frag_bsize;
};

//structure used by CDX_CTRL_DPA_SET_PARAMS ioctl call
struct cdx_ctrl_set_dpa_params {
	uint32_t num_fmans;	//number of frame managers
	struct cdx_fman_info *fman_info; //pointer to array of fman info
	struct cdx_ipr_info *ipr_info;
};

#define CDX_CTRL_DPA_SET_PARAMS\
        _IOWR(CDX_IOC_MAGIC, 1, struct cdx_ctrl_set_dpa_params)

//flow add ioctl structures, used only by test code
struct test_flow_info {
        uint16_t sport;		//source port for tcp/udp conn
        uint16_t dport;		//dest port for tcp/udp conn
        uint16_t mtu;		//mtu to be used
        char *ingress_port;	//packets ingress iface name
        char *egress_port;	//packets egress iface name
	char dest_mac[6];	//dest gw mac address
        union {
                struct {
                        uint32_t ipv4_saddr;	//ipv4 source addr
                        uint32_t ipv4_daddr;	//ipv4 dest addr
                };
                struct {
                        uint8_t ipv6_saddr[16];	//ipv6 src addr
                        uint8_t ipv6_daddr[16];	//ipv6 dest addr
                };
        };
};


//per connection info
struct test_conn_info {
        uint32_t flags;                 //mapped to CTentry status flags
        uint8_t proto;			//protocol - udp, tcp, icmp etc
        struct test_flow_info fwd_flow;	//forward flow info
        struct test_flow_info rev_flow; //rev flow info
};


//structure used by CDX_CTRL_DPA_CONNADD call
struct add_conn_info {
        uint32_t num_conn;		//num conn to add
        struct test_conn_info *conn_info; //pointer to array of connections
};

#define CDX_CTRL_DPA_CONNADD\
        _IOWR(CDX_IOC_MAGIC, 3, struct add_conn_info)

#ifdef DPAA_DEBUG_ENABLE
struct muram_data {
        uint8_t *buff;
        uint32_t size;
};

#define CDX_CTRL_DPA_GET_MURAM_DATA\
        _IOWR(CDX_IOC_MAGIC, 4, struct muram_data)
#endif

struct QoSConfig_Info
{
  char If_info[12];
  unsigned int uiCIR;
  unsigned int uiEIR;
  unsigned int uiCBS;
  unsigned int uiEBS;
  short int uiNoOfSchedulers;
  short int uiNoOfQueues;
  int sp; /*Strict priority algorithm*/
} ; 

#define CDX_CTRL_DPA_QOS_CONFIG_ADD\
        _IOWR(CDX_IOC_MAGIC, 3, struct QoSConfig_Info)
struct add_mc_group_info
{
   union
   {
     struct
     {
       uint32_t ipv4_saddr;	//ipv4 source addr
       uint32_t ipv4_daddr;	//ipv4 dest addr
     };
     struct
     {
       uint8_t ipv6_saddr[16];	//ipv6 src addr
       uint8_t ipv6_daddr[16];	//ipv6 dest addr
     };
   };
   char ucListenerPort[32]; /* Interface name on which multicast packet need to be sent out*/
   uint8_t uiMaxMembers; /*Max listeners for this group*/
   uint8_t mctype; /* 0  for v4 and 1 for v6*/
};

#define CDX_CTRL_DPA_ADD_MCAST_GROUP\
        _IOWR(CDX_IOC_MAGIC, 5, struct add_mc_group_info)

struct dpa_member_to_mcast_group
{
  uint8_t mcast_grp;
  char ucListenerPort[32];
};

#define CDX_CTRL_DPA_ADD_MCAST_MEMBER\
        _IOWR(CDX_IOC_MAGIC, 6, struct add_mc_group_info)

struct add_mc_entry_info
{
   union
   {
     struct
     {
       uint32_t ipv4_saddr;	//ipv4 source addr
       uint32_t ipv4_daddr;	//ipv4 dest addr
     };
     struct
     {
       uint8_t ipv6_saddr[16];	//ipv6 src addr
       uint8_t ipv6_daddr[16];	//ipv6 dest addr
     };
   };
   char ucIngressPort[32];
   uint8_t mctype; /* 0  for v4 and 1 for v6*/
};
#define CDX_CTRL_DPA_ADD_MCAST_TABLE_ENTRY\
        _IOWR(CDX_IOC_MAGIC, 7, struct add_mc_entry_info)
#endif
