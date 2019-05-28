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


#include "pdb.h"

#ifndef DPA_IPSEC_H
#define DPA_IPSEC_H


#define MAX_SHARED_DESC_SIZE 	62	
#define PRE_HDR_ALIGN		64

#define IPSEC_FMAN_IDX		0
#define DEFA_WQ_ID              0
struct desc_hdr {
        uint32_t sd_hdr;
        union {
                struct ipsec_encap_pdb pdb_encrypt;
                struct ipsec_decap_pdb pdb_decrypt;
        };
};

struct sec_descriptor {
        uint64_t preheader;
        /* SEC Shared Descriptor */
        union {
                uint32_t shared_desc[MAX_SHARED_DESC_SIZE];
                struct desc_hdr desc_hdr;
#define hdr_word        desc_hdr.sd_hdr
#define pdb_en          desc_hdr.pdb_encrypt
#define pdb_dec         desc_hdr.pdb_decrypt
        };
};

#define IPSEC_BUFSIZE	1700
#define IPSEC_BUFCOUNT  1000	

struct ipsec_info; 
void *  dpa_get_ipsec_instance(void);
void *cdx_dpa_ipsecsa_alloc(struct ipsec_info *info, uint32_t handle); 
int cdx_dpa_ipsec_wanport_td(struct ipsec_info *info, uint32_t table_type, void **td);
int dpa_ipsec_ofport_td(struct ipsec_info *info, uint32_t table_type, void **td, 
			uint32_t* portid);
int cdx_dpa_ipsecsa_release(void *handle) ;
uint32_t get_fqid_to_sec(void *handle);
uint32_t get_fqid_from_sec(void *handle);
struct sec_descriptor *get_shared_desc(void *handle);

struct qman_fq *get_to_sec_fq(void *handle);
struct qman_fq *get_from_sec_fq(void *handle);


#endif

