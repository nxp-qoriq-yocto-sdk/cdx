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




#ifndef CDX_DPA_IPSEC_H
#define CDX_DPA_IPSEC_H

#include "dpa_ipsec.h"

#define MAX_NUM_OF_SA       1000
#define MAX_CIPHER_KEY_LEN  100
#define MAX_AUTH_KEY_LEN    256
#define MAX_BUFFER_POOL_ID  63

#define MAX_CAAM_SHARED_DESCSIZE 50     /* If CAAM used with QI the maximum
                                         * shared descriptor length is 50 words
                                         */
#define CDX_DPA_IPSEC_STATS_LEN  2
/* The maximum length (in bytes) for the CAAM extra commands */
#define MAX_EXTRA_DESC_COMMANDS         (64 * sizeof(U32))



/* for OP_PCLID_IPSEC */
#define OP_PCL_IPSEC_CIPHER_MASK		 0xff00
#define OP_PCL_IPSEC_AUTH_MASK			 0x00ff

#define OP_PCL_IPSEC_DES_IV64			 0x0100
#define OP_PCL_IPSEC_DES			 0x0200
#define OP_PCL_IPSEC_3DES			 0x0300
#define OP_PCL_IPSEC_NULL_ENC			 0x0b00
#define OP_PCL_IPSEC_AES_CBC			 0x0c00
#define OP_PCL_IPSEC_AES_CTR			 0x0d00
#define OP_PCL_IPSEC_AES_XTS			 0x1600
#define OP_PCL_IPSEC_AES_CCM8			 0x0e00
#define OP_PCL_IPSEC_AES_CCM12			 0x0f00
#define OP_PCL_IPSEC_AES_CCM16			 0x1000
#define OP_PCL_IPSEC_AES_GCM8			 0x1200
#define OP_PCL_IPSEC_AES_GCM12			 0x1300
#define OP_PCL_IPSEC_AES_GCM16			 0x1400

#define OP_PCL_IPSEC_HMAC_NULL			 0x0000
#define OP_PCL_IPSEC_HMAC_MD5_96		 0x0001
#define OP_PCL_IPSEC_HMAC_SHA1_96		 0x0002
#define OP_PCL_IPSEC_AES_XCBC_MAC_96		 0x0005
#define OP_PCL_IPSEC_HMAC_MD5_128		 0x0006
#define OP_PCL_IPSEC_HMAC_SHA1_160		 0x0007
#define OP_PCL_IPSEC_HMAC_SHA2_256_128		 0x000c
#define OP_PCL_IPSEC_HMAC_SHA2_384_192		 0x000d
#define OP_PCL_IPSEC_HMAC_SHA2_512_256		 0x000e


#if 0
struct desc_hdr {
        uint32_t hdr_word;
        union {
                struct ipsec_encap_pdb pdb_en;
                struct ipsec_decap_pdb pdb_dec;
        };
};

struct sec_descriptor {
        u64     preheader;
        /* SEC Shared Descriptor */
        union {
                uint32_t desc[MAX_CAAM_DESCSIZE];
                struct desc_hdr desc_hdr;
#define hdr_word        desc_hdr.hdr_word
#define pdb_en          desc_hdr.pdb_en
#define pdb_dec         desc_hdr.pdb_dec
        };
};

#endif


int cdx_ipsec_init(void);
int cdx_ipsec_get_of_port_tbl_id ( PCtEntry entry, struct ins_entry_info *info);

PDpaSecSAContext  cdx_ipsec_sec_sa_context_alloc (uint32_t);
void cdx_ipsec_sec_sa_context_free(PDpaSecSAContext pdpa_sec_context ) ;

int cdx_dpa_ipsec_find_sa_direction(PSAEntry sa);
int  cdx_ipsec_add_classification_table_entry(PSAEntry sa);
int  cdx_ipsec_create_shareddescriptor(PSAEntry sa);
int cdx_ipsec_generate_split_key(struct auth_params *auth_param);
void cdx_ipsec_release_sa_resources(PSAEntry pSA);
#endif
