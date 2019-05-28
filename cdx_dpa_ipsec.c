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
#include <linux/delay.h>
#include <linux/udp.h>
#include "error.h"
#include "desc.h"
#include "jr.h"
#include "pdb.h"
#include "desc_constr.h"

#include "misc.h"
#include "cdx.h"
#include "cdx_common.h"
#include "control_ipv4.h"
#include "control_ipv6.h"
#include "control_pppoe.h"
#include "control_socket.h"
#include "layer2.h"
#include "control_ipsec.h"

#include "dpa_ipsec.h"
#include "cdx_dpa_ipsec.h"
#include "fm_ehash.h"


#define CLASS_SHIFT		25
#define CLASS_MASK		(0x03 << CLASS_SHIFT)

#define CLASS_NONE		(0x00 << CLASS_SHIFT)
#define CLASS_1			(0x01 << CLASS_SHIFT)
#define CLASS_2			(0x02 << CLASS_SHIFT)
#define CLASS_BOTH		(0x03 << CLASS_SHIFT)

#define PREHDR_IDLEN_SHIFT	32
#define PREHDR_OFFSET_SHIFT	26
#define PREHDR_BPID_SHIFT	16
#define PREHDR_BSIZE_SHIFT	0

#define PREHDR_IDLEN_MASK	GENMASK_ULL(39,32)
#define PREHDR_OFFSET_MASK	GENMASK_ULL(27,26)
#define PREHDR_BPID_MASK	GENMASK_ULL(23,16)
#define PREHDR_BSIZE_MASK	GENMASK_ULL(15,0)

#define PREHEADER_PREP_IDLEN(preh, idlen) \
	(preh) |= ((u64)(idlen) << PREHDR_IDLEN_SHIFT) & PREHDR_IDLEN_MASK

#define PREHEADER_PREP_BPID(preh, bpid) \
	(preh) |= ((u64)(bpid) << PREHDR_BPID_SHIFT) & PREHDR_BPID_MASK

#define PREHEADER_PREP_BSIZE(preh, bufsize) \
	(preh) |= ((u64)(bufsize) << PREHDR_BSIZE_SHIFT) & PREHDR_BSIZE_MASK

#define PREHEADER_PREP_OFFSET(preh, offs) \
	(preh) |= ((u64)(offs) << PREHDR_OFFSET_SHIFT) & PREHDR_OFFSET_MASK



/*
 * to retrieve a 256 byte aligned buffer address from an address
 * we need to copy only the first 7 bytes
 */
#define ALIGNED_PTR_ADDRESS_SZ  (CAAM_PTR_SZ - 1)

#define JOB_DESC_HDR_LEN        CAAM_CMD_SZ
#define SEQ_OUT_PTR_SGF_MASK    0x01000000;

#define SEQ_NUM_HI_MASK         0xFFFFFFFF00000000
#define SEQ_NUM_LOW_MASK        0x00000000FFFFFFFF

#define POST_SEC_OUT_DATA_OFFSET 128 //bytes multiple of 64
#define POST_SEC_IN_DATA_OFFSET  128 //bytes multiple of 64

/* relative offset where the input pointer should be updated in the descriptor*/
#define IN_PTR_REL_OFF          4 /* words from current location */

/* dummy pointer value */
#define DUMMY_PTR_VAL           0x00000000
#define PTR_LEN                 2       /* Descriptor is created only for 8 byte
                                         * pointer. PTR_LEN is in words. */
#define UDP_HEADER_LEN          8


struct ipsec_info *ipsec_instance;
int sec_era;
U64 post_sec_out_data_off;
U64 post_sec_in_data_off;

struct device *jrdev_g;


extern void *dpa_get_fm_ctx(uint32_t fm_idx);
extern uint32_t dpa_get_fm_timestamp(void *fm_ctx);
extern int create_sa_entry_hm_chain( PRouteEntry pRtEntry , 
		struct ins_entry_info *info, uint32_t sa_dir_in,
			 struct hw_ct *ct );
extern void delete_hm_chain(struct hw_ct * ct);
extern void *dpa_get_pcdhandle(uint32_t fm_index);
extern int dpa_get_out_tx_info_by_itf_id(PRouteEntry rt_entry , 
				struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info);
extern int dpa_get_in_tx_info_by_itf_id(uint32_t itf_id, 
				struct dpa_l2hdr_info *l2_info,
				struct dpa_l3hdr_info *l3_info, uint32_t * portid);
extern int cdx_dpa_get_ipsec_pool_info(uint32_t *bpid, uint32_t *buf_size);
extern int cdx_dpa_ipsec_wanport_itf(void *instance, uint32_t *itf);
extern void display_buf(void *, uint32_t);
extern int dpa_get_iface_info_by_ipaddress(int sa_family, uint32_t  *daddr, uint32_t *tx_fqid,
					uint32_t * itf_id, uint32_t * portid , void **netdev);
extern void *dpa_get_tdinfo(uint32_t fm_index, uint32_t port_idx, uint32_t type);
extern uint32_t dpa_get_timestamp_addr(uint32_t id);
extern int fill_ipsec_actions(PSAEntry entry, struct ins_entry_info *info,
                        uint32_t sa_dir_in);

extern int ExternalHashTableAddKey(void *h_HashTbl, uint8_t keySize,
                                       void *tbl_entry);
extern int ExternalHashTableDeleteKey(void *h_HashTbl, uint16_t index,
                                       void *tbl_entry);
//#define PRINT_DESC 
#ifdef PRINT_DESC
void cdx_ipsec_print_desc ( U32 *desc,const char* function)
{
	int  desc_length,ii;
	desc_length = desc_len(desc);
	printk(KERN_ERR "\n%s -  Desc dump: \n",function);
        for ( ii=0; ii< desc_length; ii++){ 
		printk(KERN_ERR "0x%08x \n", caam32_to_cpu(desc[ii]));
	}


}
#endif
#if 0
int cdx_ipsec_init(void)
{
	printk(KERN_INFO "%s\n", __func__);
	ipsec_instance = dpa_get_ipsec_instance();
	sec_era = 4 ;
	post_sec_out_data_off = ((uint64_t )POST_SEC_OUT_DATA_OFFSET /64);
	post_sec_in_data_off = ((uint64_t )POST_SEC_IN_DATA_OFFSET / 64);
	/* get the jr device  */
	jrdev_g  = caam_jr_alloc();
	if (!jrdev_g) {
		log_err("Failed to get the job ring device, check the dts\n");
		return -EINVAL;
	}
	printk(KERN_INFO "%s job ring device= %p\n", __func__,jrdev_g);
	return 0;
}
#endif


int cdx_ipsec_fill_sec_info( PCtEntry entry, struct ins_entry_info *info)
{
	int i;
	PSAEntry sa;
  
	for (i=0;i < SA_MAX_OP;i++)
	{ 
		if((sa = M_ipsec_sa_cache_lookup_by_h(entry->hSAEntry[i])) 
					!= NULL)
		{ 
               		if(sa->direction == CDX_DPA_IPSEC_OUTBOUND )
			{
				info->to_sec_fqid = 
				  sa->pSec_sa_context->to_sec_fqid;
				 info->sa_family = sa->family ;
#ifdef CDX_DPA_DEBUG	
			printk(KERN_CRIT "%s OutBound SA info->to_sec_fqid  = %d\n", __func__,info->to_sec_fqid );
#endif				
			}else{
				dpa_ipsec_ofport_td(ipsec_instance, 
					info->tbl_type, &info->td, &info->port_id );
#ifdef CDX_DPA_DEBUG	
//			printk(KERN_CRIT "%s InBound SA info->td  = %d\n", __func__,info->td );
#endif
			}
		}
	}
	return 0;
}

void cdx_ipsec_sec_sa_context_free(PDpaSecSAContext pdpa_sec_context ) 
{

	if(pdpa_sec_context->dpa_ipsecsa_handle)
		cdx_dpa_ipsecsa_release(pdpa_sec_context->dpa_ipsecsa_handle);
        if(pdpa_sec_context->cipher_data.cipher_key)
        	kfree(pdpa_sec_context->cipher_data.cipher_key);
       	if(pdpa_sec_context->auth_data.auth_key)
       		kfree(pdpa_sec_context->auth_data.auth_key);
	if(pdpa_sec_context->auth_data.split_key)
		kfree(pdpa_sec_context->auth_data.split_key); 
        if(pdpa_sec_context->sec_desc_extra_cmds_unaligned)
        	kfree(pdpa_sec_context->sec_desc_extra_cmds_unaligned);
        if(pdpa_sec_context->rjob_desc_unaligned)
        	kfree(pdpa_sec_context->rjob_desc_unaligned);
	kfree(pdpa_sec_context);

}
void cdx_ipsec_release_sa_resources(PSAEntry pSA)
{
        cdx_ipsec_sec_sa_context_free(pSA->pSec_sa_context ) ;
        pSA->pSec_sa_context = NULL;
        if(pSA->ct)
	{
#ifndef USE_ENHANCED_EHASH
        	if (dpa_classif_table_delete_entry_by_ref(pSA->ct->td,
                	pSA->ct->handle)) {
                	DPA_ERROR("%s::failed to remove entry\n",
                        __FUNCTION__);
        	}
        	delete_hm_chain(pSA->ct);
#else
		if (ExternalHashTableDeleteKey(pSA->ct->td, 
			pSA->ct->index, pSA->ct->handle)) {
                DPA_ERROR("%s::unable to remove entry from hash table\n", __FUNCTION__);
		}
    		//free table entry
    		ExternalHashTableEntryFree(pSA->ct->handle);
		pSA->ct->handle =  NULL;
#endif
        	kfree(pSA->ct);
        	pSA->ct = NULL;
	}
        return;
}

PDpaSecSAContext  cdx_ipsec_sec_sa_context_alloc(uint32_t handle)
{	

	PDpaSecSAContext pdpa_sec_context; 
	pdpa_sec_context = Heap_Alloc(sizeof( DpaSecSAContext));
        if(!pdpa_sec_context )
	{
		return NULL;
	}  	
	memset(pdpa_sec_context , 0, sizeof(DpaSecSAContext));
        pdpa_sec_context->cipher_data.cipher_key =
                                        kzalloc(MAX_CIPHER_KEY_LEN, GFP_KERNEL);
        if (!pdpa_sec_context->cipher_data.cipher_key) {
               	log_err("Could not allocate memory for cipher key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
               	return NULL;
        }
	memset(pdpa_sec_context->cipher_data.cipher_key, 0, MAX_CIPHER_KEY_LEN);
       	pdpa_sec_context->auth_data.auth_key =
                                        kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
        if (!pdpa_sec_context->auth_data.auth_key) {
               	log_err("Could not allocate memory for authentication key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
               	return NULL;
        }
	memset(pdpa_sec_context->auth_data.auth_key, 0, MAX_AUTH_KEY_LEN);

	pdpa_sec_context->auth_data.split_key =
                                        kzalloc(MAX_AUTH_KEY_LEN, GFP_KERNEL);
        if (!pdpa_sec_context->auth_data.split_key) {
                log_err("Could not allocate memory for authentication split key\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
               	return NULL;
        }
	memset(pdpa_sec_context->auth_data.split_key, 0, MAX_AUTH_KEY_LEN);

        /* Allocate space for extra material space in case when the
         * descriptor is greater than 64 words */
        pdpa_sec_context->sec_desc_extra_cmds_unaligned =
                        kzalloc(2 * MAX_EXTRA_DESC_COMMANDS + L1_CACHE_BYTES,
                                GFP_KERNEL);
        if (!pdpa_sec_context->sec_desc_extra_cmds_unaligned) {
                log_err("Allocation failed for CAAM extra commands\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
               	return NULL;
        }
	memset(pdpa_sec_context->sec_desc_extra_cmds_unaligned, 0,(2* MAX_EXTRA_DESC_COMMANDS + L1_CACHE_BYTES));

        pdpa_sec_context->sec_desc_extra_cmds =
                 PTR_ALIGN(pdpa_sec_context->sec_desc_extra_cmds_unaligned,
                                          L1_CACHE_BYTES);
        if (pdpa_sec_context->sec_desc_extra_cmds_unaligned ==
                    pdpa_sec_context->sec_desc_extra_cmds)
        	pdpa_sec_context->sec_desc_extra_cmds += L1_CACHE_BYTES / 4;

         /*
          * Allocate space for the SEC replacement job descriptor
          * Required 64 byte alignment
                 */
        pdpa_sec_context->rjob_desc_unaligned =
                        kzalloc(MAX_CAAM_DESCSIZE * sizeof(U32) + 64,
                                GFP_KERNEL);
        if (!pdpa_sec_context->rjob_desc_unaligned) {
                log_err("No memory for replacement job descriptor\n");
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
               	return NULL;
        }
	memset(pdpa_sec_context->rjob_desc_unaligned, 0,(MAX_CAAM_DESCSIZE * sizeof(U32)+64));
        pdpa_sec_context->rjob_desc = 
			PTR_ALIGN(pdpa_sec_context->rjob_desc_unaligned, 64);
	pdpa_sec_context->dpa_ipsecsa_handle  = cdx_dpa_ipsecsa_alloc(NULL, handle); 
	if(pdpa_sec_context->dpa_ipsecsa_handle){
		pdpa_sec_context->sec_desc = 
			get_shared_desc(pdpa_sec_context->dpa_ipsecsa_handle);
		pdpa_sec_context->to_sec_fqid = 
			get_fqid_to_sec(pdpa_sec_context->dpa_ipsecsa_handle);	
		pdpa_sec_context->from_sec_fqid = 
		     get_fqid_from_sec(pdpa_sec_context->dpa_ipsecsa_handle);
#ifdef CDX_DPA_DEBUG	
		printk("%s::fqid_to_sec %x(%d), fqid_from_sec %x(%d)\n",
			__FUNCTION__, pdpa_sec_context->to_sec_fqid,
			pdpa_sec_context->to_sec_fqid,
			pdpa_sec_context->from_sec_fqid,
			pdpa_sec_context->from_sec_fqid);
#endif
	}
	else {
		cdx_ipsec_sec_sa_context_free(pdpa_sec_context); 
               	return NULL;
	}
	return pdpa_sec_context;	
}

static inline int get_cipher_params(U16 cipher_alg,
                                    uint32_t *iv_length, uint32_t *icv_length,
                                    uint32_t *max_pad_length)
{
        switch (cipher_alg) {
#if 0
        case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_MD5_128:
        case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_96_SHA_160:
                *iv_length = 8;
                *max_pad_length = 8;
                *icv_length = 12;
                break;
        case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_MD5_128:
                *iv_length = 8;
                *max_pad_length = 8;
                *icv_length = 16;
                break;
        case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_160:
        case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_256_128:
                *iv_length = 8;
                *max_pad_length = 8;
                *icv_length = 20;
                break;
        case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_384_192:
                *iv_length = 8;
                *max_pad_length = 8;
                *icv_length = 24;
                break;
        case DPA_IPSEC_CIPHER_ALG_3DES_CBC_HMAC_SHA_512_256:
                *iv_length = 8;
                *max_pad_length = 8;
                *icv_length = 32;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_MD5_128:
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_96_SHA_160:
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_AES_XCBC_MAC_96:
                *iv_length = 16;
                *max_pad_length = 16;
                *icv_length = 12;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_MD5_128:
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_256_128:
                *iv_length = 16;
                *max_pad_length = 16;
                *icv_length = 16;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_160:
                *iv_length = 16;
                *max_pad_length = 16;
                *icv_length = 20;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_384_192:
                *iv_length = 16;
                *max_pad_length = 16;
                *icv_length = 24;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CBC_HMAC_SHA_512_256:
                *iv_length = 16;
                *max_pad_length = 16;
                *icv_length = 32;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_MD5_128:
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_96_SHA_160:
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_AES_XCBC_MAC_96:
                *iv_length = 16;
                *max_pad_length = 16;
                *icv_length = 12;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_MD5_128:
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_256_128:
                *iv_length = 8;
                *max_pad_length = 4;
                *icv_length = 16;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_160:
                *iv_length = 8;
                *max_pad_length = 4;
                *icv_length = 20;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_384_192:
                *iv_length = 8;
                *max_pad_length = 4;
                *icv_length = 24;
                break;
        case DPA_IPSEC_CIPHER_ALG_AES_CTR_HMAC_SHA_512_256:
                *iv_length = 8;
                *max_pad_length = 4;
                *icv_length = 32;
                break;
#endif
        default:
                *iv_length = 0;
                *icv_length = 0;
                *max_pad_length = 0;
                log_err("Unsupported cipher suite %d\n", cipher_alg);
                return -EINVAL;
        }

        return 0;
}


int cdx_ipsec_build_shared_descriptor(PSAEntry sa,
			    dma_addr_t auth_key_dma,
			    dma_addr_t crypto_key_dma, u32 bytes_to_copy)
{
	uint32_t *desc, *key_jump_cmd;
	//uint32_t  copy_ptr_index = 0;
	int opthdrsz;
	size_t pdb_len = 0;
	uint32_t sa_op; 
	PDpaSecSAContext pSec_sa_context; 

#if 0
	printk("%s::authkey %p, cryptokey %p\n", __FUNCTION__,
		 (void *)auth_key_dma, (void *)crypto_key_dma);
#endif
	pSec_sa_context =sa->pSec_sa_context; 
	
	desc = (u32 *) pSec_sa_context->sec_desc->shared_desc;
	/* Reserve 2 words for statistics */
#if 0
	if (sa->enable_stats)
		pdb_len = CDX_DPA_IPSEC_STATS_LEN * sizeof(u32);
#endif

	if (sa->direction  == CDX_DPA_IPSEC_OUTBOUND) {
		/* Compute optional header size, rounded up to descriptor
		 * word size */
		opthdrsz = 
		 (caam32_to_cpu(pSec_sa_context->sec_desc->pdb_en.ip_hdr_len) +
				3) & ~3;
		pdb_len += sizeof(struct ipsec_encap_pdb) + opthdrsz;
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL, pdb_len);
		//init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_WAIT, pdb_len);
		sa_op = OP_TYPE_ENCAP_PROTOCOL;  
	} else {
		pdb_len += sizeof(struct ipsec_decap_pdb);
		init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL, pdb_len);
		//init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_WAIT, pdb_len);
		sa_op = OP_TYPE_DECAP_PROTOCOL;
	}

	/* Key jump */
	key_jump_cmd = append_jump(desc, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_SHRD | JUMP_COND_SELF);

	/* check whether a split of a normal key is used */
	if (pSec_sa_context->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(desc, auth_key_dma, pSec_sa_context->auth_data.split_key_len,
			   CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else
		/* Append normal authentication key */
		append_key(desc, auth_key_dma, pSec_sa_context->auth_data.auth_key_len,
			   CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(desc, crypto_key_dma, pSec_sa_context->cipher_data.cipher_key_len,
		   CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(desc, key_jump_cmd);
#if 0
        /*
         * Should enable for dscp copy or ECN. Currently could not find where
	 * this is configured in  cdx. - Rajendran oct21. 
         */
	/* copy frame meta data (IC) to enable DSCP / ECN propagation */
	if (sa->dscp_copy || sa->ecn_copy) {
		/* save location of ptr copy commands to update offset later */
		copy_ptr_index = desc_len(desc);
		build_meta_data_desc_cmds(sa, sa->dpa_ipsec->sec_era, 64);
	}
#endif
	if (bytes_to_copy == 0)
		goto skip_byte_copy;

	/* Copy L2 header from the original packet to the outer packet */

	/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* seqfifold: both msgdata-last2-last1-flush1 len=4 */
	append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
			     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
			     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

	/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* move: ififo->deco-alnblk -> ofifo, len=4 */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* Done coping L2 header from the original packet to the outer packet */

skip_byte_copy:

       /* Do we need to enable stats and where do we use it?
        */
#if 0
	if (sa->enable_stats)
		build_stats_descriptor_part(sa, pdb_len);
#endif	
	/* Protocol specific operation */
	append_operation(desc, OP_PCLID_IPSEC |sa_op |
			pSec_sa_context->cipher_data.cipher_type | 
			pSec_sa_context->auth_data.auth_type);

#if 0
	if (sa->enable_stats)
		save_stats_in_external_mem(sa);

	if (sa->dscp_copy || sa->ecn_copy)
		/* insert cmds to copy SEQ_IN/OUT_PTR - with updated offset */
		insert_ptr_copy_cmds(desc, copy_ptr_index,
				     desc_len(desc), false);
#endif
	/*For inbound Ipsec traffic, copy SAGD  to the outer packet at the end */

	if (sa->direction  == CDX_DPA_IPSEC_INBOUND) {
		/* ld: deco-deco-ctrl len=0 offs=8 imm -auto-nfifo-entries */
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

        	/* fifo load immediate: sa-> handle value to input fifo */
        	append_fifo_load_as_imm(desc, (void *)&sa->handle,
                                	2, FIFOLD_TYPE_MSG|
                             		FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
                             		FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/* ld: deco-deco-ctrl len=0 offs=4 imm +auto-nfifo-entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

		/* move: ififo->deco-alnblk -> ofifo, len=4 */
		append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | 2);

		/* seqfifostr: msgdata len=4 */
		append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, 2);

	}
	/* Done coping SAGD value to the outer packet at the end*/

#ifdef PRINT_DESC
	//if (sa->direction == CDX_DPA_IPSEC_OUTBOUND)
		cdx_ipsec_print_desc ( desc,__func__);
#endif
	if (desc_len(desc) >= MAX_CAAM_SHARED_DESCSIZE) {
		if (sa->enable_stats)
			memset((uint8_t *)desc + sa->stats_offset, 0,
				MAX_CAAM_DESCSIZE * sizeof(u32) -
				sa->stats_offset);
		return -EPERM;
	}

	//flush cache here??
	return 0;
}

int built_encap_extra_material(PSAEntry sa,
			       dma_addr_t auth_key_dma,
			       dma_addr_t crypto_key_dma,
			       unsigned int move_size)
{
	uint32_t *extra_cmds, *padding_jump, *key_jump_cmd;
	uint32_t len, off_b, off_w, off, opt;
	unsigned char job_desc_len, block_size;

	PDpaSecSAContext pSec_sa_context; 

	pSec_sa_context =sa->pSec_sa_context; 
	/*
	 * sec_desc_extra_cmds is the address were the first SEC extra command
	 * is located, from here SEC will overwrite Job descriptor part. Need
	 * to insert a dummy command because the LINUX CAAM API uses first word
	 * for storing the length of the descriptor.
	 */
	extra_cmds = pSec_sa_context->sec_desc_extra_cmds - 1;

	/*
	 * Dummy command - will not be executed at all. Only for setting to 1
	 * the length of the extra_cmds descriptor so that first extra material
	 * command will be located exactly at sec_desc_extra_cmds address.
	 */
	append_cmd(extra_cmds, 0xdead0000);

	/* Start Extra Material Group 1 */
	/* Load from the input address 64 bytes into internal register */
	/* load the data to be moved - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_load(extra_cmds, DUMMY_PTR_VAL, len, opt | off);

	/* Wait to finish previous operation */
	opt = JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT);
	append_jump(extra_cmds, opt);

	/* Store the data to the output FIFO - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_store(extra_cmds, DUMMY_PTR_VAL, len, opt | off);

	/* Fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off = 0x80 << LDST_OFFSET_SHIFT; /* NON_SEQ LIODN */
	append_cmd(extra_cmds, CMD_LOAD | opt | off);

	/* MATH0 += 1 (packet counter) */
	append_math_add(extra_cmds, REG0, REG0, ONE, MATH_LEN_8BYTE);

	/* Overwrite the job-desc location (word 51 or 53) with the second
	 * group (10 words) */
	job_desc_len = pSec_sa_context->job_desc_len;
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (10 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(extra_cmds, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Jump to the beginning of the JOB Descriptor to start executing
	 * the extra material group 2
	 */
	append_cmd(extra_cmds, 0xa00000f6);

	/* End of Extra Material Group 1 */

	/* Start Extra Material Group 2 */
	/* MATH REG 2 = Sequence in length + 2; 2 for pad-len and NH field */
	append_math_add_imm_u32(extra_cmds, REG2, SEQINLEN, IMM, 2);

	switch (pSec_sa_context->cipher_data.cipher_type) {
	case OP_PCL_IPSEC_3DES:
		block_size = 8; /* block size in bytes */
		break;
	case OP_PCL_IPSEC_AES_CBC:
	case OP_PCL_IPSEC_AES_CTR:
	case OP_PCL_IPSEC_AES_XTS:
	case OP_PCL_IPSEC_AES_CCM8:
	case OP_PCL_IPSEC_AES_CCM12:
	case OP_PCL_IPSEC_AES_CCM16:
	case OP_PCL_IPSEC_AES_GCM8:
	case OP_PCL_IPSEC_AES_GCM12:
	case OP_PCL_IPSEC_AES_GCM16:
		block_size = 16; /* block size in bytes */
		break;
	default:
		pr_crit("Invalid cipher algorithm for SA with spi %d\n", 
			sa->id.spi);
		return -EINVAL;
	}

	/* Adding padding to byte counter */
	append_math_and_imm_u32(extra_cmds, REG3, REG2, IMM, block_size - 1);

	/* Previous operation result is 0 i.e padding added to bytes count */
	padding_jump = append_jump(extra_cmds, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_MATH_Z);

	/* MATH REG 2 = MATH REG 2 + 1 */
	append_math_add(extra_cmds, REG2, REG2, ONE, MATH_LEN_4BYTE);

	/* jump back to adding padding i.e jump back 4 words */
	off = (-4) & 0x000000FF;
	append_jump(extra_cmds, (off << JUMP_OFFSET_SHIFT));

	set_jump_tgt_here(extra_cmds, padding_jump);
	/* Done adding padding to byte counter */

	/*
	 * Perform 32-bit left shift of DEST and concatenate with left 32 bits
	 * of SRC1 i.e MATH REG 2 = 0x00bytecount_00000000
	 */
	append_math_ldshift(extra_cmds, REG2, REG0, REG2, MATH_LEN_8BYTE);

	/* MATH REG 0  = MATH REG 0 + MATH REG 2 */
	append_math_add(extra_cmds, REG0, REG0, REG2, MATH_LEN_8BYTE);

	/*
	 * Overwrite the job-desc location (word 51 or 53) with the third
	 * group (11 words)
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (11 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(extra_cmds, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Jump to the beginning of the JOB Descriptor to start executing
	 * the extra material group 3. The command for jumping back is already
	 * here from extra material group 1
	 */

	/* End of Extra Material Group 2 */

	/* Start Extra Material Group 3 */

	if (sa->enable_stats) {
		/* Store statistics in the CAAM internal descriptor */
		off_b = sa->stats_indx * CAAM_CMD_SZ;
		append_move(extra_cmds, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
			    (off_b << MOVE_OFFSET_SHIFT) |
			    sizeof(uint64_t));
	} else {
		/* Statistics are disabled. Do not update descriptor counter */
		append_cmd(extra_cmds, 0xA0000001); /* NOP for SEC */
	}

	/* Key jump */
	key_jump_cmd = append_jump(extra_cmds, CLASS_BOTH | JUMP_TEST_ALL |
				   JUMP_COND_SHRD);

	/* check whether a split of a normal key is used */
	if (pSec_sa_context->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(extra_cmds, auth_key_dma,
			   pSec_sa_context->auth_data.split_key_len,
			   CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else
		/* Append normal authentication key */
		append_key(extra_cmds, auth_key_dma, pSec_sa_context->auth_data.auth_key_len,
			   CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(extra_cmds, crypto_key_dma, 
			pSec_sa_context->cipher_data.cipher_key_len,
		   	CLASS_1 | KEY_DEST_CLASS_REG);

	set_jump_tgt_here(extra_cmds, key_jump_cmd);

	/* Protocol specific operation */
	append_operation(extra_cmds, OP_PCLID_IPSEC | OP_TYPE_ENCAP_PROTOCOL |
			 pSec_sa_context->cipher_data.cipher_type | 
			pSec_sa_context->auth_data.auth_type);

	if (sa->enable_stats) {
		/*
		 * Store command: in the case of the Descriptor Buffer the
		 * length is specified in 4-byte words, but in all other cases
		 * the length is specified in bytes. Offset in 4 byte words
		 */
		off_w = sa->stats_indx;
		append_store(extra_cmds, 0, CDX_DPA_IPSEC_STATS_LEN,
			     LDST_CLASS_DECO | (off_w << LDST_OFFSET_SHIFT) |
			     LDST_SRCDST_WORD_DESCBUF_SHARED);
	} else {
		/* Do not store lifetime counter in external memory */
		append_cmd(extra_cmds, 0xA0000001); /* NOP for SEC */
	}

	/* Jump with CALM to be sure previous operation was finished */
	append_jump(extra_cmds, JUMP_TYPE_HALT_USER | JUMP_COND_CALM);

	/* End of Extra Material Group 3 */

	return 0;
}

/* Move size should be set to 64 bytes */
void built_decap_extra_material(PSAEntry sa,
			       dma_addr_t auth_key_dma,
			       dma_addr_t crypto_key_dma)
{
	uint32_t *extra_cmds;
	uint32_t off_b, off_w, data;
	PDpaSecSAContext pSec_sa_context; 

	pSec_sa_context =sa->pSec_sa_context; 

	/*
	 * sec_desc_extra_cmds is the address were the first SEC extra command
	 * is located, from here SEC will overwrite Job descriptor part. Need
	 * to insert a dummy command because the LINUX CAAM API uses first word
	 * for storing the length of the descriptor.
	 */
	extra_cmds = pSec_sa_context->sec_desc_extra_cmds - 1;

	/*
	 * Dummy command - will not be executed at all. Only for setting to 1
	 * the length of the extra_cmds descriptor so that first extra material
	 * command will be located exactly at sec_desc_extra_cmds address.
	 */
	append_cmd(extra_cmds, 0xdead0000);

	data = 16;
	append_math_rshift_imm_u64(extra_cmds, REG2, REG2, IMM, data);

	/* math: (math1 - math2)->math1 len=8 */
	append_math_sub(extra_cmds, REG1, REG1, REG2, MATH_LEN_8BYTE);

	/* math: (math0 + 1)->math0 len=8 */
	append_math_add(extra_cmds, REG0, REG0, ONE, MATH_LEN_8BYTE);

	append_math_ldshift(extra_cmds, REG1, REG0, REG1, MATH_LEN_8BYTE);

	append_math_add(extra_cmds, REG0, REG0, REG1, MATH_LEN_8BYTE);

	append_cmd(extra_cmds, 0x7883c824);

	/* Store in the descriptor but not in external memory */
	off_b = sa->stats_offset;
	append_move(extra_cmds, MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF |
		    MOVE_WAITCOMP | (off_b << MOVE_OFFSET_SHIFT) | sizeof(u64));

	append_cmd(extra_cmds, 0xa70040fe);

	append_cmd(extra_cmds, 0xa00000f7);

	/* check whether a split of a normal key is used */
	if (pSec_sa_context->auth_data.split_key_len)
		/* Append split authentication key */
		append_key(extra_cmds, auth_key_dma,
			   pSec_sa_context->auth_data.split_key_len,
			   CLASS_2 | KEY_ENC | KEY_DEST_MDHA_SPLIT);
	else
		/* Append normal authentication key */
		append_key(extra_cmds, auth_key_dma, 
				pSec_sa_context->auth_data.auth_key_len,
			   	CLASS_2 | KEY_DEST_CLASS_REG);

	/* Append cipher key */
	append_key(extra_cmds, crypto_key_dma, 
			pSec_sa_context->cipher_data.cipher_key_len,
		   	CLASS_1 | KEY_DEST_CLASS_REG);

	/* Protocol specific operation */
	append_operation(extra_cmds, OP_PCLID_IPSEC | OP_TYPE_DECAP_PROTOCOL |
			 pSec_sa_context->cipher_data.cipher_type | 
			 pSec_sa_context->auth_data.auth_type);

	/*
	 * Store command: in the case of the Descriptor Buffer the length
	 * is specified in 4-byte words, but in all other cases the length
	 * is specified in bytes. Offset in 4 byte words
	 */
	off_w = sa->stats_indx;
	append_store(extra_cmds, 0, CDX_DPA_IPSEC_STATS_LEN,
		     LDST_CLASS_DECO | (off_w << LDST_OFFSET_SHIFT) |
		     LDST_SRCDST_WORD_DESCBUF_SHARED);

	append_jump(extra_cmds, JUMP_TYPE_HALT_USER | JUMP_COND_CALM);
}

int cdx_ipsec_build_extended_encap_shared_descriptor(PSAEntry sa,
				     dma_addr_t auth_key_dma,
				     dma_addr_t crypto_key_dma,
				     U32 bytes_to_copy,
				     int sec_era)
{
	U32 *desc, *no_sg_jump, *extra_cmds;
	U32  len, off_b, off_w, opt, stats_off_b, sg_mask;
	unsigned int extra_cmds_len;
	unsigned char job_desc_len;
	dma_addr_t dma_extra_cmds;
	int ret;
	PDpaSecSAContext pSec_sa_context; 

	pSec_sa_context =sa->pSec_sa_context; 

	desc = (U32 *)pSec_sa_context->sec_desc->shared_desc;

	if (sec_era == 2) {
		if (sa->enable_stats)
			sa->stats_indx = 27;
		sa->next_cmd_indx = 29;
	} else {
		if (sa->enable_stats)
			sa->stats_indx = 28;
		sa->next_cmd_indx = 30;
	}

	/* This code only works when SEC is configured to use PTR on 64 bit
	 * so the Job Descriptor length is 13 words long when DPOWRD is set */
	job_desc_len = 13;

	/* Set CAAM Job Descriptor length */
	pSec_sa_context->job_desc_len = job_desc_len;

	/* Set lifetime counter stats offset */
	sa->stats_offset = sa->stats_indx * sizeof(uint32_t);

	ret = built_encap_extra_material(sa, auth_key_dma, crypto_key_dma, 64);
	if (ret < 0) {
		log_err("Failed to create extra CAAM commands\n");
		return -EAGAIN;
	}

	extra_cmds = pSec_sa_context->sec_desc_extra_cmds - 1;
	extra_cmds_len = desc_len(extra_cmds) - 1;

	/* get the jr device  */

	dma_extra_cmds = dma_map_single(jrdev_g,
					 pSec_sa_context->sec_desc_extra_cmds,
					extra_cmds_len * sizeof(uint32_t),
					DMA_TO_DEVICE);
	if (!dma_extra_cmds) {
		log_err("Could not DMA map extra CAAM commands\n");
		return -ENXIO;
	}

	init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
			 (sa->next_cmd_indx - 1) * sizeof(uint32_t));

	if (sec_era == 2) {
		/* disable iNFO FIFO entries for p4080rev2 & ??? */
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 * Offset refers to SRC
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_CLASS1INFIFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
				     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
				     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_TYPE_MSG | FIFOLD_CLASS_BOTH |
				 FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_LAST2 |
				 FIFOLD_TYPE_FLUSH1);

		/* enable iNFO FIFO entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);
	} else {
		/* ????? */
		opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | opt | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_INFIFO_NOINFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes. No information FIFO entry even if automatic
		 * iNformation FIFO entries are enabled.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_CLASS_BOTH |
				     FIFOLD_TYPE_NOINFOFIFO);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_CLASS_BOTH | FIFOLD_TYPE_NOINFOFIFO);
	}

	/*
	 * throw away the first part of the S/G table and keep only the buffer
	 * address;
	 * offset = undefined memory after MATH3; Refers to the destination.
	 * len = 41 bytes to discard
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 8 << MOVE_OFFSET_SHIFT;
	len   = 41 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* put the buffer address (still in the IN FIFO) in MATH2 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 0 << MOVE_OFFSET_SHIFT;
	len   = 8 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* copy 15 bytes starting at 4 bytes before the OUT-PTR-CMD in
	 * the job-desc into math1
	 * i.e. in the low-part of math1 we have the out-ptr-cmd and
	 * in the math2 we will have the address of the out-ptr
	 */
	opt = MOVE_SRC_DESCBUF | MOVE_DEST_MATH1;
	off_b = (MAX_CAAM_DESCSIZE - job_desc_len + PTR_LEN) * sizeof(uint32_t);
	len = (8 + 4 * PTR_LEN - 1) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Copy 7 bytes of the in-ptr into math0 */
	opt   = MOVE_SRC_DESCBUF | MOVE_DEST_MATH0;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 1 + 3 + 2 * PTR_LEN;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * the SEQ OUT PTR command is now in math reg 1, so the SGF bit can be
	 * checked using a math command;
	 */
	sg_mask = SEQ_OUT_PTR_SGF_MASK;
	append_math_and_imm_u32(desc, NONE, REG1, IMM, sg_mask);

	opt = CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_COND_MATH_Z | JUMP_TEST_ALL;
	no_sg_jump = append_jump(desc, opt);

	append_math_add(desc, REG2, ZERO, REG3, MATH_LEN_8BYTE);

	/* update no S/G jump location */
	set_jump_tgt_here(desc, no_sg_jump);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* move: ififo->deco-alnblk -> ofifo, len=4 */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* Overwrite the job-desc location (word 51 or 53) with the first
	 * group (11 words)*/
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (11 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math0 (input address) to words 52+53 or 54+56
	 * depending where the Job Descriptor starts.
	 * They will be used later by the load command.
	 */
	opt = MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 1; /* 52 + 53 or 54 + 55 */
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math2 (output address) to words 56+57 or 58+59
	 * depending where the Job Descriptor starts.
	 * They will be used later by the store command.
	 */
	opt = MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF;
	off_w = MAX_CAAM_DESCSIZE - job_desc_len + 5; /* 56 + 57 or 58 + 59 */
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Fix LIODN - OFFSET[0:1] - 01 = SEQ LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x40; /* SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | (off_b << LDST_OFFSET_SHIFT));

	/* Copy the context of the counters from word 29 into math0 */
	/* Copy from descriptor to MATH REG 0 the current statistics */
	stats_off_b = sa->stats_indx * CAAM_CMD_SZ;
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 |
		    (stats_off_b << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	dma_unmap_single(jrdev_g, dma_extra_cmds,
			 extra_cmds_len * sizeof(uint32_t), DMA_TO_DEVICE);

#ifdef PRINT_DESC
	cdx_ipsec_print_desc ( desc,__func__);
#endif
	return 0;
}

int cdx_ipsec_build_extended_decap_shared_descriptor(PSAEntry sa,
					   dma_addr_t auth_key_dma,
					   dma_addr_t crypto_key_dma,
					   uint32_t bytes_to_copy,
					   uint8_t move_size,
					   int sec_era)
{
	uint32_t *desc, *no_sg_jump, *extra_cmds;
	uint32_t len, off_b, off_w, opt, stats_off_b, sg_mask, extra_cmds_len,
		 esp_length, iv_length, icv_length, max_pad, data;
	dma_addr_t dma_extra_cmds;
	PDpaSecSAContext psec_as_context;
	
	psec_as_context = sa->pSec_sa_context;

	desc = (uint32_t *)psec_as_context->sec_desc->shared_desc;

	/* CAAM hdr cmd + PDB size in words */
	sa->next_cmd_indx =
		sizeof(struct ipsec_decap_pdb) / sizeof(uint32_t) + 1;
	if (sa->enable_stats) {
		sa->stats_indx = sa->next_cmd_indx;
		sa->next_cmd_indx += 2;
		if (sec_era != 2) {
			sa->stats_indx += 1;
			sa->next_cmd_indx += 1;
		}
	}

	/* Set lifetime counter stats offset */
	sa->stats_offset = sa->stats_indx * sizeof(uint32_t);

	built_decap_extra_material(sa, auth_key_dma, crypto_key_dma);

	extra_cmds = psec_as_context->sec_desc_extra_cmds - 1;
	extra_cmds_len = desc_len(extra_cmds) - 1;


	dma_extra_cmds = dma_map_single(jrdev_g, psec_as_context->sec_desc_extra_cmds,
					extra_cmds_len * sizeof(uint32_t),
					DMA_TO_DEVICE);
	if (!dma_extra_cmds) {
		log_err("Could not DMA map extra CAAM commands\n");
		return -ENXIO;
	}

	init_sh_desc_pdb(desc, HDR_SAVECTX | HDR_SHARE_SERIAL,
			 (sa->next_cmd_indx - 1) * sizeof(uint32_t));

	if (sec_era == 2) {
		/* disable iNFO FIFO entries for p4080rev2 & ??? */
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 * Offset refers to SRC
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_CLASS1INFIFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_TYPE_MSG |
				     FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LAST1 |
				     FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_FLUSH1);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_TYPE_MSG | FIFOLD_CLASS_BOTH |
				 FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_LAST2 |
				 FIFOLD_TYPE_FLUSH1);

		/* enable iNFO FIFO entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);
	} else {
		/* ????? */
		opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
		len = 0x10 << LDST_LEN_SHIFT;
		append_cmd(desc, CMD_LOAD | opt | len);

		/*
		 * load in IN FIFO the S/G Entry located in the 5th reg after
		 * MATH3 -> offset = sizeof(GT_REG) * 4 + offset_math3_to_GT_REG
		 * len = sizeof(S/G entry)
		 */
		opt   = MOVE_SRC_MATH3 | MOVE_DEST_INFIFO_NOINFO;
		off_b = 127 << MOVE_OFFSET_SHIFT;
		len   = 49 << MOVE_LEN_SHIFT;
		append_move(desc, opt | off_b | len);

		/*
		 * L2 part 1
		 * Load from input packet to INPUT DATA FIFO first bytes_to_copy
		 * bytes. No information FIFO entry even if automatic
		 * iNformation FIFO entries are enabled.
		 */
		append_seq_fifo_load(desc, bytes_to_copy, FIFOLD_CLASS_BOTH |
				     FIFOLD_TYPE_NOINFOFIFO);

		/*
		 * Extra word part 1
		 * Load extra words for this descriptor into the INPUT DATA FIFO
		 */
		append_fifo_load(desc, dma_extra_cmds,
				 extra_cmds_len * sizeof(uint32_t),
				 FIFOLD_CLASS_BOTH | FIFOLD_TYPE_NOINFOFIFO);
	}

	/*
	 * throw away the first part of the S/G table and keep only the buffer
	 * address;
	 * offset = undefined memory after MATH3; Refers to the destination.
	 * len = 41 bytes to discard
	 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 8 << MOVE_OFFSET_SHIFT;
	len   = 41 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/* put the buffer address (still in the IN FIFO) in MATH2 */
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_MATH3;
	off_b = 0 << MOVE_OFFSET_SHIFT;
	len   = 8 << MOVE_LEN_SHIFT;
	append_move(desc, opt | off_b | len);

	/*
	 * Copy 15 bytes starting at 4 bytes before the OUT-PTR-CMD in
	 * the job-desc into math1
	 * i.e. in the low-part of math1 we have the out-ptr-cmd and
	 * in the math2 we will have the address of the out-ptr
	 */
	opt = MOVE_SRC_DESCBUF | MOVE_DEST_MATH1;
	off_b = (50 + 1 * PTR_LEN) * sizeof(uint32_t);
	len = (8 + 4 * PTR_LEN - 1) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Copy 7 bytes of the in-ptr into math0 */
	opt   = MOVE_SRC_DESCBUF | MOVE_DEST_MATH0;
	off_w = 50 + 1 + 3 + 2 * PTR_LEN;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * the SEQ OUT PTR command is now in math reg 1, so the SGF bit can be
	 * checked using a math command;
	 */
	sg_mask = SEQ_OUT_PTR_SGF_MASK;
	append_math_and_imm_u32(desc, NONE, REG1, IMM, sg_mask);

	opt = CLASS_NONE | JUMP_TYPE_LOCAL | JUMP_COND_MATH_Z | JUMP_TEST_ALL;
	no_sg_jump = append_jump(desc, opt);

	append_math_add(desc, REG2, ZERO, REG3, MATH_LEN_8BYTE);

	/* update no S/G jump location */
	set_jump_tgt_here(desc, no_sg_jump);

	/* seqfifostr: msgdata len=4 */
	append_seq_fifo_store(desc, FIFOST_TYPE_MESSAGE_DATA, bytes_to_copy);

	/* move: ififo->deco-alnblk -> ofifo, len */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_OUTFIFO | bytes_to_copy);

	/* Overwrite the job-desc location (word 50) with the first
	 * group (10 words)*/
	opt   = MOVE_SRC_INFIFO | MOVE_DEST_DESCBUF;
	off_w = 50;
	off_b = off_w * sizeof(uint32_t); /* calculate off in bytes */
	len   = (10 * sizeof(uint32_t)) << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math0 (input address) to words 32+33
	 * They will be used later by the load command.
	 */
	opt = MOVE_SRC_MATH0 | MOVE_DEST_DESCBUF;
	off_w = 32;
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/*
	 * Copy the context of math2 (output address) to words 56+57 or 58+59
	 * depending where the Job Descriptor starts.
	 * They will be used later by the store command.
	 */
	opt = MOVE_SRC_MATH2 | MOVE_DEST_DESCBUF | MOVE_WAITCOMP;
	off_w = 36;
	off_b = off_w * sizeof(uint32_t);
	len = ALIGNED_PTR_ADDRESS_SZ << MOVE_LEN_SHIFT;
	append_move(desc, opt | (off_b << MOVE_OFFSET_SHIFT) | len);

	/* Fix LIODN - OFFSET[0:1] - 01 = SEQ LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x40; /* SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | (off_b << LDST_OFFSET_SHIFT));

	/* Load from the input address 64 bytes into internal register */
	/* load the data to be moved - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off_b = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_load(desc, DUMMY_PTR_VAL, len, opt | off_b);

	/* Wait to finish previous operation */
	opt = JUMP_COND_CALM | (1 << JUMP_OFFSET_SHIFT);
	append_jump(desc, opt);

	/* Store the data to the output FIFO - insert dummy pointer */
	opt = LDST_CLASS_2_CCB | LDST_SRCDST_WORD_CLASS_CTX;
	off_b = 0 << LDST_OFFSET_SHIFT;
	len = move_size << LDST_LEN_SHIFT;
	append_store(desc, DUMMY_PTR_VAL, len, opt | off_b);

	/* Fix LIODN */
	opt = LDST_IMM | LDST_CLASS_DECO | LDST_SRCDST_WORD_DECOCTRL;
	off_b = 0x80 << LDST_OFFSET_SHIFT; /* NON_SEQ LIODN */
	append_cmd(desc, CMD_LOAD | opt | off_b);

	/* Copy from descriptor to MATH REG 0 the current statistics */
	stats_off_b = sa->stats_indx * CAAM_CMD_SZ;
	append_move(desc, MOVE_SRC_DESCBUF | MOVE_DEST_MATH0 | MOVE_WAITCOMP |
		    (stats_off_b << MOVE_OFFSET_SHIFT) | sizeof(uint64_t));

	/* Remove unnecessary headers
	 * MATH1 = 0 - (esp_length + iv_length + icv_length) */
	esp_length = 8; /* SPI + SEQ NUM */
	get_cipher_params(psec_as_context->alg_suite, &iv_length, &icv_length, &max_pad);
	data = (uint32_t) (esp_length + iv_length + icv_length);
	append_math_sub_imm_u64(desc, REG1, ZERO, IMM, data);

	/* MATH1 += SIL (bytes counter) */
	append_math_add(desc, REG1, SEQINLEN, REG1, MATH_LEN_8BYTE);

	/* data = outer IP header - should be read from DPOVRD register
	 * MATH 2 = outer IP header length */
	data = cpu_to_caam32(20);
	opt = LDST_CLASS_DECO | LDST_SRCDST_WORD_DECO_MATH2;
	len = sizeof(data) << LDST_LEN_SHIFT;
	append_load_as_imm(desc, &data, len, opt);

	off_w = 7;
	append_jump(desc, (off_w << JUMP_OFFSET_SHIFT));

	/* jump: all-match[] always-jump offset=0 local->[00] */
	append_jump(desc, (0 << JUMP_OFFSET_SHIFT));

	/* jump: all-match[] always-jump offset=0 local->[00] */
	append_jump(desc, (0 << JUMP_OFFSET_SHIFT));

	data = 0x00ff0000;
	append_math_and_imm_u64(desc, REG2, DPOVRD, IMM, data);

	dma_unmap_single(jrdev_g, dma_extra_cmds,
			 extra_cmds_len * sizeof(uint32_t), DMA_TO_DEVICE);

#ifdef PRINT_DESC
	cdx_ipsec_print_desc ( desc,__func__);
#endif
	return 0;
}

int  cdx_ipsec_build_in_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext psec_as_context;
//	struct iphdr *outer_ip_hdr;

	psec_as_context = sa->pSec_sa_context;
	sec_desc= psec_as_context->sec_desc; 

        sec_desc->pdb_dec.seq_num =
                cpu_to_caam32(sa->seq & SEQ_NUM_LOW_MASK);
	
	sec_desc->pdb_dec.options = PDBOPTS_ESP_TUNNEL |
                                        PDBOPTS_ESP_OUTFMT;
        if (sec_era > 4)
                sec_desc->pdb_dec.options |= PDBOPTS_ESP_AOFL;

        if ( sa->flags & SA_ALLOW_EXT_SEQ_NUM ) {
                sec_desc->pdb_dec.seq_num_ext_hi =
                        cpu_to_caam32((sa->seq & SEQ_NUM_HI_MASK) >> 32);
                sec_desc->pdb_dec.options |= PDBOPTS_ESP_ESN;
        }

        if (sa->header_len == IPV6_HDR_SIZE)
                sec_desc->pdb_dec.options |= PDBOPTS_ESP_IPVSN;
        else
                sec_desc->pdb_dec.options |= PDBOPTS_ESP_VERIFY_CSUM;

        if (sa->flags & SA_ALLOW_SEQ_ROLL  ) {
                sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARSNONE;
	}else{
		/* assuming anti reply window of 64 defult. This is not
		  known through cmm-cdx command */
                //sa->sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARS32;
                sec_desc->pdb_dec.options |= PDBOPTS_ESP_ARS64;
        }


        /*
         * Updated the offset to the point in frame were the encrypted
         * stuff starts.
         */
//        sec_desc->pdb_dec.hmo_ip_hdr_len = sa->header_len ;
	sec_desc->pdb_dec.options |= (sa->header_len << PDBHDRLEN_ESP_DECAP_SHIFT);
        if (sa->natt.sport && sa->natt.dport) {
		/* UDP nat traversal so remove the UDP header also. 
         	*/         
//       	sec_desc->pdb_dec.hmo_ip_hdr_len += UDP_HEADER_LEN;
		sec_desc->pdb_dec.options &= 0xf000ffff;
		sec_desc->pdb_dec.options |= ((sa->header_len+UDP_HEADER_LEN) << PDBHDRLEN_ESP_DECAP_SHIFT);
 
        }
        if (sa->hdr_flags) {
                if (sa->hdr_flags & SA_HDR_COPY_TOS)
		{
                 //       sec_desc->pdb_dec.hmo_ip_hdr_len |=
                  //                      PDBHMO_ESP_DIFFSERV;
			sec_desc->pdb_dec.options |=
					        (PDBHMO_ESP_DIFFSERV << PDBHDRLEN_ESP_DECAP_SHIFT);
		}
  
                if (sa->hdr_flags & SA_HDR_DEC_TTL)
		{
                 //       sec_desc->pdb_dec.hmo_ip_hdr_len |=
                   //                     PDBHMO_ESP_DECAP_DEC_TTL;
			sec_desc->pdb_dec.options |=
                                       (PDBHMO_ESP_DECAP_DEC_TTL << PDBHDRLEN_ESP_DECAP_SHIFT);
   
		}
                if (sa->hdr_flags & SA_HDR_COPY_DF)
                        pr_info("Copy DF bit not supported for inbound SAs");

        }
/*        sec_desc->pdb_dec.hmo_ip_hdr_len =
                        cpu_to_caam16(sec_desc->pdb_dec.hmo_ip_hdr_len); */
	sec_desc->pdb_dec.options = cpu_to_caam32(sec_desc->pdb_dec.options);

        return 0;
}

int  cdx_ipsec_build_out_sa_pdb(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	PDpaSecSAContext psec_as_context;
	struct iphdr *outer_ip_hdr;

	psec_as_context = sa->pSec_sa_context;
	sec_desc= psec_as_context->sec_desc; 

	//sec_desc->pdb_en.spi = cpu_to_caam32(sa->id.spi);
	sec_desc->pdb_en.spi = sa->id.spi;
        sec_desc->pdb_en.options = PDBOPTS_ESP_TUNNEL |
                                       PDBOPTS_ESP_INCIPHDR |
                                       PDBOPTS_ESP_IPHDRSRC;
        if (sa->hdr_flags) {
                if (sa->hdr_flags & SA_HDR_COPY_TOS)
			sec_desc->pdb_en.options |= PDBOPTS_ESP_DIFFSERV;
                if (sa->hdr_flags & SA_HDR_DEC_TTL)
		{
		//	sec_desc->pdb_en.hmo_rsvd |=
                  //                      PDBHMO_ESP_ENCAP_DEC_TTL;
			sec_desc->pdb_en.options |=
                                       (PDBHMO_ESP_ENCAP_DEC_TTL << PDBHMO_ESP_ENCAP_SHIFT);
 		}
                if (sa->hdr_flags & SA_HDR_COPY_DF){
			if (sa->family == PROTO_IPV4)
			{
			//	sec_desc->pdb_en.hmo_rsvd |=
                          //                              PDBHMO_ESP_DFBIT;
				sec_desc->pdb_en.options |=
                                                        (PDBHMO_ESP_DFBIT << PDBHMO_ESP_ENCAP_SHIFT);
			}
 
                        else
                                pr_warn("Copy DF not supported for IPv6 SA");
                }

        }

        if (sa->flags & SA_ALLOW_EXT_SEQ_NUM ) {
                sec_desc->pdb_en.seq_num_ext_hi =
                        cpu_to_caam32((sa->seq & SEQ_NUM_HI_MASK) >> 32);
                sec_desc->pdb_en.options |= PDBOPTS_ESP_ESN;
        }
        sec_desc->pdb_en.seq_num =
                cpu_to_caam32(sa->seq & SEQ_NUM_LOW_MASK);

        if (sa->family == PROTO_IPV6 )
                sec_desc->pdb_en.options |= PDBOPTS_ESP_IPV6;
        else
                sec_desc->pdb_en.options |= PDBOPTS_ESP_UPDATE_CSUM;

        //if (!sa->init_vector)
                sec_desc->pdb_en.options |= PDBOPTS_ESP_IVSRC;
        /*else
                memcpy(&sec_desc->pdb_en.cbc,
                       sa->init_vector->init_vector,
                       sa->.init_vector->length);*/

       /* Copy the outer header and generate the original header checksum */
        memcpy(&sec_desc->pdb_en.ip_hdr[0],
               &sa->tunnel.ip4,
               sa->header_len);

        if (sa->natt.sport && sa->natt.dport) {
                uint8_t *tmp;
                struct udphdr udp_hdr;
		udp_hdr.source = sa->natt.sport;
		udp_hdr.dest = sa->natt.dport;
                /* disable UDP checksum calculation, because for now there is
                 * no mechanism for UDP checksum update */
                udp_hdr.check = 0x0000;

                tmp = (uint8_t *) &sec_desc->pdb_en.ip_hdr[0];
                memcpy(tmp + sa->header_len,
                        &udp_hdr ,
                       UDP_HEADER_LEN);
                sec_desc->pdb_en.ip_hdr_len =
                       sa->header_len + UDP_HEADER_LEN;

                if (sa->header_len == IPV4_HDR_SIZE ) {
                        outer_ip_hdr = (struct iphdr *)
                                                &sec_desc->pdb_en.ip_hdr[0];
                        outer_ip_hdr->protocol = IPPROTO_UDP;
                } else {
                       /*
                         * this should never be reached - it should be checked
                         * before in check SA params function
                         */
                        log_err("NAT-T is not supported for IPv6 SAs\n");
                        return -EINVAL;
                }

        } else {
                sec_desc->pdb_en.ip_hdr_len = sa->header_len ;
        }
        
	/* Update endianness of this value to match SEC endianness: */
//        sec_desc->pdb_en.ip_hdr_len =
//                                cpu_to_caam16(sec_desc->pdb_en.ip_hdr_len);
        sec_desc->pdb_en.ip_hdr_len =
                               cpu_to_caam32(sec_desc->pdb_en.ip_hdr_len);

	

        if (sa->family == PROTO_IPV4) {
                outer_ip_hdr = (struct iphdr *) &sec_desc->pdb_en.ip_hdr[0];
		outer_ip_hdr->tot_len = 
//                                sec_desc->pdb_en.ip_hdr_len;
			((sec_desc->pdb_en.ip_hdr_len >> 16) & 0xffff) ;
                outer_ip_hdr->check =
                        ip_fast_csum((unsigned char *)outer_ip_hdr,
                                     outer_ip_hdr->ihl);
       		/* Only IPv4 inner packets are currently tested. */
//        	sec_desc->pdb_en.ip_nh = 0x04;
		sec_desc->pdb_en.options |= (0x04 << PDBNH_ESP_ENCAP_SHIFT);
        }
        else
	{
       		/*  IPV6 logic need to be tested */
//        	sec_desc->pdb_en.ip_nh = 41;
		sec_desc->pdb_en.options |= (0x06 << PDBNH_ESP_ENCAP_SHIFT);

	}
	sec_desc->pdb_en.options = cpu_to_caam32(sec_desc->pdb_en.options);
        return 0;
}

int  cdx_ipsec_create_shareddescriptor(PSAEntry sa)
{
	struct sec_descriptor *sec_desc;
	dma_addr_t auth_key_dma;
	dma_addr_t crypto_key_dma;
	dma_addr_t shared_desc_dma;
	int ret = 0;
	uint32_t bpid;
	uint32_t buf_size;
	PDpaSecSAContext psec_sa_context;
	
	if (cdx_dpa_get_ipsec_pool_info(&bpid, &buf_size))
		return -EIO;
	psec_sa_context = sa->pSec_sa_context;
	if(sa->direction == CDX_DPA_IPSEC_OUTBOUND ){
		 cdx_ipsec_build_out_sa_pdb( sa);
	}else{
		 cdx_ipsec_build_in_sa_pdb(sa);
	}

	/* check whether a split or a normal key is used */
	if (psec_sa_context->auth_data.split_key_len) {
#if 0
		printk("%s::split key::\n", __FUNCTION__);
		display_buff_data(psec_sa_context->auth_data.split_key, 
			psec_sa_context->auth_data.split_key_len);
#endif
		auth_key_dma = dma_map_single(jrdev_g, 
					psec_sa_context->auth_data.split_key,
				psec_sa_context->auth_data.split_key_pad_len,
					DMA_TO_DEVICE);
	} else {
#if 0
		printk("%s::auth key::\n", __FUNCTION__);
		display_buff_data(psec_sa_context->auth_data.auth_key, 
			psec_sa_context->auth_data.auth_key_len);
#endif
		auth_key_dma = dma_map_single(jrdev_g, 
				psec_sa_context->auth_data.auth_key,
				psec_sa_context->auth_data.auth_key_len,
				DMA_TO_DEVICE);
	}
	if (!auth_key_dma) {
		log_err("Could not DMA map authentication key\n");
		return -EINVAL;
	}

#if 0
	printk("%s::cipher key::\n", __FUNCTION__);
	display_buff_data(psec_sa_context->cipher_data.cipher_key, 
			psec_sa_context->cipher_data.cipher_key_len);
#endif
	crypto_key_dma = dma_map_single(jrdev_g, 
				psec_sa_context->cipher_data.cipher_key,
				psec_sa_context->cipher_data.cipher_key_len,
				DMA_TO_DEVICE);
	if (!crypto_key_dma) {
		log_err("Could not DMA map cipher key\n");
		return -EINVAL;
	}

	/*
	 * Build the shared descriptor and see if its length is less than
	 * 64 words. If build_shared_descriptor returns -EPERM than it is
	 * required to build the extended shared descriptor in order to have
	 * all the SA features that were required.
	 * Forth argument is passed was l2_hdr_size. Since we already removed 
	 * L2 header before passing to sec , I am passing zero. 
	 * This need to be revisited and corrected if required.  
	 */
	ret = cdx_ipsec_build_shared_descriptor(sa, auth_key_dma, crypto_key_dma,
				      14);
	switch (ret) {
	case 0:
		psec_sa_context->sec_desc_extended = false;
		goto done_shared_desc;
	case -EPERM:
		psec_sa_context->sec_desc_extended = true;
		goto build_extended_shared_desc;
	default:
		log_err("Failed to create SEC descriptor for SA with   spi %d\n", sa->id.spi);
		return -EFAULT;
	}

build_extended_shared_desc:
	/* Build the extended shared descriptor */
	if (sa->direction == CDX_DPA_IPSEC_INBOUND)
		ret = cdx_ipsec_build_extended_decap_shared_descriptor(sa, 
				auth_key_dma,
				crypto_key_dma, 0, 64,
				sec_era);
	else
		ret = cdx_ipsec_build_extended_encap_shared_descriptor(sa, 
				auth_key_dma,
				crypto_key_dma, 0 ,
				sec_era);
	if (ret < 0) {
		log_err("Failed to create SEC descriptor for SA with spi %d\n", 
			sa->id.spi);
		return -EFAULT;
	}

done_shared_desc:
	sec_desc = psec_sa_context->sec_desc;
	/* setup preheader */

	PREHEADER_PREP_IDLEN(sec_desc->preheader, 
				desc_len(sec_desc->shared_desc));
	PREHEADER_PREP_BPID(sec_desc->preheader, bpid);
	PREHEADER_PREP_BSIZE(sec_desc->preheader, buf_size);
	if (sa->direction  == CDX_DPA_IPSEC_INBOUND) {
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
			post_sec_in_data_off);
	}
	else
	{
		PREHEADER_PREP_OFFSET(sec_desc->preheader,
			post_sec_out_data_off);
	}
	//printk("%s::preheader %p\n", __FUNCTION__, 
	//	(void *)sec_desc->preheader);
	sec_desc->preheader = cpu_to_caam64(sec_desc->preheader);

	dma_unmap_single(jrdev_g, auth_key_dma,
			psec_sa_context->auth_data.split_key_pad_len, 
			DMA_TO_DEVICE);
	dma_unmap_single(jrdev_g, crypto_key_dma,
			psec_sa_context->cipher_data.cipher_key_len, 
			DMA_TO_DEVICE);
	shared_desc_dma = dma_map_single(jrdev_g, sec_desc,
				sizeof(struct sec_descriptor),
                                DMA_TO_DEVICE);
	dma_unmap_single(jrdev_g, shared_desc_dma, 
			sizeof(struct sec_descriptor),
			DMA_TO_DEVICE);
	return 0;
}

static void split_key_done(struct device *dev, u32 *desc, u32 err,
			   void *context)
{
	register atomic_t *done = context;
	//printk(KERN_ERR "%s: Job ring  err  value =%d\n", __func__, err);

	if (err)
		caam_jr_strstatus(dev, err);

	atomic_set(done, 1);
}

/* determine the HASH algorithm and the coresponding split key length */
int cdx_ipsec_get_split_key_info(struct auth_params *auth_param, u32 *hmac_alg)
{
	/*
	 * Sizes for MDHA pads (*not* keys): MD5, SHA1, 224, 256, 384, 512
	 * Running digest size
	 */
	const u8 mdpadlen[] = {16, 20, 32, 32, 64, 64};

	switch (auth_param->auth_type) {
	case OP_PCL_IPSEC_HMAC_MD5_96:
	case OP_PCL_IPSEC_HMAC_MD5_128:
		*hmac_alg = OP_ALG_ALGSEL_MD5;
		break;
	case OP_PCL_IPSEC_HMAC_SHA1_96:
	case OP_PCL_IPSEC_HMAC_SHA1_160:
		*hmac_alg = OP_ALG_ALGSEL_SHA1;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_256_128:
		*hmac_alg = OP_ALG_ALGSEL_SHA256;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_384_192:
		*hmac_alg = OP_ALG_ALGSEL_SHA384;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_512_256:
		*hmac_alg = OP_ALG_ALGSEL_SHA512;
		break;
	case OP_PCL_IPSEC_AES_XCBC_MAC_96:
		*hmac_alg = 0;
		auth_param->split_key_len = 0;
		break;
	default:
		log_err("Unsupported authentication algorithm\n");
		return -EINVAL;
	}

	if (*hmac_alg)
		auth_param->split_key_len =
				mdpadlen[(*hmac_alg & OP_ALG_ALGSEL_SUBMASK) >>
					 OP_ALG_ALGSEL_SHIFT] * 2;

	return 0;
}
int cdx_ipsec_generate_split_key(struct auth_params *auth_param)
{
	dma_addr_t dma_addr_in, dma_addr_out;
	u32 *desc, timeout = 1000000, alg_sel = 0;
	atomic_t done;
	int ret = 0;

	ret = cdx_ipsec_get_split_key_info(auth_param, &alg_sel);
	/* exit if error or there is no need to compute a split key */
	if (ret < 0 || alg_sel == 0)
		return ret;


	desc = kmalloc(CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2, GFP_KERNEL | GFP_DMA);
	if (!desc) {
		log_err("Allocate memory failed for split key desc\n");
		return -ENOMEM;
	}

	auth_param->split_key_pad_len = ALIGN(auth_param->split_key_len, 16);

	dma_addr_in = dma_map_single(jrdev_g, auth_param->auth_key,
				     auth_param->auth_key_len, DMA_TO_DEVICE);
	if (dma_mapping_error(jrdev_g, dma_addr_in)) {
		dev_err(jrdev_g, "Unable to DMA map the input key address\n");
		kfree(desc);
		return -ENOMEM;
	}

	dma_addr_out = dma_map_single(jrdev_g, auth_param->split_key,
				      auth_param->split_key_pad_len,
				      DMA_FROM_DEVICE);
	if (dma_mapping_error(jrdev_g, dma_addr_out)) {
		dev_err(jrdev_g, "Unable to DMA map the output key address\n");
		dma_unmap_single(jrdev_g, dma_addr_in, auth_param->auth_key_len,
				 DMA_TO_DEVICE);
		kfree(desc);
		return -ENOMEM;
	}
	init_job_desc(desc, 0);

	append_key(desc, dma_addr_in, auth_param->auth_key_len,
		   CLASS_2 | KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
//	append_operation(desc, (OP_ALG_TYPE_CLASS2 << OP_ALG_TYPE_SHIFT) |
	append_operation(desc, OP_ALG_TYPE_CLASS2 |
			 alg_sel | OP_ALG_AAI_HMAC |
			OP_ALG_DECRYPT | OP_ALG_AS_INIT);

	/* Do a FIFO_LOAD of zero, this will trigger the internal key expansion
	   into both pads inside MDHA */
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
				FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/* FIFO_STORE with the explicit split-key content store
	 * (0x26 output type) */
	append_fifo_store(desc, dma_addr_out, auth_param->split_key_len,
			  LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

#if 0//def PRINT_DESC
	cdx_ipsec_print_desc ( desc,__func__);
#endif
	atomic_set(&done, 0);
	ret = caam_jr_enqueue(jrdev_g, desc, split_key_done, &done);

	while (!atomic_read(&done) && --timeout) {
		udelay(1);
		cpu_relax();
	}

	if (timeout == 0)
		log_err("Timeout waiting for job ring to complete\n");

	dma_unmap_single(jrdev_g, dma_addr_out, auth_param->split_key_pad_len,
			 DMA_FROM_DEVICE);
	dma_unmap_single(jrdev_g, dma_addr_in, auth_param->auth_key_len,
			 DMA_TO_DEVICE);
	kfree(desc);
	return ret;
}


//insert entry in ESP class table
#ifndef USE_ENHANCED_EHASH
int  cdx_ipsec_add_classification_table_entry(PSAEntry sa)
{
	int ii;
	struct ins_entry_info *info;
	struct dpa_offload_key_info *key_info;
	uint32_t sa_dir_in=0;
	unsigned char *saddr, *daddr;
	uint32_t  itf_id = 0;
#ifdef CDX_DPA_DEBUG
	printk("%s:: direction %d\n", __FUNCTION__, sa->direction);
#endif
	if (cdx_ipsec_create_shareddescriptor(sa)) {
		DPA_ERROR("%s::unable to create shared desc\n", __FUNCTION__);
        	return FAILURE;
	}

	sa->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!sa->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n", __FUNCTION__);
		return -ENOMEM;
	}
        memset(sa->ct, 0, sizeof(struct hw_ct ));

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info) {
		DPA_ERROR("%s::unable to alloc mem for ins_info\n", __FUNCTION__);
		sa->ct = NULL;
		kfree(sa->ct);
        	return FAILURE;
	}
        memset(info, 0, sizeof(struct ins_entry_info));
        key_info = &info->key_info;
        memset(&key_info->key.key_array[0], 0, sizeof(union dpa_key));
#ifdef USE_EXACT_MATCH_TABLE
        memset(&key_info->mask.key_array[0], 0, sizeof(union dpa_key));
#endif
        memset(&key_info->mask.key_array[0], 0, sizeof(union  dpa_key));
	info->fm_idx = IPSEC_FMAN_IDX;	
	//get pcd handle based on determined fman
	info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
	if (!info->fm_pcd) {
		DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
                        	__FUNCTION__, info->fm_idx);
        	goto err_ret;
	}	
        if (sa->natt.sport && sa->natt.dport) {
		if(sa->family == PROTO_IPV4)
		{
			key_info->type = IPV4_UDP_TABLE;
			key_info->dpa_key.size = sizeof(struct ipv4_tcpudp_key);
			key_info->key.ipv4_tcpudp_key.ipv4_saddr = 
						sa->tunnel.ip4.SourceAddress;
			key_info->key.ipv4_tcpudp_key.ipv4_daddr = 
						sa->tunnel.ip4.DestinationAddress;
			key_info->key.ipv4_tcpudp_key.ipv4_protocol = IPPROTO_UDP;
			key_info->key.ipv4_tcpudp_key.ipv4_sport = sa->natt.sport;
			key_info->key.ipv4_tcpudp_key.ipv4_dport = sa->natt.dport;
		}
		else 
		{
			saddr = (unsigned char*) sa->tunnel.ip6.SourceAddress;
			daddr = (unsigned char*) sa->tunnel.ip6.DestinationAddress;
			key_info->type = IPV6_UDP_TABLE;
			key_info->dpa_key.size = sizeof(struct ipv6_tcpudp_key);
			for (ii = 0; ii < 16; ii++)
	 		     key_info->key.ipv6_tcpudp_key.ipv6_saddr[ii] = saddr[ii];
			for (ii = 0; ii < 16; ii++)
			     key_info->key.ipv6_tcpudp_key.ipv6_daddr[ii] = daddr[ii];

			key_info->key.ipv6_tcpudp_key.ipv6_protocol = IPPROTO_UDP;
			key_info->key.ipv6_tcpudp_key.ipv6_sport = sa->natt.sport;
			key_info->key.ipv6_tcpudp_key.ipv6_dport = sa->natt.dport;
		}

	}
	else
	{
		if(sa->family == PROTO_IPV4)
		{
			key_info->type = ESP_IPV4_TABLE;
			key_info->dpa_key.size = sizeof(struct ipv4_esp_key);
                	key_info->key.ipv4_esp_key.ipv4_daddr =  sa->id.daddr.a6[0];
			key_info->key.ipv4_esp_key.ipv4_protocol = IPPROTOCOL_ESP;
			key_info->key.ipv4_esp_key.spi = sa->id.spi;
		}
		else 
		{
			key_info->type = ESP_IPV6_TABLE;
			key_info->dpa_key.size = sizeof(struct ipv6_esp_key);
                	memcpy(key_info->key.ipv6_esp_key.ipv6_daddr,&sa->id.daddr,16);
			key_info->key.ipv6_esp_key.ipv6_protocol = IPPROTOCOL_ESP;
			key_info->key.ipv6_esp_key.spi = sa->id.spi;
		}
	}
   	if(sa->direction == CDX_DPA_IPSEC_INBOUND)
	{
		//inbound
       	  	/* Add the Flow to the ESP table of wan port*/ 
#ifdef CDX_DPA_DEBUG
		printk("%s::inbound sa\n", __FUNCTION__);
#endif
	       if( dpa_get_iface_info_by_ipaddress(sa->family , &sa->id.daddr.a6[0],NULL, 
					&itf_id, &info->portid, &sa->netdev) !=SUCCESS)
                {
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
				__FUNCTION__);
        		goto err_ret;
                }
		//get table descriptor based on type and port
		sa->ct->td = dpa_get_tdinfo(info->fm_idx, info->portid, 
						key_info->type);
		if (sa->ct->td  == -1) {
			DPA_ERROR("%s::unable to get td for portid  %d, type %d\n",
                        	__FUNCTION__, info->portid, 
				info->key_info.type);
        		goto err_ret;
		}
#ifdef CDX_DPA_DEBUG
                printk("%s:: Got the table id for portid %d and key type %d as %d \n", 
			__FUNCTION__, info->portid, key_info->type,sa->ct->td );
#endif
		sa_dir_in = 1;
	} else {
         	/* Add the Flow to the ESP table of sec offline port*/ 
#ifdef CDX_DPA_DEBUG
		printk("%s::outbound sa\n", __FUNCTION__);
#endif
		dpa_ipsec_ofport_td(ipsec_instance, key_info->type, &sa->ct->td ,&info->portid);
		if(!sa->pRtEntry )
		{
			DPA_ERROR("%s:: NULL ROUTE for out SA  finding outbound interface by ipaddress\n",
                        	__FUNCTION__);
	       		if( dpa_get_iface_info_by_ipaddress(sa->family ,
							((sa->family == PROTO_IPV4) ?  &sa->tunnel.ip4.SourceAddress : 
						        &sa->tunnel.ip6.SourceAddress[0]),
							&info->l2_info.fqid, &itf_id,
							NULL, NULL) !=SUCCESS)
                	{
				DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
				          __FUNCTION__);
        			goto err_ret;
                	}
   		}
                else if(dpa_get_out_tx_info_by_itf_id(sa->pRtEntry, 
				 	&info->l2_info, &info->l3_info ))
		{
			DPA_ERROR("%s:: dpa_get_out_tx_info_by_itf_id returned error\n",
                        	__FUNCTION__);
        		goto err_ret;

		}
		sa_dir_in = 0;
	}
	//get table descriptor based on type and port
	info->td = sa->ct->td;
#ifdef CDX_DPA_DEBUG
	printk("%s: Sa direction = %d Table id = %d port id = %d\n ", __func__,sa_dir_in, info->td, info->portid);
#endif
	if (info->td == -1) {
		DPA_ERROR("%s:: wrong table id passed \n",
                        	__FUNCTION__);
        	goto err_ret;
	}
#ifdef USE_EXACT_MATCH_TABLE
        memset(&key_info->mask.key_array[0], 0, 14);
	memset(&key_info->mask.key_array[14], 0xff,
                                        (key_info->dpa_key.size - 15));
        key_info->mask.key_array[(key_info->dpa_key.size -1)] =
                                0;
#endif
	//portid added to key
	key_info->key.portid = info->portid;
	key_info->dpa_key.size++;
        //set key values
        key_info->dpa_key.byte = &key_info->key.key_array[0];
#ifdef USE_EXACT_MATCH_TABLE
        key_info->dpa_key.mask = &key_info->mask.key_array[0];
#else
#ifdef USE_INTERNAL_TIMESTAMP
        key_info->dpa_key.timestamp_type = FMAN_INTERNAL_TIMESTAMP;
#else
        key_info->dpa_key.timestamp_type = EXTERNAL_TIMESTAMP_TIMERID;
#endif
#endif
#ifdef CDX_DPA_DEBUG
	printk("%s:: displaying SA table entry key\n",__func__);
	display_buf(&key_info->key.key_array[0],  key_info->dpa_key.size);
#endif
	//set actions
	memset(&info->action, 0, sizeof(struct dpa_cls_tbl_action));

	info->action.type = DPA_CLS_TBL_ACTION_ENQ;
	info->action.enable_statistics = 1;
	if(sa_dir_in)
		info->action.enq_params.new_fqid = sa->pSec_sa_context->to_sec_fqid;
	else
		info->action.enq_params.new_fqid = info->l2_info.fqid;
	info->action.enq_params.override_fqid = 1;
	sa->ct->entry_fqid =info->action.enq_params.new_fqid ;
#if 0
	printk("new fqid %x td %d\n",
		info->action.enq_params.new_fqid, info->td);
#endif
	if (create_sa_entry_hm_chain(sa->pRtEntry, info,sa_dir_in, sa->ct)) {
		printk("create_sa_entry_hm_chain return error\n");
		goto err_ret;
	}
	
	//insert entry
	sa->ct->fm_ctx = dpa_get_fm_ctx(info->fm_idx);
	if (sa->ct->fm_ctx == NULL) {
		DPA_ERROR("%s::failed to get ctx fro fm idx %d\n",
			__FUNCTION__, info->fm_idx);
		goto err_ret;
	}
	//printk("%s:;%d\n", __FUNCTION__, __LINE__);
#ifdef USE_INTERNAL_TIMESTAMP
	sa->ct->timestamp = dpa_get_fm_timestamp(entry->ct->fm_ctx);
#else
	sa->ct->timestamp = JIFFIES32;
#endif
	ii = dpa_classif_table_insert_entry(info->td, &info->key_info.dpa_key,
		 &info->action, 0, &sa->ct->dpa_handle);
	if (ii) {
		DPA_ERROR("%s::failed to insert forward entry err %d\n", 
			__FUNCTION__, ii);
        	goto err_ret;
	}
#ifdef CDX_DPA_DEBUG
	printk("%s:;%d sa direction = %d \n entry fqid = %x(%d)\n", __FUNCTION__, 
			__LINE__,sa->direction ,info->action.enq_params.new_fqid,
			info->action.enq_params.new_fqid );
	printk("%s:;%d Added entry into table =%d dpahandle = %d\n", 
			__FUNCTION__, __LINE__,info->td ,sa->ct->dpa_handle);
#endif
	kfree(info);
	return SUCCESS;
err_ret:
	if (sa->ct)
	{
		kfree(sa->ct);
		sa->ct = NULL;
	}
	//free hw flow entry if allocated
	kfree(info);
	return FAILURE;
}
#else
static int fill_ipsec_key_info(PSAEntry sa, struct en_exthash_tbl_entry *tbl_entry, 
				uint32_t port_id)
{
	union dpa_key *key;
	uint32_t key_size;
	uint32_t ii;
	uint8_t *sptr;

	key = (union dpa_key *)&tbl_entry->hashentry.key[0];
	//portid added to key
        key->portid = port_id;
	key_size = 1;
	if (sa->natt.sport && sa->natt.dport) {
       		if(sa->family == PROTO_IPV4)
                {
                        key_size += sizeof(struct ipv4_tcpudp_key);	
			
			key->ipv4_tcpudp_key.ipv4_saddr = sa->tunnel.ip4.SourceAddress;
                        key->ipv4_tcpudp_key.ipv4_daddr = sa->tunnel.ip4.DestinationAddress;
                        key->ipv4_tcpudp_key.ipv4_protocol = IPPROTO_UDP;
                        key->ipv4_tcpudp_key.ipv4_sport = sa->natt.sport;
                        key->ipv4_tcpudp_key.ipv4_dport = sa->natt.dport;
                }
                else
                {

                        key_size = sizeof(struct ipv6_tcpudp_key);
			sptr = (uint8_t *)&sa->tunnel.ip6.SourceAddress;
                        for (ii = 0; ii < 16; ii++)
                        	key->ipv6_tcpudp_key.ipv6_saddr[ii] = *(sptr + ii);
			sptr = (uint8_t *)&sa->tunnel.ip6.DestinationAddress;
                        for (ii = 0; ii < 16; ii++)
                        	key->ipv6_tcpudp_key.ipv6_daddr[ii] = *(sptr + ii);
                        key->ipv6_tcpudp_key.ipv6_protocol = IPPROTO_UDP;
                        key->ipv6_tcpudp_key.ipv6_sport = sa->natt.sport;
                        key->ipv6_tcpudp_key.ipv6_dport = sa->natt.dport;
                }
        
	} else {
	
                if(sa->family == PROTO_IPV4)
                {
                        key_size += sizeof(struct ipv4_esp_key);
                        key->ipv4_esp_key.ipv4_daddr = sa->id.daddr.a6[0];
                        key->ipv4_esp_key.ipv4_protocol = IPPROTOCOL_ESP;
                        key->ipv4_esp_key.spi = sa->id.spi;
                }
                else
                {
                        key_size += sizeof(struct ipv6_esp_key);
			sptr = (uint8_t *)&sa->id.daddr;
                        for (ii = 0; ii < 16; ii++)
                        	key->ipv6_tcpudp_key.ipv6_saddr[ii] = *(sptr + ii);
                        key->ipv6_esp_key.ipv6_protocol = IPPROTOCOL_ESP;
                        key->ipv6_esp_key.spi = sa->id.spi;
                }
        }
	return (key_size);
}


static int get_tbl_type(PSAEntry sa) 
{
	if (sa->natt.sport && sa->natt.dport) {
       		if(sa->family == PROTO_IPV4)
			return IPV4_UDP_TABLE;
		else
			return IPV6_TCP_TABLE; 
	} else {
                if(sa->family == PROTO_IPV4)
                        return ESP_IPV4_TABLE;
		else
                        return ESP_IPV6_TABLE;
	}
	return -1;
}

int  cdx_ipsec_add_classification_table_entry(PSAEntry sa)
{
	int retval;
	uint32_t flags;
	uint8_t *ptr;
	uint32_t key_size;
	int tbl_type;
	struct ins_entry_info *info;
	struct en_exthash_tbl_entry *tbl_entry;
	uint32_t sa_dir_in = 0;
	uint32_t  itf_id = 0;

#ifdef CDX_DPA_DEBUG
	printk("%s:: direction %d\n", __FUNCTION__, sa->direction);
#endif
	//create shared descriptoy
	if (cdx_ipsec_create_shareddescriptor(sa)) {
		DPA_ERROR("%s::unable to create shared desc\n", __FUNCTION__);
        	return FAILURE;
	}

	info = kzalloc(sizeof(struct ins_entry_info), 0);
	if (!info) {
		DPA_ERROR("%s::unable to alloc mem for ins_info\n", __FUNCTION__);
		//remove shared desc here??? TBD
        	return FAILURE;
	}
        memset(info, 0, sizeof(struct ins_entry_info));

	tbl_entry = NULL;
	//allocate hw ct entry
	sa->ct = (struct hw_ct *)kzalloc(sizeof(struct hw_ct), GFP_KERNEL);
	if (!sa->ct) {
		DPA_ERROR("%s::unable to alloc mem for hw_ct\n", __FUNCTION__);
                goto err_ret;
	}
        memset(sa->ct, 0, sizeof(struct hw_ct));

	//fman used for ipsec on this SOC, hardcode it for LS1043/46 as there is only one FMAN
	info->fm_idx = IPSEC_FMAN_IDX;
	//get pcd handle based on determined fman
        info->fm_pcd = dpa_get_pcdhandle(info->fm_idx);
        if (!info->fm_pcd) {
                DPA_ERROR("%s::unable to get fm_pcd_handle for fmindex %d\n",
                                __FUNCTION__, info->fm_idx);
                goto err_ret;
        }


	flags = 0;
	tbl_type = get_tbl_type(sa);
	if (tbl_type ==  -1) {
                DPA_ERROR("%s::unable to get tbl type\n",
                                __FUNCTION__);
                goto err_ret;
        }
		
	//get portand table info
   	if(sa->direction == CDX_DPA_IPSEC_INBOUND)
	{
		//inbound
       	  	/* Add the Flow to the ESP table of wan port*/ 
#ifdef CDX_DPA_DEBUG
		printk("%s::inbound sa\n", __FUNCTION__);
#endif
	       if( dpa_get_iface_info_by_ipaddress(sa->family, &sa->id.daddr.a6[0], NULL, 
				       &itf_id , &info->port_id, &sa->netdev) != SUCCESS)
                {
			DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
				__FUNCTION__);
        		goto err_ret;
                }
		//get table descriptor based on type and port
		sa->ct->td = dpa_get_tdinfo(info->fm_idx, info->port_id, 
						tbl_type);
		if (sa->ct->td == NULL) {
			DPA_ERROR("%s::unable to get td for portid %d, type %d\n",
                        	__FUNCTION__, info->port_id, tbl_type);
        		goto err_ret;
		}
#ifdef CDX_DPA_DEBUG
//       printk("%s:: Got the table id for portid %d and key type %d as %p \n", 
//			__FUNCTION__, info->port_id, key_info->type, sa->ct->td);
#endif
		sa_dir_in = 1;
	} else {
         	/* Add the Flow to the ESP table of sec offline port*/ 
#ifdef CDX_DPA_DEBUG
		printk("%s::outbound sa\n", __FUNCTION__);
#endif
		dpa_ipsec_ofport_td(ipsec_instance, tbl_type, &sa->ct->td,
				&info->port_id);
		if(!sa->pRtEntry)
		{
			DPA_ERROR("%s:: NULL ROUTE for out SA  finding outbound interface by ipaddress\n",
                        	__FUNCTION__);
	       		if (dpa_get_iface_info_by_ipaddress(sa->family,
				((sa->family == PROTO_IPV4) ?  &sa->tunnel.ip4.SourceAddress : 
						&sa->tunnel.ip6.SourceAddress[0]),
						&info->l2_info.fqid, &itf_id, 
						NULL, NULL) != SUCCESS)
                	{
				DPA_ERROR("%s:: dpa_get_iface_info_by_ipaddress returned error\n", 
				          __FUNCTION__);
        			goto err_ret;
                	}
			dpa_get_in_tx_info_by_itf_id( itf_id,
				 	&info->l2_info, &info->l3_info,NULL);
   		} else {
			if (dpa_get_out_tx_info_by_itf_id(sa->pRtEntry, 
				 	&info->l2_info, &info->l3_info)) {
				DPA_ERROR("%s:: dpa_get_out_tx_info_by_itf_id returned error\n",
                        		__FUNCTION__);
        			goto err_ret;
			}
		}
		sa_dir_in = 0;
	}
	//get table descriptor based on type and port
	info->td = sa->ct->td;
	//allocate hash table entry
        tbl_entry = ExternalHashTableAllocEntry(info->td);
        if (!tbl_entry) {
                DPA_ERROR("%s::unable to alloc hash tbl memory\n",
                                __FUNCTION__);
                goto err_ret;
        }
#ifdef CDX_DPA_DEBUG
//	printk("%s: Sa direction = %d Table id = %d port id = %d\n ", __func__,sa_dir_in, info->td, 
//		info->port_id);
#endif
	if (info->td == NULL) {
		DPA_ERROR("%s:: wrong table id passed \n",
                        	__FUNCTION__);
        	goto err_ret;
	}
	//fill key information from entry
        key_size = fill_ipsec_key_info(sa, tbl_entry, info->port_id);
        if (!key_size) {
                DPA_ERROR("%s::unable to compose key\n",
                                __FUNCTION__);
                goto err_ret;
        }

	//round off keysize to next 4 bytes boundary
        ptr = (uint8_t *)&tbl_entry->hashentry.key[0];
        ptr += ALIGN(key_size, TBLENTRY_OPC_ALIGN);
        //set start of opcode list
        info->opcptr = ptr;
        //ptr now after opcode section
        ptr += MAX_OPCODES;
	flags = 0;
#ifdef ENABLE_FLOW_TIME_STAMPS
        SET_TIMESTAMP_ENABLE(flags);
        tbl_entry->hashentry.timestamp_counter =
                cpu_to_be32(dpa_get_timestamp_addr(EXTERNAL_TIMESTAMP_TIMERID));
        sa->ct->timestamp = JIFFIES32;
#endif
#ifdef ENABLE_FLOW_STATISTICS
        SET_STATS_ENABLE(flags);
#endif
        //set offset to first opcode
        SET_OPC_OFFSET(flags, (uint32_t)(info->opcptr - (uint8_t *)tbl_entry));
        //set param offset
        SET_PARAM_OFFSET(flags, (uint32_t)(ptr - (uint8_t *)tbl_entry));
        //param_ptr now points after timestamp location
        tbl_entry->hashentry.flags = cpu_to_be16(flags);
        //param pointer and opcode pointer now valid
        info->paramptr = ptr;
        info->param_size = (MAX_EN_EHASH_ENTRY_SIZE -
                GET_PARAM_OFFSET(flags));
#ifdef CDX_DPA_DEBUG
//	printk("%s:: displaying SA table entry key\n",__func__);
//	display_buf(&key_info->key.key_array[0],  key_info->dpa_key.size);
#endif
	if(sa_dir_in) {
		//fix mtu and fqid for packets to sec
		info->l2_info.fqid = sa->pSec_sa_context->to_sec_fqid;
		info->l2_info.mtu = 0xffff;
	}
	if (fill_ipsec_actions(sa, info, sa_dir_in)) {
                DPA_ERROR("%s::unable to fill actions\n", __FUNCTION__);
                goto err_ret;
        }
	tbl_entry->enqueue_params = info->enqueue_params;
	sa->ct->handle = tbl_entry;
#ifdef CDX_DPA_DEBUG
        display_ehash_tbl_entry(&tbl_entry->hashentry, key_size);
#endif // CDX_DPA_DEBUG
        //insert entry into hash table
        retval = ExternalHashTableAddKey(info->td, key_size, tbl_entry);
        if (retval == -1) {
                DPA_ERROR("%s::unable to add entry in hash table\n", __FUNCTION__);
                goto err_ret;
        }
        sa->ct->index = (uint16_t)retval;
        kfree(info);
        return SUCCESS;
err_ret:
	if (sa->ct)
	{
		kfree(sa->ct);
		//shared descriptor to be released? TBD???
		sa->ct = NULL;
	}
	if (tbl_entry)
                ExternalHashTableEntryFree(tbl_entry);
	//free hw flow entry if allocated
	kfree(info);
	return FAILURE;
}
#endif
#endif // DPA_IPSEC_OFFLOAD
