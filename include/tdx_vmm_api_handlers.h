// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_vmm_api_handelrs.h
 * @brief TDX VMM API Handelrs
 */
#ifndef __TDX_VMM_API_HANDLERS_H_INCLUDED__
#define __TDX_VMM_API_HANDLERS_H_INCLUDED__


#include "tdx_api_defs.h"


/**
 * @brief Add a 4KB private page to a TD.
 *
 * Page is mapped to the specified GPA,
 * filled with the given page image and encrypted using the TD ephemeral key,
 * and update the TD measurement with the page properties.
 *
 * @note
 *
 * @param gpa_page_info Guest physical address and level of to be mapped for the target page
 * @param tdr_pa Host physical address of the parent TDR page
 * @param target_page_pa Host physical address of the target page to be added to the TD
 * @param source_page_pa Host physical address of the source page image
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_add(page_info_api_input_t gpa_page_info,
                           uint64_t tdr_pa,
                           uint64_t target_page_pa,
                           uint64_t source_page_pa);


/**
 * @brief Add and map a 4KB Secure EPT page to a TD.
 *
 * @note
 *
 * @param sept_level_and_gpa Level and to-be-mapped GPA of the Secure EPT page
 * @param tdr_pa Host physical address of the parent TDR page
 * @param sept_page_pa Host physical address of the new Secure EPT page to be added to the TD
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_sept_add(page_info_api_input_t sept_level_and_gpa,
                           uint64_t tdr_pa,
                           uint64_t sept_page_pa);


/**
 * @brief Add a TDCX page to a TD.
 *
 * @note
 *
 * @param tdcx_pa The physical address of a page where TDCX will be added
 * @param tdr_pa The physical address of the owner TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_add_cx(uint64_t tdcx_pa, uint64_t tdr_pa);


/**
 * @brief Add a TDVPX page, as a child of a given TDVPR, to memory.
 *
 * @note
 *
 * @param tdvpx_pa The physical address of a page where the TDVPX page will be added
 * @param tdvpr_pa The physical address of a TDVPR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_addcx(uint64_t tdvpx_pa, uint64_t tdvpr_pa);


/**
 * @brief Dynamically add a 4KB private page to an initialized TD, mapped to the specified GPAs.
 *
 * @note
 *
 * @param gpa_page_info Guest physical address and level of to be mapped for the target page
 * @param tdr_pa Host physical address of the parent TDR page
 * @param target_page_pa Host physical address of the target page to be added to the TD
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_aug(page_info_api_input_t gpa_page_info,
                           uint64_t tdr_pa,
                           uint64_t target_page_pa);

/**
 * @brief Relocate a 4KB mapped page from its current host physical address to another.
 *
 * @note
 *
 * @param target_tdr_pa Host physical address of the target page to be added to the TD
 * @param tdr_pa Host physical address of the parent TDR page
 * @param source_page_pa Guest physical address of the private page to be relocated
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_relocate(uint64_t source_page_pa,
                                   uint64_t target_tdr_pa,
                                   uint64_t target_page_pa);

/**
 * @brief Block a TD private GPA range.
 *
 * Block a TD private GPA range, i.e., a Secure EPT page or a TD private page,
 * at any level (4KB, 2MB, 1GB, 512GB, 256TB etc.)
 * from creating new GPA-to-HPA address translations.
 *
 * @note
 *
 * @param page_info Level and GPA of the page to be blocked
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_range_block(page_info_api_input_t page_info, uint64_t tdr_pa);


/**
 * @brief Configure the TD ephemeral private key on a single package.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_key_config(uint64_t tdr_pa);


/**
 * @brief Create a new guest TD and its TDR root page.
 *
 * @note
 *
 * @param target_tdr_pa The physical address of a page where TDR will be created
 * @param hkid The TD’s ephemeral private HKID
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_create(uint64_t target_tdr_pa, hkid_api_input_t hkid_info);


/**
 * @brief Create a guest TD VCPU and its root TDVPR page.
 *
 * @note
 *
 * @param target_tdvpr_pa The physical address of a page where TDVPR will be added
 * @param tdr_pa The physical address of the owner TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_create(uint64_t target_tdvpr_pa, uint64_t tdr_pa);


/**
 * @brief Read a TD-scope control structure field of a debuggable TD.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 * @param field_code Field access code
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_rd(uint64_t tdr_pa, uint64_t field_code);


/**
 * @brief Read a 64b chunk from a debuggable guest TD private memory.
 *
 * @note
 *
 * @param aligned_page_pa The physical address of a naturally-aligned 64b chuck of a guest TD private page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_rd(uint64_t aligned_page_pa, uint64_t target_tdr_pa);


/**
 * @brief Write a TD-scope control structure field of a debuggable TD.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 * @param field_code Field access code
 * @param data Data to write to the field
 * @param wr_request_mask 64b write mask to indicate which bits of the value in R8 are to be written to the field
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_wr(uint64_t tdr_pa, uint64_t field_code, uint64_t data, uint64_t wr_request_mask);


/**
 * @brief Write a 64b chunk to a debuggable guest TD private memory.
 *
 * @note
 *
 * @param aligned_page_pa The physical address of a naturally-aligned 64b chuck of a guest TD private page
 * @param data Data to write to memory
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_wr(uint64_t aligned_page_pa, uint64_t target_tdr_pa, uint64_t data);


/**
 * @brief Split a large (2MB or 1GB) private TD page into 512 small (4KB or 2MB respectively) pages.
 *
 * @note
 *
 * @param page_info Level and GPA of the page to be split
 * @param tdr_pa Host physical address of the parent TDR page
 * @param sept_pa Host physical address of the new Secure EPT page to be added to the TD
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_demote(page_info_api_input_t page_info,
                              uint64_t tdr_pa,
                              uint64_t sept_pa);


/**
 * @brief Enter TDX non-root operation.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of the TD VCPU’s TDVPR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_enter(uint64_t tdvpr_pa);


/**
 * @brief Extend the MRTD measurement register in the TDCS with the measurement of the indicated chunk of a TD page.
 *
 * @note
 *
 * @param page_gpa The GPA of the TD page chunk to be measured
 * @param tdr_pa The TDR page of the target TD
 *
 * @return Success or Error type
 */
api_error_type tdh_mr_extend(uint64_t page_gpa, uint64_t tdr_pa);


/**
 * @brief Complete measurement of the initial TD contents and mark the as initialized.
 *
 * @note
 *
 * @param tdr_pa The physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mr_finalize(uint64_t tdr_pa);


/**
 * @brief Flush the address translation caches and cached TD VMCS associated with a TD VCPU,
 *        on the current logical processor.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_flush(uint64_t tdvpr_pa);


/**
 * @brief Verify that none of the TD’s VCPUs is associated with an LP.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_vpflushdone(uint64_t tdr_pa);


/**
 * @brief End the platform cache flush sequence and mark applicable HKIDs in KOT as free.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_key_freeid(uint64_t tdr_pa);


/**
 * @brief Initialize TD-scope control structures TDR and TDCS.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 * @param td_params_pa The physical address of an input TD_PARAMS struct
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_init(uint64_t tdr_pa, uint64_t td_params_pa);


/**
 * @brief Initialize the saved state of a TD VCPU.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 * @param td_vcpu_rcx Initial value of the guest TD VCPU RCX
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_init(uint64_t tdvpr_pa, uint64_t td_vcpu_rcx);


/**
 * @brief Merge 512 consecutive small (4KB or 2MB) private TD pages into one large (2MB or 1GB respectively) page.
 *
 * @note
 *
 * @param page_info Level and GPA of the page to be merged
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_promote(page_info_api_input_t page_info, uint64_t tdr_pa);


/**
 * @brief Read the metadata of a page in TDMR.
 *
 * @note
 *
 * @param tdmr_page_pa A physical address of a 4KB page in TDMR
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_page_rdmd(uint64_t tdmr_page_pa);


/**
 * @brief Read a Secure EPT entry.
 *
 * @note
 *
 * @param sept_page_info Level and GPA of SEPT entry to read
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_sept_rd(page_info_api_input_t sept_page_info, uint64_t tdr_pa);


/**
 * @brief Read a TDVPS field.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 * @param field_code  Field code
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_rd(uint64_t tdvpr_pa, td_ctrl_struct_field_code_t field_code);


/**
 * @brief Reclaim all the HKIDs assigned to a TD.
 *
 * @note
 *
 * @param tdr_pa The physical address of a TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mng_key_reclaimid(uint64_t tdr_pa);


/**
 * @brief Remove a physical 4KB, 2MB or 1GB TD-owned page
 *
 * Remove a TD private page, Secure EPT page or a control structure page from a TD.
 *
 * @note
 *
 * @param page_pa The physical address of a page to be reclaimed
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_page_reclaim(uint64_t page_pa);


/**
 * @brief Remove a GPA-mapped 4KB, 2MB or 1GB private page from a TD.
 *
 * @note
 *
 * @param page_info Level and GPA of the to-be-removed page
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_page_remove(page_info_api_input_t page_info, uint64_t tdr_pa);


/**
 * @brief Remove an empty 4KB Secure EPT page from a TD.
 *
 * @note
 *
 * @param sept_page_info Level and GPA of the to-be-removed SEPT page
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_sept_remove(page_info_api_input_t sept_page_info, uint64_t tdr_pa);


/**
 * @brief Globally configure the TDX-SEAM module.
 *
 * @note
 *
 * @param tdmr_info_array_pa The physical address of an array of TDMR_INFO entries
 * @param num_of_tdmr_entries The number of TDMR_INFO entries in the about buffer
 * @param global_private_hkid TDX-SEAM global private HKID value
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_config(uint64_t tdmr_info_array_pa,
                             uint64_t num_of_tdmr_entries,
                             hkid_api_input_t global_private_hkid);


/**
 * @brief Configure the TDX-SEAM global private key on the current package.
 *
 * @note
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_key_config(void);


/**
 * @brief Provide information about the TDX-SEAM module and the convertible memory.
 *
 * @note
 *
 * @param tdsysinfo_output_pa The physical address of a buffer where the output TDSYSINFO_STRUCT will be written
 * @param num_of_bytes_in_buffer The number of bytes in the above buffer
 * @param cmr_info_pa The physical address of a buffer where an array of CMR_INFO will be written
 * @param num_of_cmr_info_entries The number of CMR_INFO entries in the above buffer
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_info(uint64_t tdhsysinfo_output_pa,
                           uint64_t num_of_bytes_in_buffer,
                           uint64_t cmr_info_pa,
                           uint64_t num_of_cmr_info_entries);


/**
 * @brief Globally initialize the TDX-SEAM module.
 *
 * @note
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_init(sys_attributes_t tmp_sys_attributes);


/**
 * @brief Initialize the TDX-SEAM module at the current logical processor scope.
 *
 * @note
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_lp_init(void);


/**
 * @brief Partially initialize a TDX Memory Range (TDMR) and its associated PAMT.
 *
 * @note
 *
 * @param tdmr_pa The physical base address of a TDMR
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_tdmr_init(uint64_t tdmr_pa);


/**
 * @brief Initiate TDX-SEAM module shutdown and prevent further SEAMCALL on the current logical processor.
 *
 * @note Marks the TDX-SEAM module as being shut down and prevents further SEAMCALL on the current LP.
 *
 * @return Success or Error type
 */
api_error_type tdh_sys_lp_shutdown(void);


/**
 * @brief Increment the TD’s TLB epoch counter.
 *
 * @note
 *
 * @param tdr_pa The physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_track(uint64_t tdr_pa);


/**
 * @brief Remove the blocking of a TD private GPA range.
 *
 * Remove the blocking of a TD private GPA range, i.e.,
 * a Secure EPT page or a TD private page, at any level (4KB, 2MB, 1GB, 512GB, 256TB etc.)
 * previously blocked by TDHMEMRANGEBLOCK.
 *
 * @note
 *
 * @param page_info Level and GPA of page to be unblocked
 * @param tdr_pa Host physical address of the parent TDR page
 *
 * @return Success or Error type
 */
api_error_type tdh_mem_range_unblock(page_info_api_input_t page_info, uint64_t tdr_pa);


/**
 * @brief Interruptible and restartable function to write back the cache hierarchy on a package or a core.
 *
 * @note
 *
 * @param cachewb_cmd PHYMEMCACHEWB command option
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_cache_wb(uint64_t cachewb_cmd);


/**
 * @brief Write back and invalidate all cache lines associated with the specified memory page and HKID.
 *
 * @note
 *
 * @param tdmr_page_pa Physical address of a 4KB page in TDMR, including HKID bits
 *
 * @return Success or Error type
 */
api_error_type tdh_phymem_page_wbinvd(uint64_t tdmr_page_pa);

/**
 * @brief Write a TDVPS field.
 *
 * @note
 *
 * @param tdvpr_pa The physical address of a TDVPR page
 * @param field_code Field code in TDVPS
 * @param wr_data 64b data to write to the field
 * @param wr_mask 64b write mask to be applied on the write data
 *
 * @return Success or Error type
 */
api_error_type tdh_vp_wr(uint64_t tdvpr_pa,
                         td_ctrl_struct_field_code_t field_code,
                         uint64_t wr_data,
                         uint64_t wr_mask);


#endif // __TDX_VMM_API_HANDLERS_H_INCLUDED__
