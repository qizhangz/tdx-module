// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mr_extend
 * @brief TDHMREXTEND API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "crypto/sha384.h"


api_error_type tdh_mr_extend(uint64_t target_page_gpa, uint64_t target_tdr_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // GPA related variables
    pa_t                  page_gpa;                  // Target page GPA
    pa_t                  page_hpa;                  // Target page HPA (after SEPT walk)
    void                * page_ptr = NULL;           // Pointer to target page HPA (linear address)

    // SEPT related variables
    ia32e_sept_t        * page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           page_level_entry = LVL_PT; // SEPT entry level of the page
    bool_t                sept_locked_flag = false;  // Indicate SEPT is locked

    uint128_t             xmms[16];                  // SSE state backup for crypto
    sha384_128B_block_t   sha_gpa_update_block = {.block_qword_buffer = {0}};
    crypto_api_error      sha_error_code;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    page_gpa.raw = target_page_gpa;
    tdr_pa.raw = target_tdr_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the TD state
    if ((return_val = check_td_in_correct_build_state(tdr_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("TD is not in build state - error = %lld\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);
    if (tdcs_ptr->management_fields.finalized)
    {
        TDX_ERROR("TD is already finalized\n");
        return_val = TDX_TD_FINALIZED;
        goto EXIT;
    }

    // Check the page GPA is 256 Byte aligned
    if (!is_addr_aligned_pwr_of_2(page_gpa.raw, 256))
    {
        TDX_ERROR("Page GPA is not aligned to 256 Bytes\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &page_sept_entry_ptr,
                                                      &page_level_entry,
                                                      &page_sept_entry_copy,
                                                      &sept_locked_flag);

    if (return_val == api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX) ||
            return_val == api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_SEPT))
    {
        TDX_ERROR("Failed on GPA check or SEPT lock - error = %llx\n", return_val);
        goto EXIT;
    }

    /*
     * Walk failed only if it did not find a leaf entry.
     * If we did find a leaf entry, we don't care if it's at 4K, 2M or 1G level.
     **/
    if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX) &&
            !is_ept_leaf_entry(&page_sept_entry_copy, page_level_entry))
    {
        // Update output register operands
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Verify the Secure EPT entry state
    if (get_sept_entry_state(&page_sept_entry_copy, page_level_entry) != SEPTE_PRESENT)
    {
        // Update output register operands
        set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_NOT_PRESENT, OPERAND_ID_RCX);
        TDX_ERROR("EPT entry is not present %llx\n", return_val);
        goto EXIT;
    }

    // Calculate HPA at 4KB resolution from SEPT page entry by inserting GPA bits 30:12 (for 1G) or 21:12 (for 2M)
    page_hpa.raw = leaf_ept_entry_to_hpa(page_sept_entry_copy, page_gpa.raw, page_level_entry);

    // Map the page to measure
    page_ptr = map_pa_with_hkid(page_hpa.raw_void, tdr_ptr->key_management_fields.hkid, TDX_RANGE_RO);

    /**
     *  Update the TD measurements with the page's measurement using SHA384.
     *  SHA384 works on 128 Byte block sizes, therefore we process 3 blocks (= 384 Byte).
     */
    sha_gpa_update_block.api_name.bytes[0] = 'M';
    sha_gpa_update_block.api_name.bytes[1] = 'R';
    sha_gpa_update_block.api_name.bytes[2] = '.';
    sha_gpa_update_block.api_name.bytes[3] = 'E';
    sha_gpa_update_block.api_name.bytes[4] = 'X';
    sha_gpa_update_block.api_name.bytes[5] = 'T';
    sha_gpa_update_block.api_name.bytes[6] = 'E';
    sha_gpa_update_block.api_name.bytes[7] = 'N';
    sha_gpa_update_block.api_name.bytes[8] = 'D';
    sha_gpa_update_block.gpa = page_gpa.raw;

    store_xmms_in_buffer(xmms);

    if ((sha_error_code = sha384_update_128B(&(tdcs_ptr->measurement_fields.td_sha_ctx),
                                               &sha_gpa_update_block,
                                               1)) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        FATAL_ERROR();
    }
    if ((sha_error_code = sha384_update_128B(&(tdcs_ptr->measurement_fields.td_sha_ctx),
                                               (sha384_128B_block_t*)page_ptr,
                                               2)) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        FATAL_ERROR();
    }

    load_xmms_from_buffer(xmms);
    basic_memset_to_zero(xmms, sizeof(xmms));

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }
    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (page_sept_entry_ptr != NULL)
        {
            free_la(page_sept_entry_ptr);
        }
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (page_ptr != NULL)
    {
        free_la(page_ptr);
    }
    return return_val;
}
