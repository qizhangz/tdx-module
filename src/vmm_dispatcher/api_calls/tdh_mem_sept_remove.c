// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mem_sept_remove
 * @brief TDHMEMSEPTREMOVE API handler
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


api_error_type tdh_mem_sept_remove(page_info_api_input_t gpa_page_info, uint64_t target_tdr_pa)
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

    // GPA and SEPT related variables
    pa_t                  page_gpa = {.raw = 0};        // Target page GPA
    page_info_api_input_t gpa_mappings = gpa_page_info; // GPA and level
    ia32e_sept_t        * sept_entry_ptr = NULL;        // SEPT entry of the page
    ia32e_sept_t          sept_entry_copy;              // Cached entry of the page
    ept_level_t           sept_level_entry = gpa_mappings.level; // SEPT entry level of the page
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked

    // Removed Secure-EPT page
    pa_t                  removed_page_pa;
    pamt_entry_t        * removed_page_pamt_entry_ptr;
    ia32e_paging_table_t* removed_page_sept_page_ptr = NULL;
    bool_t                removed_page_pamt_locked_flag = false;

    api_error_type        return_val = UNINITIALIZE_ERROR;


    tdr_pa.raw = target_tdr_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_SHARED,
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
        TDX_ERROR("TD is not in build state - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    // Verify that GPA mapping input reserved fields equal zero
    if (!is_reserved_zero_in_mappings(gpa_mappings))
    {
        TDX_ERROR("Reserved fields in GPA mappings are not zero\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }
    page_gpa.page_4k_num = gpa_mappings.gpa;

    // Verify mapping level input is valid
    if ((gpa_mappings.level > tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl) ||
         gpa_mappings.level < LVL_PD)
    {
        TDX_ERROR("Input GPA level (=%d) is not valid\n", gpa_mappings.level);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check the page GPA is page aligned
    if (!is_gpa_aligned(gpa_mappings))
    {
        TDX_ERROR("Page GPA is not page aligned\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_EXCLUSIVE,
                                                      &sept_entry_ptr,
                                                      &sept_level_entry,
                                                      &sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Verify that the entry is a non-leaf entry
    if (is_ept_leaf_entry(&sept_entry_copy, sept_level_entry))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_LEAF, OPERAND_ID_RCX);
        TDX_ERROR("Entry is a leaf entry!\n");
        goto EXIT;
    }

    // Verify that the page is blocked
    if ((get_sept_entry_state(&sept_entry_copy, sept_level_entry) & SEPTE_BLOCKED) != SEPTE_BLOCKED)
    {
        TDX_ERROR("SEPT entry of GPA is not blocked\n");
        return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Get removed page HPA PAMT entry
    removed_page_pa.raw =  (sept_entry_copy.fields_4k.base << IA32E_4K_PAGE_OFFSET) | (page_gpa.raw & IA32E_4K_OFFSET);

    removed_page_pamt_entry_ptr = pamt_implicit_get_and_lock(removed_page_pa, PT_4KB, TDX_LOCK_EXCLUSIVE);

    if (removed_page_pamt_entry_ptr == NULL)
    {
        TDX_ERROR("Can't acquire lock on removed page pamt entry\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }

    removed_page_pamt_locked_flag = true;

    if (!is_tlb_tracked(tdcs_ptr, removed_page_pamt_entry_ptr->bepoch))
    {
        TDX_ERROR("Removed page TLB tracking not done\n");
        return_val = api_error_with_operand_id(TDX_TLB_TRACKING_NOT_DONE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Scan the Secure-EPT page to be removed, and verify all its entries are at
    // SEPT_FREE state.  Map the merged Secure-EPT page
    removed_page_sept_page_ptr = map_pa_with_hkid(removed_page_pa.raw_void,
                                    tdr_ptr->key_management_fields.hkid, TDX_RANGE_RO);

    for (uint32_t i = 0; i < 512; i++)
    {
        if (get_sept_entry_state(&removed_page_sept_page_ptr->sept[i], (ept_level_t)(sept_level_entry - 1))
            != SEPTE_FREE)
        {
            TDX_ERROR("SEPT entry [%d] is not FREE\n", i);
            return_val = api_error_with_operand_id(TDX_EPT_ENTRY_NOT_FREE, OPERAND_ID_RCX);
            goto EXIT;
        }
    }

    //---------------------------------------------------------------
    //  ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    //---------------------------------------------------------------

    // Atomically set the removed page Secure-EPT entry to SEPT_FREE
    sept_entry_ptr->raw = SEPTE_INIT_VALUE;

    // Decrement TDR child count by 1
    _lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, (uint64_t)-1);

    // Update the removed page PAMT entry to FREE
    removed_page_pamt_entry_ptr->pt = PT_NDA; // PT = PT_NDA, OWNER = 0
    removed_page_pamt_entry_ptr->owner = 0;
    removed_page_pamt_entry_ptr->bepoch = 0;

    // Update RCX with the removed page HPA
    local_data_ptr->vmm_regs.rcx = removed_page_pa.raw;

EXIT:

    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }
    if (sept_locked_flag)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (sept_entry_ptr != NULL)
        {
            free_la(sept_entry_ptr);
        }
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (removed_page_pamt_locked_flag)
    {
        pamt_implicit_release_lock(removed_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE);
    }
    if (removed_page_sept_page_ptr != NULL)
    {
        free_la(removed_page_sept_page_ptr);
    }

    return return_val;
}
