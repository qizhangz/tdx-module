// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mem_page_demote
 * @brief TDHMEMPAGEDEMOTE API handler
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


api_error_type tdh_mem_page_demote(page_info_api_input_t gpa_page_info,
                              uint64_t target_tdr_pa, uint64_t target_sept_pa)
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
    pa_t                  page_gpa = {.raw = 0};            // Target page GPA
    page_info_api_input_t gpa_mappings = gpa_page_info;     // GPA and level
    ia32e_sept_t        * split_page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t          split_page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           split_page_level_entry = gpa_mappings.level; // SEPT entry level of the page
    pa_t                  split_page_pa;
    pamt_block_t          split_page_pamt_block;
    pamt_entry_t        * split_page_pamt_entry_ptr = NULL; // Pointer to the to-be-splited page PAMT entry
    bool_t                sept_locked_flag = false;         // Indicate SEPT is locked

    // New Secure-EPT page variables
    pa_t                  sept_page_pa;                // Physical address of the new SEPT page
    pamt_block_t          sept_page_pamt_block;        // SEPT page PAMT block
    pamt_entry_t        * sept_page_pamt_entry_ptr;    // Pointer to the SEPT page PAMT entry
    page_size_t           sept_page_leaf_size;
    bool_t                sept_page_locked_flag = false;   // Indicate SEPT page is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    sept_page_pa.raw = target_sept_pa;

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
    if ((gpa_mappings.level != LVL_PD) && (gpa_mappings.level != LVL_PDPT))
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
                                                      &split_page_sept_entry_ptr,
                                                      &split_page_level_entry,
                                                      &split_page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(split_page_sept_entry_copy, split_page_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Verify that the parent entry is leaf entry
    if (!is_ept_leaf_entry(&split_page_sept_entry_copy, split_page_level_entry))
    {
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_NOT_LEAF, OPERAND_ID_RCX);
        TDX_ERROR("Demoted entry is not leaf entry!\n");
        goto EXIT;
    }

    // Verify the parent entry located for new TD page is blocked (could also be pending as long as it is blocked)
    if ((get_sept_entry_state(&split_page_sept_entry_copy, split_page_level_entry) & SEPTE_BLOCKED)!= SEPTE_BLOCKED)
    {
        TDX_ERROR("SEPT entry of GPA is not blocked\n");
        return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify the TLB tacking of the blocked page has been completed
    split_page_pa.raw = leaf_ept_entry_to_hpa(split_page_sept_entry_copy, page_gpa.raw, split_page_level_entry);
    split_page_pamt_entry_ptr = pamt_implicit_get(split_page_pa, (page_size_t)split_page_level_entry);

    if (!is_tlb_tracked(tdcs_ptr, split_page_pamt_entry_ptr->bepoch))
    {
        TDX_ERROR("Target splitted page TLB tracking not done\n");
        return_val = api_error_with_operand_id(TDX_TLB_TRACKING_NOT_DONE, OPERAND_ID_RCX);
        goto EXIT;
    }

    if (((page_size_t)split_page_level_entry) == PT_2MB &&
                split_page_sept_entry_copy.fields_ps.tdp == 1)
    {
        // Clears low PA bits used for interruptible TACCEPTPAGE
        split_page_pa.raw &= MEM_MASK_2MB;
    }

    // Check and lock the new Secure-EPT page in PAMT
    return_val = check_and_lock_explicit_4k_private_hpa(sept_page_pa,
                                                         OPERAND_ID_R8,
                                                         TDX_LOCK_EXCLUSIVE,
                                                         PT_NDA,
                                                         &sept_page_pamt_block,
                                                         &sept_page_pamt_entry_ptr,
                                                         &sept_page_leaf_size,
                                                         &sept_page_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map the new SEPT page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Get PAMT block (should never fail)
    if (! pamt_get_block(split_page_pa, &split_page_pamt_block))
    {
        FATAL_ERROR();
    }

    // Split PAMT of the demoted page
    if (!pamt_demote(split_page_pa, (page_size_t)split_page_level_entry, split_page_pamt_block))
    {
        TDX_ERROR("Couldn't not split the destined page in PAMT\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }

    //---------------------------------------------------------------
    //  ALL_CHECKS_PASSED:  The function is guaranteed to succeed
    //---------------------------------------------------------------

    // Map the new Secure-EPT page
    bool_t is_pending = split_page_sept_entry_copy.fields_ps.tdp;
    bool_t suppress_ve = (is_pending? tdcs_ptr->executions_ctl_fields.attributes.sept_ve_disable : 1);
    sept_split_entry(tdr_ptr, sept_page_pa, split_page_pa, split_page_sept_entry_ptr,
                     split_page_level_entry, is_pending, suppress_ve);

    // Increment TDR child count by 1 using atomic operation.
    // Note that CHLDCNT counts the number of 4KB pages.  The change is only due
    // to the addition of the new Secure EPT page.
    _lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, 1);

    // Update the new Secure-EPT page PAMT entry
    sept_page_pamt_entry_ptr->owner = tdr_pa.page_4k_num;
    sept_page_pamt_entry_ptr->pt = PT_EPT;

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
        if (split_page_sept_entry_ptr != NULL)
        {
            free_la(split_page_sept_entry_ptr);
        }
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (sept_page_locked_flag)
    {
        pamt_unwalk(sept_page_pa, sept_page_pamt_block, sept_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
    }
    if (split_page_pamt_entry_ptr != NULL)
    {
        free_la(split_page_pamt_entry_ptr);
    }

    return return_val;
}
