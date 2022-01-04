// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mem_sept_add
 * @brief TDHMEMSEPTADD API handler
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


api_error_type tdh_mem_sept_add(page_info_api_input_t sept_level_and_gpa,
                           uint64_t target_tdr_pa,
                           uint64_t target_sept_page_pa)
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
    pa_t                  page_gpa;                  // Target page GPA
    page_info_api_input_t gpa_mappings = sept_level_and_gpa; // GPA and SEPT level
    ia32e_sept_t        * page_sept_entry_ptr = NULL; // SEPT entry of the page
    ia32e_sept_t          page_sept_entry_copy;       // Cached SEPT entry of the page
    ept_level_t           page_level_entry = sept_level_and_gpa.level;  // SEPT entry level of the page parent
    bool_t                sept_locked_flag = false;  // Indicate SEPT is locked

    // New SEPT EPT page variables
    pa_t                  sept_page_pa;              // Physical address of the new Secure-EPT page
    void                * sept_page_ptr;             // Pointer to the new Secure-ETP page
    pamt_block_t          sept_page_pamt_block;      // New Secure-EPT page PAMT block
    pamt_entry_t        * sept_page_pamt_entry_ptr;  // Pointer to the Secure-EPT PAMT entry
    bool_t                sept_page_locked_flag = false;   // Indicate SEPT EPT page is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    sept_page_pa.raw = target_sept_page_pa;
    page_gpa.raw = 0ULL;
    page_gpa.page_4k_num = sept_level_and_gpa.gpa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0;
    local_data_ptr->vmm_regs.rdx = 0;

    // Check, lock and map the owner TDR page (Shared lock!)
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

    // Verify mapping level input is valid
    if ((page_level_entry > tdcs_ptr->executions_ctl_fields.eptp.fields.ept_pwl) ||
        (page_level_entry < LVL_PD))
    {
        TDX_ERROR("SEPT EPT page level is not in possible range. Level = %d\n", page_level_entry);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check the page GPA is aligned to its level
    if (!is_gpa_aligned(gpa_mappings))
    {
        TDX_ERROR("Page GPA is not level (=%llx) aligned\n", gpa_mappings.level);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_EXCLUSIVE,
                                                      &page_sept_entry_ptr,
                                                      &page_level_entry,
                                                      &page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(page_sept_entry_copy, page_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Verify the parent entry located for new TD page is FREE
    if (get_sept_entry_state(&page_sept_entry_copy, page_level_entry) != SEPTE_FREE)
    {
        TDX_ERROR("SEPT entry of GPA is not free\n");
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_NOT_FREE, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check, lock and map the new SEPT EPT page
    return_val = check_lock_and_map_explicit_private_4k_hpa(sept_page_pa,
                                                            OPERAND_ID_R8,
                                                            tdr_ptr,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &sept_page_pamt_block,
                                                            &sept_page_pamt_entry_ptr,
                                                            &sept_page_locked_flag,
                                                            (void**)&sept_page_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map the new SEPT EPT page - error = %llx\n", return_val);
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Initialize the new Secure EPT page, indicating 512 entries in the
    // SEPT_FREE state, and Suppress-VE (bit 63) set,
    // using the TD’s ephemeral private HKID and direct writes(MOVDIR64B)
    fill_area_cacheline(sept_page_ptr, TDX_PAGE_SIZE_IN_BYTES, SEPTE_INIT_VALUE);

    // Update the parent EPT entry with the new TD page HPA and SEPT_PRESENT state
    map_sept_non_leaf(page_sept_entry_ptr, sept_page_pa);

    // Increment TDR child count, use an atomic operation since we have SHARED lock on TDR
    _lock_xadd_64b(&(tdr_ptr->management_fields.chldcnt), 1);

    // Update the new Secure EPT page’s PAMT entry
    sept_page_pamt_entry_ptr->pt = PT_EPT;
    set_pamt_entry_owner(sept_page_pamt_entry_ptr, tdr_pa);

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
        if (page_sept_entry_ptr != NULL)
        {
            free_la(page_sept_entry_ptr);
        }
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (sept_page_locked_flag)
    {
        pamt_unwalk(sept_page_pa, sept_page_pamt_block, sept_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(sept_page_ptr);
    }
    return return_val;
}
