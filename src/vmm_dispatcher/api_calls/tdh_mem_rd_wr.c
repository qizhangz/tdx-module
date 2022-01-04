// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mem_rd_wr
 * @brief TDHMEMRD and TDHMEMWR API handlers
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "auto_gen/tdvps_fields_lookup.h"

static api_error_type tdh_mem_rd_wr(uint64_t gpa, uint64_t target_tdr_pa,
                                    uint64_t data, bool_t write)
{
    tdx_module_local_t * local_data_ptr = get_local_data();

    // Temporary Variables
    uint64_t            * data_ptr = NULL;                      // Pointer to the data
    pa_t                  data_pa = {.raw = 0};                 // Physical address of the data
    pa_t                  page_gpa = {.raw = 0};                             // Target page GPA

    // TDR related variables
    pa_t                  tdr_pa;
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    // SEPT related variables
    ia32e_sept_t        * sept_entry_ptr = NULL;        // SEPT entry of the page
    ia32e_sept_t          sept_entry_copy;              // Cached SEPT entry of the page
    ept_level_t           sept_level_entry = LVL_PT;    // SEPT entry level of the page - Try 4K level
    bool_t                sept_locked_flag = false;     // Indicate SEPT is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    page_gpa.raw = gpa;

    // Initialize output registers to default values
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;
    local_data_ptr->vmm_regs.r8  = 0ULL;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the TD state
    if ((return_val = check_td_in_correct_build_state(tdr_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("TD is not in build state - error = %lld\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state. No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    if (!tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        return_val = TDX_TD_NON_DEBUG;
        TDX_ERROR("TD is a non debug!\n");
        goto EXIT;
    }

    // Verify GPA is private and aligned on 8 bytes
    if (!is_addr_aligned_pwr_of_2(page_gpa.raw, 8))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      page_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_SHARED,
                                                      &sept_entry_ptr,
                                                      &sept_level_entry,
                                                      &sept_entry_copy,
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
            !is_ept_leaf_entry(&sept_entry_copy, sept_level_entry))
    {
        // Update output register operands
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        TDX_ERROR("Failed on SEPT walk - error = %llx\n", return_val);
        goto EXIT;
    }


    // Verify the Secure EPT entry state
    if (get_sept_entry_state(&sept_entry_copy, sept_level_entry) != SEPTE_PRESENT)
    {
        // Update output register operands
        set_arch_septe_details_in_vmm_regs(sept_entry_copy, sept_level_entry, local_data_ptr);
        return_val = api_error_with_operand_id(TDX_EPT_ENTRY_NOT_PRESENT, OPERAND_ID_RCX);
        TDX_ERROR("EPT entry is not present %llx\n", return_val);
        goto EXIT;
    }

    /*---------------------------------------------------------------
          ALL_CHECKS_PASSED:  The function is guaranteed to succeed
     *---------------------------------------------------------------*/

    // Get the data HPA at 4KB resolution by inserting GPA bits 30:12 (for 1G) or 21:12 (for 2M)
    data_pa.raw = leaf_ept_entry_to_hpa(sept_entry_copy, page_gpa.raw, sept_level_entry);

    // Map and get the data pointer
    data_ptr = map_pa_with_hkid((void*)data_pa.raw, tdr_ptr->key_management_fields.hkid, write ? TDX_RANGE_RW : TDX_RANGE_RO);

    // Read the data
    local_data_ptr->vmm_regs.r8 = *data_ptr;

    // Write the data
    if (write)
    {
        *data_ptr = data;
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }

    if (sept_locked_flag)
    {
        release_sharex_lock_sh(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (sept_entry_ptr != NULL)
        {
            free_la(sept_entry_ptr);
        }
    }

    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    if (data_ptr != NULL)
    {
        free_la(data_ptr);
    }

    return return_val;
}

api_error_type tdh_mem_rd(uint64_t gpa, uint64_t target_tdr_pa)
{
    return tdh_mem_rd_wr(gpa, target_tdr_pa, 0, false);
}

api_error_type tdh_mem_wr(uint64_t gpa, uint64_t target_tdr_pa, uint64_t data)
{
    return tdh_mem_rd_wr(gpa, target_tdr_pa, data, true);
}

