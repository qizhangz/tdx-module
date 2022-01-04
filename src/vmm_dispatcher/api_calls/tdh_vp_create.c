// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_vp_create.c
 * @brief TDHVPCREATE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/ia32_accessors.h"


api_error_type tdh_vp_create(uint64_t target_tdvpr_pa, uint64_t target_tdr_pa)
{
    // TDVPS related variables
    pa_t                  tdvpr_pa;                  // TDVPR physical address
    tdvps_t             * tdvps_ptr;                 // Pointer to the TDVPS (multi-page linear address)
    pamt_block_t          tdvpr_pamt_block;          // TDVPR PAMT block
    pamt_entry_t        * tdvpr_pamt_entry_ptr;      // Pointer to the TDVPR PAMT entry
    bool_t                tdvpr_locked_flag = false; // Indicate TDVPR is locked

    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS page (linear address)

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdvpr_pa.raw = target_tdvpr_pa;
    tdr_pa.raw = target_tdr_pa;

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

    // Map the TDCS structure and check the state. No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RO);

    if (tdcs_ptr->management_fields.finalized)
    {
        TDX_ERROR("TD is already finalized\n");
        return_val = TDX_TD_FINALIZED;
        goto EXIT;
    }

    // Check, lock and map the new TDVPR page
    return_val = check_lock_and_map_explicit_private_4k_hpa(tdvpr_pa,
                                                            OPERAND_ID_RCX,
                                                            tdr_ptr,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &tdvpr_pamt_block,
                                                            &tdvpr_pamt_entry_ptr,
                                                            &tdvpr_locked_flag,
                                                            (void**)&tdvps_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDVPR - error = 0x%llx\n", return_val);
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Clear the content of the TDVPR page using direct writes
    zero_area_cacheline(tdvps_ptr, TDX_PAGE_SIZE_IN_BYTES);

    /**
     * Initialize TDVPS management fields.
     * Fields which are initialized to zero are implicitly zero'd in the
     * previous state.
     */
    tdvps_ptr->management.assoc_lpid = (uint32_t)-1;
    tdvps_ptr->management.tdvps_pa[0] = tdvpr_pa.raw;

    // Register the new TDVPR page in its owner TDR
    _lock_xadd_64b(&(tdr_ptr->management_fields.chldcnt), 1);

    // Set the new TDVPR page PAMT fields
    tdvpr_pamt_entry_ptr->pt = PT_TDVPR;
    set_pamt_entry_owner(tdvpr_pamt_entry_ptr, tdr_pa);

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdvps_ptr);
    }
    return return_val;
}


