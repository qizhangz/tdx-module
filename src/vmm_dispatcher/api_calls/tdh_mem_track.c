// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mem_track
 * @brief TDHMEMTRACK API handler
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


api_error_type tdh_mem_track(uint64_t target_tdr_pa)
{
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    bool_t                epoch_locked_flag = false;

    api_error_type        return_val = UNINITIALIZE_ERROR;


    tdr_pa.raw = target_tdr_pa;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RO,
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

    // Map the TDCS structure
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    // Lock the TD epoch
    if (acquire_sharex_lock_ex(&tdcs_ptr->epoch_tracking.epoch_lock)
                                != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Could not lock the TD epoch\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_TD_EPOCH);
        goto EXIT;
    }
    epoch_locked_flag = true;

    // Verify that no VCPUs are associated with the previous epoch
    uint64_t td_epoch = tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch;
    uint16_t* refcount = tdcs_ptr->epoch_tracking.epoch_and_refcount.refcount;

    if (refcount[1 - (td_epoch  & 1)] != 0)
    {
        TDX_ERROR("VCPU associated with the previous epoch\n");
        return_val = TDX_PREVIOUS_TLB_EPOCH_BUSY;
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Switch to the next TD epoch.  Note that since we only have 2 REFCOUNTs,
    // the previous epoch's REFCOUNT, verified above to be 0, is now the
    // current epoch's REFCOUNT.
    tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch++;

EXIT:

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }

    if (epoch_locked_flag)
    {
        release_sharex_lock_ex(&tdcs_ptr->epoch_tracking.epoch_lock);
    }

    if(tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    return return_val;
}
