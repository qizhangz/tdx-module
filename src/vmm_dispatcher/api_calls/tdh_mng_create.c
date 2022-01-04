// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mng_create
 * @brief TDHMNGCREATE API handler
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


api_error_type tdh_mng_create(uint64_t target_tdr_pa, hkid_api_input_t hkid_info)
{
    tdx_module_global_t * global_data = get_global_data();

    // TDR related variables
    pa_t                  tdr_pa;                   // TDR physical address
    tdr_t               * tdr_ptr;                  // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;           // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;       // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;  // Indicate TDR is locked

    uint16_t              td_hkid;
    bool_t                kot_locked_flag = false;  // Indicate KOT is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    td_hkid = hkid_info.hkid;

    // Verify HKID
    if ((hkid_info.reserved != 0) || !is_private_hkid(td_hkid))
    {
        TDX_ERROR("HKID %d is not a private HKID\n", td_hkid);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    /**
     * Check TDR (explicit access, opaque semantics, exclusive lock).
     */
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_NDA,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Acquire exclusive access to KOT
    if(acquire_sharex_lock_ex(&global_data->kot.lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on KOT\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_KOT);
        goto EXIT;
    }
    kot_locked_flag = true;

    // Protection against speculation attacks with out-of-bound td_hkid user input value
    lfence();

    // Check the provided HKID entry in KOT
    if (global_data->kot.entries[td_hkid].state != KOT_STATE_HKID_FREE)
    {
        TDX_ERROR("Given HKID %d is not free in KOT\n", td_hkid);
        return_val = TDX_HKID_NOT_FREE;
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Clear the content of the TDR page using direct writes
    zero_area_cacheline(tdr_ptr, TDX_PAGE_SIZE_IN_BYTES);

    /**
     * Initialize the TD Management and Key Management Fields.
     * Fields which are initialized to zero are implicitly zero'd in the
     * previous state.
     */
    // Mark the HKID entry in the KOT as assigned
    global_data->kot.entries[td_hkid].state = (uint8_t)KOT_STATE_HKID_ASSIGNED;

    // Set HKID in the TKT entry
    tdr_ptr->key_management_fields.hkid = td_hkid;
    tdr_ptr->management_fields.lifecycle_state = TD_HKID_ASSIGNED;

    // Set the new TDR page PAMT fields
    tdr_pamt_entry_ptr->pt = PT_TDR;
    tdr_pamt_entry_ptr->owner = 0;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (kot_locked_flag)
    {
        release_sharex_lock_ex(&global_data->kot.lock);
    }

    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }
    return return_val;
}
