// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mng_vpflushdone
 * @brief TDHMNGVPFLUSHDONE API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"


api_error_type tdh_mng_vpflushdone(uint64_t target_tdr_pa)
{
    // TDX Global data
    tdx_module_global_t * global_data_ptr = get_global_data();

    // TDR related variables
    pa_t                  tdr_pa = {.raw = target_tdr_pa}; // TDR physical address
    tdr_t               * tdr_ptr;                         // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;                  // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;              // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;         // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                 // Pointer to the TDCS structure (Multi-page)

    uint16_t              curr_hkid;
    bool_t                kot_locked_flag = false;         // Indicates whether KOT is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    /**
     * Check TDR (explicit access, opaque semantics, exclusive lock).
     */
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %lld\n", return_val);
        goto EXIT;
    }

    // Acquire exclusive access to KOT
    if (acquire_sharex_lock_ex(&global_data_ptr->kot.lock) != LOCK_RET_SUCCESS)
    {
        TDX_ERROR("Failed to acquire lock on KOT\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_KOT);
        goto EXIT;
    }
    kot_locked_flag = true;

    // Get the TD's ephemeral HKID
    curr_hkid = tdr_ptr->key_management_fields.hkid;

    // Verify TD life cycle state
    if ((tdr_ptr->management_fields.lifecycle_state != TD_KEYS_CONFIGURED) &&
       (tdr_ptr->management_fields.lifecycle_state != TD_HKID_ASSIGNED))
    {
        TDX_ERROR("TD in incorrect life cycle state\n");
        return_val = TDX_LIFECYCLE_STATE_INCORRECT;
        goto EXIT;
    }

    // Verify KOT entry state
    tdx_debug_assert(global_data_ptr->kot.entries[curr_hkid].state == KOT_STATE_HKID_ASSIGNED);

    /**
     * At this point no new concurrent VCPU association can be done.
     * Verify that the number of associated VCPUs is 0.
     */
    if (tdr_ptr->management_fields.init)
    {
        // Map the TDCS structure and check the state.  No need to lock
        tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RO);
        if (tdcs_ptr->management_fields.num_assoc_vcpus != 0)
        {
            TDX_ERROR("TD associated vcpus is (%d) and not zero\n",
                      tdcs_ptr->management_fields.num_assoc_vcpus);
            return_val = TDX_FLUSHVP_NOT_DONE;
            goto EXIT;
        }
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    /**
     * Create the WBINVD_BITMAP per-package.
     * Set to 1 num_of_pkgs bits from the LSB
     */
    global_data_ptr->kot.entries[curr_hkid].wbinvd_bitmap = global_data_ptr->pkg_config_bitmap;

    // Set new TD life cycle state
    tdr_ptr->management_fields.lifecycle_state = TD_BLOCKED;

    // Set the proper new KOT entry state
    global_data_ptr->kot.entries[curr_hkid].state = (uint8_t)KOT_STATE_HKID_FLUSHED;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (kot_locked_flag)
    {
        release_sharex_lock_ex(&global_data_ptr->kot.lock);
    }
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    return return_val;
}
