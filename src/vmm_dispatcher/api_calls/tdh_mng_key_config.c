// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mng_key_config
 * @brief TDHKEYCONFIG API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/mktme.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/ia32_accessors.h"


api_error_type tdh_mng_key_config(uint64_t target_tdr_pa)
{
    // global data
    tdx_module_global_t * global_data = get_global_data();

    // Local data
    tdx_module_local_t  * local_data = get_local_data();

    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;


    tdr_pa.raw = target_tdr_pa;

    // Check,lock and map the TDR page
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
        TDX_ERROR("Failed to check/lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    //Verify TDR is not in fatal state
    if (tdr_ptr->management_fields.fatal)
    {
        TDX_ERROR("TDR is in fatal state.\n");
        return_val = TDX_TD_FATAL;
        goto EXIT;
    }
    // Verify LIFECYCLE_STATE
    if (tdr_ptr->management_fields.lifecycle_state != TD_HKID_ASSIGNED)
    {
        TDX_ERROR("TDR HKID state is not assigned. lifecycle_state = %d\n", tdr_ptr->management_fields.lifecycle_state);
        return_val = TDX_LIFECYCLE_STATE_INCORRECT;
        goto EXIT;
    }

    // Check if the key is already configured
    if (tdr_ptr->key_management_fields.pkg_config_bitmap & (BIT(local_data->lp_info.pkg)))
    {
        TDX_ERROR("Key is already configured for this package\n");
        return_val = TDX_KEY_CONFIGURED;
        goto EXIT;
    }

    /** Try to configure the key on the package using a CPU-generated key.
     * This operation acquires an exclusive lock on KET (encryption engine tables)
     * and may fail if a concurrent TDHKEYCONFIG or PCONFIG is in progress.
     * Key generation may fail.
     */
    return_val = program_mktme_keys(tdr_ptr->key_management_fields.hkid);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to program MKTME keys for this TD\n");
        goto EXIT;
    }


    // ALL_CHECKS_PASSED:  The instruction is guaranteed to succeed

    // Set the configuration indication for the current package
    tdr_ptr->key_management_fields.pkg_config_bitmap |= BIT(local_data->lp_info.pkg);

    // Check whether the TD keys have been configured on all packages
    if (tdr_ptr->key_management_fields.pkg_config_bitmap == global_data->pkg_config_bitmap)
    {
        tdr_ptr->management_fields.lifecycle_state = (uint8_t)TD_KEYS_CONFIGURED;
    }

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }

    return return_val;
}
