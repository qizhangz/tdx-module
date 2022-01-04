// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_vp_flush
 * @brief TDHVPFLUSH API handler
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
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"


api_error_type tdh_vp_flush(uint64_t target_tdvpr_pa)
{
    // TDX Local data
    tdx_module_local_t  * local_data_ptr = get_local_data();

    // TDVPS related variables
    pa_t                  tdvpr_pa = {.raw = target_tdvpr_pa};  // TDVPR physical address
    tdvps_t             * tdvps_ptr = NULL;                     // Pointer to the TDVPS structure ((Multi-page linear address)
    pamt_block_t          tdvpr_pamt_block;                     // TDVPR PAMT block
    pamt_entry_t        * tdvpr_pamt_entry_ptr;                 // Pointer to the TDVPR PAMT entry
    bool_t                tdvpr_locked_flag = false;            // Indicate TDVPR is locked
    page_size_t           tdvpr_leaf_size = PT_4KB;

    // TDR related variables
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    uint16_t              curr_hkid;

    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Check and lock the parent TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RCX,
                                                         TDX_LOCK_EXCLUSIVE,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_block,
                                                         &tdvpr_pamt_entry_ptr,
                                                         &tdvpr_leaf_size,
                                                         &tdvpr_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock a TDVPR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Lock and map the TDR page
    return_val = lock_and_map_implicit_tdr(get_pamt_entry_owner(tdvpr_pamt_entry_ptr),
                                           OPERAND_ID_TDR,
                                           TDX_RANGE_RO,
                                           TDX_LOCK_SHARED,
                                           &tdr_pamt_entry_ptr,
                                           &tdr_locked_flag,
                                           &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the TD's key state
    if (tdr_ptr->management_fields.lifecycle_state != TD_KEYS_CONFIGURED)
    {
        TDX_ERROR("TD in incorrect life cycle state\n");
        return_val = TDX_TD_KEYS_NOT_CONFIGURED;
        goto EXIT;
    }

    // Get the TD's ephemeral HKID
    curr_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the multi-page TDVPS structure
    tdvps_ptr = map_tdvps(tdvpr_pa, curr_hkid, TDX_RANGE_RW);

    if (tdvps_ptr == NULL)
    {
        TDX_ERROR("TDVPS mapping failed\n");
        return_val = TDX_TDVPX_NUM_INCORRECT;
        goto EXIT;
    }

    // Check if this VCPU is associated with the current LP
    if (tdvps_ptr->management.assoc_lpid != local_data_ptr->lp_info.lp_id)
    {
        TDX_ERROR("TD VCPU not associated - LPID = %d\n", local_data_ptr->lp_info.lp_id);
        return_val = TDX_VCPU_NOT_ASSOCIATED;
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    /**
     *  Flush the TLB context and extended paging structure (EPxE) caches associated
     *  with the current TD
     */
    ept_descriptor_t ept_desc = {.ept = tdcs_ptr->executions_ctl_fields.eptp.raw, .reserved = 0};
    ia32_invept(&ept_desc, INVEPT_TYPE_1);

    // Flush the cached TD VMCS content to TDVPS using VMCLEAR
    pa_t vmcs_pa = set_hkid_to_pa((pa_t)tdvps_ptr->management.tdvps_pa[TDVPS_VMCS_PAGE_INDEX], curr_hkid);

    ia32_vmclear((void*)vmcs_pa.raw);

    // Mark the guest TD as not launched.  Next VM entry will require VMLAUNCH
    tdvps_ptr->management.launched = false;

    // Mark the VCPU as not associated with any LP
    tdvps_ptr->management.assoc_lpid = (uint32_t)-1;

    // Atomically decrement the associated VCPUs counter.
    _lock_xadd_32b(&(tdcs_ptr->management_fields.num_assoc_vcpus), (uint32_t)-1);

    // Make sure the current VCPU is not marked as the last one that ran on this LP
    local_data_ptr->vp_ctx.last_tdvpr_pa.raw = NULL_PA;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
        free_la(tdr_ptr);
    }
    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    return return_val;
}
