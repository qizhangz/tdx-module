// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_vp_addcx.c
 * @brief TDHVPADDCX API handler
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


api_error_type tdh_vp_addcx(uint64_t target_tdvpx_pa, uint64_t target_tdvpr_pa)
{
    // TDVPX related variables
    pa_t                  tdvpx_pa;                  // TDVPX physical address
    void                * tdvpx_ptr;                 // Pointer to the TDVPX page (linear address)
    pamt_block_t          tdvpx_pamt_block;          // TDVPX PAMT block
    pamt_entry_t        * tdvpx_pamt_entry_ptr;      // Pointer to the TDVPX PAMT entry
    bool_t                tdvpx_locked_flag = false; // Indicate TDVPX is locked

    // TDVPS related variables
    pa_t                  tdvpr_pa;                  // TDVPR physical address
    tdvps_t             * tdvps_ptr = NULL;          // Pointer to the TDVPS (multi-page linear address)
    pamt_block_t          tdvpr_pamt_block;          // TDVPR PAMT block
    pamt_entry_t        * tdvpr_pamt_entry_ptr;      // Pointer to the TDVPR PAMT entry
    bool_t                tdvpr_locked_flag = false; // Indicate TDVPR is locked

    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDVPR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS page (linear address)

    uint64_t              tdvpx_index_num;
    uint16_t              td_hkid;
    page_size_t           page_leaf_size = PT_4KB;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdvpx_pa.raw = target_tdvpx_pa;
    tdvpr_pa.raw = target_tdvpr_pa;

    // Check and lock the parent TDVPR page
    return_val = check_and_lock_explicit_4k_private_hpa(tdvpr_pa,
                                                         OPERAND_ID_RDX,
                                                         TDX_LOCK_EXCLUSIVE,
                                                         PT_TDVPR,
                                                         &tdvpr_pamt_block,
                                                         &tdvpr_pamt_entry_ptr,
                                                         &page_leaf_size,
                                                         &tdvpr_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock a TDVPR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Get and lock the owner TDR page
    tdr_pa = get_pamt_entry_owner(tdvpr_pamt_entry_ptr);
    return_val = lock_and_map_implicit_tdr(tdr_pa,
                                           OPERAND_ID_TDR,
                                           TDX_RANGE_RW,
                                           TDX_LOCK_SHARED,
                                           &tdr_pamt_entry_ptr,
                                           &tdr_locked_flag,
                                           &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the TD state
    if ((return_val = check_td_in_correct_build_state(tdr_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("TD is not in build state - error = %llx\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RO);
    if (tdcs_ptr->management_fields.finalized)
    {
        TDX_ERROR("TD is already finalized\n");
        return_val = TDX_TD_FINALIZED;
        goto EXIT;
    }

    // Get the TD's ephemeral HKID
    td_hkid = tdr_ptr->key_management_fields.hkid;

    // Map the TDVPS structure.  Note that only the 1st page (TDVPR) is
    // accessible at this point.
    tdvps_ptr = (tdvps_t*)map_pa((void*)(set_hkid_to_pa(tdvpr_pa, td_hkid).full_pa), TDX_RANGE_RW);

    // Check the VCPU state
    if (tdvps_ptr->management.state != VCPU_UNINITIALIZED)
    {
        TDX_ERROR("TD VCPU is already initialized\n");
        return_val = TDX_VCPU_STATE_INCORRECT;
        goto EXIT;
    }

    // Get the current number of TDVPX pages and verify
    tdvpx_index_num = tdvps_ptr->management.num_tdvpx;
    if (tdvpx_index_num >= (MAX_TDVPS_PAGES - 1))
    {
        TDX_ERROR("Number of TDVPX pages (%llu) exceeds the allowed count (%d)\n", tdvpx_index_num, MAX_TDVPS_PAGES-1);
        return_val = TDX_TDVPX_NUM_INCORRECT;
        goto EXIT;
    }

    // Check, lock and map the new TDVPX page
    return_val = check_lock_and_map_explicit_private_4k_hpa(tdvpx_pa,
                                                            OPERAND_ID_RCX,
                                                            tdr_ptr,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &tdvpx_pamt_block,
                                                            &tdvpx_pamt_entry_ptr,
                                                            &tdvpx_locked_flag,
                                                            (void**)&tdvpx_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDVPX - error = %lld\n", return_val);
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Clear the content of the TDVPX page using direct writes
    zero_area_cacheline(tdvpx_ptr, TDX_PAGE_SIZE_IN_BYTES);

    // Register the new TDVPX in its parent TDVPS structure
    // Note that tdvpx_pa[0] is the PA of TDVPR, so TDVPX
    // pages start from index 1
    tdvpx_index_num++;
    tdvps_ptr->management.num_tdvpx = (uint8_t)tdvpx_index_num;
    tdvps_ptr->management.tdvps_pa[tdvpx_index_num] = tdvpx_pa.raw;

    // Register the new TDVPX page in its owner TDR
    _lock_xadd_64b(&(tdr_ptr->management_fields.chldcnt), 1);

    // Set the new TDVPX page PAMT fields
    tdvpx_pamt_entry_ptr->pt = PT_TDVPX;
    set_pamt_entry_owner(tdvpx_pamt_entry_ptr, tdr_pa);


EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (tdvpr_locked_flag)
    {
        pamt_unwalk(tdvpr_pa, tdvpr_pamt_block, tdvpr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        if (tdvps_ptr != NULL)
        {
            free_la(tdvps_ptr);
        }
    }
    if (tdvpx_locked_flag)
    {
        pamt_unwalk(tdvpx_pa, tdvpx_pamt_block, tdvpx_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdvpx_ptr);
    }
    return return_val;
}
