// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mng_add_cx.c
 * @brief TDHMNGADDCX API handler
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
#include "accessors/data_accessors.h"
#include "accessors/ia32_accessors.h"


api_error_type tdh_mng_add_cx(uint64_t target_tdcx_pa, uint64_t target_tdr_pa)
{
    // TDCX related variables
    pa_t                  tdcx_pa;                   // TDCX physical address
    void                * tdcx_ptr;                  // Pointer to the TDCX page (linear address)
    pamt_block_t          tdcx_pamt_block;           // TDCX PAMT block
    pamt_entry_t        * tdcx_pamt_entry_ptr;       // Pointer to the TDCX PAMT entry
    bool_t                tdcx_locked_flag = false;  // Indicate TDCX is locked

    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    uint64_t              tdcx_index_num;

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdcx_pa.raw = target_tdcx_pa;
    tdr_pa.raw = target_tdr_pa;

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RDX,
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

    // Check the TD state
    if (tdr_ptr->management_fields.fatal)
    {
        TDX_ERROR("TDR state is fatal\n");
        return_val = TDX_TD_FATAL;
        goto EXIT;
    }

    if (tdr_ptr->management_fields.lifecycle_state != TD_KEYS_CONFIGURED)
    {
        TDX_ERROR("TDR key state not configured\n");
        return_val = TDX_TD_KEYS_NOT_CONFIGURED;
        goto EXIT;
    }

    if (tdr_ptr->management_fields.init)
    {
        TDX_ERROR("TDR state already initialized\n");
        return_val = TDX_TD_INITIALIZED;
        goto EXIT;
    }

    // Get the current number of TDCS pages and verify
    tdcx_index_num = (uint64_t)tdr_ptr->management_fields.num_tdcx;
    if (tdcx_index_num > (MAX_NUM_TDCS_PAGES-1))
    {
        TDX_ERROR("Number of TDCS pages (%llu) exceeds the allowed count (%d)\n", tdcx_index_num, MAX_NUM_TDCS_PAGES-1);
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    // Check, lock and map the new TDCX page
    return_val = check_lock_and_map_explicit_private_4k_hpa(tdcx_pa,
                                                            OPERAND_ID_RCX,
                                                            tdr_ptr,
                                                            TDX_RANGE_RW,
                                                            TDX_LOCK_EXCLUSIVE,
                                                            PT_NDA,
                                                            &tdcx_pamt_block,
                                                            &tdcx_pamt_entry_ptr,
                                                            &tdcx_locked_flag,
                                                            (void**)&tdcx_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDCS - error = %llx\n", return_val);
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    /**
     *  Fill the content of the TDCX page using direct writes.
     *  To save later work during TDHMNGINIT, the MSR bitmaps page is filled with
     *  all 1's, which is the default case for most MSRs.
     *  Other pages are filled with 0's.
     */

    if (tdcx_index_num == MSR_BITMAPS_PAGE_INDEX)
    {
        fill_area_cacheline(tdcx_ptr, TDX_PAGE_SIZE_IN_BYTES, (~(uint64_t)0));
    }
    else if (tdcx_index_num == SEPT_ROOT_PAGE_INDEX)
    {
        fill_area_cacheline(tdcx_ptr, TDX_PAGE_SIZE_IN_BYTES, SEPTE_INIT_VALUE);
    }
    else
    {
        zero_area_cacheline(tdcx_ptr, TDX_PAGE_SIZE_IN_BYTES);
    }

    // Register the new TDCS page in its parent TDR
    tdr_ptr->management_fields.tdcx_pa[tdcx_index_num] = tdcx_pa.raw;
    tdr_ptr->management_fields.num_tdcx = (uint32_t)(tdcx_index_num + 1);
    tdr_ptr->management_fields.chldcnt++;

    // Set the new TDCS page PAMT fields
    tdcx_pamt_entry_ptr->pt = PT_TDCX;
    set_pamt_entry_owner(tdcx_pamt_entry_ptr, tdr_pa);

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }
    if (tdcx_locked_flag)
    {
        pamt_unwalk(tdcx_pa, tdcx_pamt_block, tdcx_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdcx_ptr);
    }

    return return_val;
}
