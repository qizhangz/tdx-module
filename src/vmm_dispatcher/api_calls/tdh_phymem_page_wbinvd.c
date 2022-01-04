// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_phymem_page_wbinvd
 * @brief TDHPHYMEMPAGEWBINVD API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"


api_error_type tdh_phymem_page_wbinvd(uint64_t tdmr_page_pa)
{
    // Page to WBINVD variables
    pa_t                  page_wbinvd_pa = {.raw = tdmr_page_pa}; // Physical address of the page to be wbinvd
    void                * page_wbinvd_ptr = NULL;                 // Pointer to linear address of page
    pamt_block_t          page_wbinvd_pamt_block;                 // Page PAMT block
    pamt_entry_t        * page_wbinvd_pamt_entry_ptr = NULL;      // Pointer to the page PAMT entry
    bool_t                page_wbinvd_locked_flag = false;        // Indicate PAMT of page is locked
    page_size_t           page_wbinvd_leaf_size;                  // Page size
    uint16_t              curr_hkid;                              // HKID taken from the page physical address

    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Get HKID from PA and remove it for the checks
    curr_hkid = get_hkid_from_pa(page_wbinvd_pa);
    page_wbinvd_pa.raw &= ~(get_global_data()->hkid_mask);

    // Check and lock the page
    return_val = check_and_lock_explicit_4k_private_hpa(page_wbinvd_pa,
                                                         OPERAND_ID_RCX,
                                                         TDX_LOCK_SHARED,
                                                         PT_NDA,
                                                         &page_wbinvd_pamt_block,
                                                         &page_wbinvd_pamt_entry_ptr,
                                                         &page_wbinvd_leaf_size,
                                                         &page_wbinvd_locked_flag);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock the given TDMR physical address - error = %lld\n", return_val);
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The instruction is guaranteed to succeed

    // Map the page to get a linear address pointer
    page_wbinvd_ptr = map_pa_with_hkid(page_wbinvd_pa.raw_void, curr_hkid, TDX_RANGE_RO);

    // Perform write back and invalidate on all the page’s cache lines
    invalidate_cache_lines((uint64_t)page_wbinvd_ptr, TDX_PAGE_SIZE_IN_BYTES);

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (page_wbinvd_locked_flag)
    {
        pamt_unwalk(page_wbinvd_pa,
                    page_wbinvd_pamt_block,
                    page_wbinvd_pamt_entry_ptr,
                    TDX_LOCK_SHARED,
                    page_wbinvd_leaf_size);
        if (page_wbinvd_ptr != NULL)
        {
            free_la(page_wbinvd_ptr);
        }
    }
    return return_val;
}
