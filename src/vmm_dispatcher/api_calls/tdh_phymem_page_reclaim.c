// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_phymem_page_reclaim
 * @brief TDHPHYMEMPAGERECLAIM API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"


api_error_type tdh_phymem_page_reclaim(uint64_t page_pa)
{
    // TDX Local data
    tdx_module_local_t  * local_data_ptr = get_local_data();

    // Reclaimed page related variables
    pa_t                  reclaimed_page_pa = {.raw = page_pa}; // Reclaimed page physical address
    pamt_block_t          reclaimed_page_pamt_block;            // Reclaimed page PAMT block
    pamt_entry_t        * reclaimed_page_pamt_entry_ptr;        // Pointer to the reclaimed page PAMT entry
    bool_t                reclaimed_page_pamt_locked_flag = false; // Indicate pamt is locked for this page
    page_size_t           reclaimed_page_leaf_size;
    page_size_api_input_t reclaimed_page_level = {.raw = 0};    // Output - reclaimed page level

    // TDR related variables
    pa_t                  page_owner_pa = {.raw = 0};           // Owner of this page (points to TDR if not TDR itself)
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_entry_t        * tdr_pamt_entry_ptr;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    api_error_type        return_val = UNINITIALIZE_ERROR;

    // Initialize output registers to default values
    local_data_ptr->vmm_regs.rcx = 0ULL; // Reclaimed page type (from PAMT entry)
    local_data_ptr->vmm_regs.rdx = 0ULL; // Reclaimed page owner (from PAMT entry)
    local_data_ptr->vmm_regs.r8  = 0ULL; // Reclaimed page size (from PAMT walk)
    local_data_ptr->vmm_regs.r9  = 0ULL; // Reserved
    local_data_ptr->vmm_regs.r10 = 0ULL; // Reserved
    local_data_ptr->vmm_regs.r11 = 0ULL; // Reserved

    // Check that page address is page-aligned and that its HKID is zero
    if (!is_addr_aligned_pwr_of_2(reclaimed_page_pa.raw, TDX_PAGE_SIZE_IN_BYTES) ||
        !is_pa_smaller_than_max_pa(reclaimed_page_pa.raw) ||
        (get_hkid_from_pa(reclaimed_page_pa) != 0))
    {
        TDX_ERROR("Page is not aligned or does not have zero-ed HKID bits\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Get reclaimed page PAMT block
    if (!pamt_get_block(reclaimed_page_pa, &reclaimed_page_pamt_block))
    {
        TDX_ERROR("Page PA does not comply with PAMT range rules\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_ADDR_RANGE_ERROR, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Walk and locate the leaf PAMT entry
    reclaimed_page_pamt_entry_ptr =  pamt_walk(reclaimed_page_pa,
                                               reclaimed_page_pamt_block,
                                               TDX_LOCK_EXCLUSIVE,
                                               &reclaimed_page_leaf_size,
                                               false);
    if (reclaimed_page_pamt_entry_ptr == NULL)
    {
        TDX_ERROR("Failed to PAMT walk to entry - PAMT is locked\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }
    page_owner_pa = get_pamt_entry_owner(reclaimed_page_pamt_entry_ptr);
    reclaimed_page_pamt_locked_flag = true;

    // Verify that the target page type is not NDA or reserved
    if ((reclaimed_page_pamt_entry_ptr->pt == PT_NDA) ||
        (reclaimed_page_pamt_entry_ptr->pt == PT_RSVD))
    {
        TDX_ERROR("Page to reclaim is NDA or reserved\n");
        return_val = api_error_with_operand_id(TDX_PAGE_METADATA_INCORRECT, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Update output registers
    reclaimed_page_level.level = reclaimed_page_leaf_size;
    local_data_ptr->vmm_regs.rcx = reclaimed_page_pamt_entry_ptr->pt;
    local_data_ptr->vmm_regs.rdx = page_owner_pa.raw;
    local_data_ptr->vmm_regs.r8 = reclaimed_page_level.raw;

    // Re-check page alignment if PAMT entry is larger than 4KB
    // 2MB = 4KB*(2^9) 1GB = 4KB*(2^18)
    if ((reclaimed_page_leaf_size > PT_4KB) &&
        (!is_addr_aligned_pwr_of_2(reclaimed_page_pa.raw, TDX_PAGE_SIZE_IN_BYTES << (9 * reclaimed_page_leaf_size))))
    {
        TDX_ERROR("Page is not aligned according to its PAMT level = (%d)\n", reclaimed_page_leaf_size);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Reclaimed page is not a TDR, lock and map the TDR to update params
    if (reclaimed_page_pamt_entry_ptr->pt != PT_TDR)
    {
        // Lock and map the TDR page
        return_val = lock_and_map_implicit_tdr(page_owner_pa,
                                               OPERAND_ID_TDR,
                                               TDX_RANGE_RW,
                                               TDX_LOCK_SHARED,
                                               &tdr_pamt_entry_ptr,
                                               &tdr_locked_flag,
                                               &tdr_ptr);
        if (return_val != TDX_SUCCESS)
        {
            TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
            goto EXIT;
        }

        // Verify that the TD is in teardown state
        if (tdr_ptr->management_fields.lifecycle_state != TD_TEARDOWN)
        {
            TDX_ERROR("TD life cycle state is not in teardown\n");
            return_val = TDX_LIFECYCLE_STATE_INCORRECT;
            goto EXIT;
        }

        // Atomically decrement TDR child count by the amount of reclaimed 4KB pages
        _lock_xadd_64b(&tdr_ptr->management_fields.chldcnt, -(1 << (9 * reclaimed_page_leaf_size)));
    }
    else // Reclaimed page is TDR
    {
        // Map the TDR page to read the TD state variables
        // no need to walk n' lock as we already did that for this page
        tdr_ptr = map_pa_with_global_hkid((void*)reclaimed_page_pa.raw, TDX_RANGE_RW);

        // Verify that the TD is in teardown state
        if (tdr_ptr->management_fields.lifecycle_state != TD_TEARDOWN)
        {
            TDX_ERROR("TD life cycle state is not in teardown\n");
            return_val = TDX_LIFECYCLE_STATE_INCORRECT;
            goto EXIT;
        }

        // Verify that TDR.CHLDCNT is 0
        if (tdr_ptr->management_fields.chldcnt != 0)
        {
            TDX_ERROR("Reclaiming TDR but child count is not zero = (%llu)\n",
                       tdr_ptr->management_fields.chldcnt);
            return_val = TDX_TD_ASSOCIATED_PAGES_EXIST;
            goto EXIT;
        }
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    // Update the PAMT entry of the reclaimed page to PT_FREE
    reclaimed_page_pamt_entry_ptr->pt = PT_NDA;

    return_val= TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_implicit_release_lock(tdr_pamt_entry_ptr, TDX_LOCK_SHARED);
    }
    if (tdr_ptr != NULL)
    {
        free_la(tdr_ptr);
    }
    if (reclaimed_page_pamt_locked_flag)
    {
        pamt_unwalk(reclaimed_page_pa,
                    reclaimed_page_pamt_block,
                    reclaimed_page_pamt_entry_ptr,
                    TDX_LOCK_EXCLUSIVE,
                    reclaimed_page_leaf_size);
    }

    return return_val;
}
