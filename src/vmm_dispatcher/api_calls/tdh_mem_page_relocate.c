// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mem_page_relocate.c
 * @brief TDHMEMPAGERELOCATE API handler
 */

#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "helpers/helpers.h"

api_error_type tdh_mem_page_relocate(uint64_t source_page_pa,
                                    uint64_t target_tdr_pa,
                                    uint64_t target_page_pa)
{
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // Page target
    pa_t                  target_pa;                        // Physical address of the new TD page target
    pamt_block_t          target_page_pamt_block;           // New TD page PAMT block
    pamt_entry_t        * target_page_pamt_entry_ptr = NULL;// Pointer to the TD PAMT entry
    bool_t                target_page_locked_flag = false;  // Indicate TD page is locked
    void*                 target_ptr = NULL;

    // Currently mapped page
    pa_t                  mapped_gpa = {.raw = 0};                        // mapped TD page GPA
    page_info_api_input_t gpa_mappings = {.raw = source_page_pa};                  // GPA and level
    ia32e_sept_t        * mapped_page_sept_entry_ptr = NULL;              // SEPT entry of the page
    ia32e_sept_t          mapped_page_sept_entry_copy;                    // Cached SEPT entry of the page
    ept_level_t           mapped_page_level_entry = gpa_mappings.level;   // SEPT entry level of the mapped page
    bool_t                sept_locked_flag = false;                       // Indicate SEPT is locked
    pa_t                  source_pa = {.raw = 0};
    pamt_entry_t*         mapped_page_pamt_ptr = NULL;                    // Pointer to currently mapped TD page PAMT block
    bool_t                mapped_page_locked_flag = false;                // Indicate PAMT of currently mapped TD page
    void*                 mapped_ptr = NULL;

    api_error_type        return_val = TDX_SUCCESS;

    tdr_pa.raw = target_tdr_pa;
    target_pa.raw = target_page_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;
    local_data_ptr->vmm_regs.rdx = 0ULL;

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

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    // Verify that GPA mapping input reserved fields equal zero
    if (!is_reserved_zero_in_mappings(gpa_mappings))
    {
        TDX_ERROR("Reserved fields in GPA mappings are not zero\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }
    mapped_gpa.page_4k_num = gpa_mappings.gpa;

    // Verify mapping level input is valid
    if (gpa_mappings.level != LVL_PT)
    {
        TDX_ERROR("Input GPA level (=%d) is not valid\n", gpa_mappings.level);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check the page GPA is page aligned
    if (!is_addr_aligned_pwr_of_2(mapped_gpa.raw, TDX_PAGE_SIZE_IN_BYTES))
    {
        TDX_ERROR("Page GPA is not page (=%llx) aligned\n", TDX_PAGE_SIZE_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Check GPA, lock SEPT and walk to find entry
    return_val = lock_sept_check_and_walk_private_gpa(tdcs_ptr,
                                                      OPERAND_ID_RCX,
                                                      mapped_gpa,
                                                      tdr_ptr->key_management_fields.hkid,
                                                      TDX_LOCK_EXCLUSIVE,
                                                      &mapped_page_sept_entry_ptr,
                                                      &mapped_page_level_entry,
                                                      &mapped_page_sept_entry_copy,
                                                      &sept_locked_flag);
    if (return_val != TDX_SUCCESS)
    {
        if (return_val == api_error_with_operand_id(TDX_EPT_WALK_FAILED, OPERAND_ID_RCX))
        {
            // Update output register operands
            set_arch_septe_details_in_vmm_regs(mapped_page_sept_entry_copy, mapped_page_level_entry, local_data_ptr);
        }

        TDX_ERROR("Failed on GPA check, SEPT lock or walk - error = %llx\n", return_val);
        goto EXIT;
    }

    // Verify the page entry is blocked (BLOCKED or PENDING_BLOCKED)
    if ((get_sept_entry_state(&mapped_page_sept_entry_copy, mapped_page_level_entry)& SEPTE_BLOCKED) != SEPTE_BLOCKED)
    {
        TDX_ERROR("SEPT entry of GPA is not free\n");
        return_val = api_error_with_operand_id(TDX_GPA_RANGE_NOT_BLOCKED,OPERAND_ID_RCX);
        goto EXIT;
    }

    // Get currently mapped page HPA
    source_pa.raw = leaf_ept_entry_to_hpa(mapped_page_sept_entry_copy, mapped_gpa.raw, mapped_page_level_entry);

    // Verify mapped HPA is different than target HPA
    if (source_pa.full_pa == target_pa.full_pa)
    {
        return_val =  api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_R8);
        goto EXIT;
    }

    // Verify the TLB tacking of the blocked page has been completed
    mapped_page_pamt_ptr = pamt_implicit_get_and_lock(source_pa, (page_size_t)mapped_page_level_entry, TDX_LOCK_EXCLUSIVE);

    if (mapped_page_pamt_ptr == NULL)
    {
        TDX_ERROR("Can't acquire lock on mapped page pamt entry\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }

    mapped_page_locked_flag = true;

    if (!is_tlb_tracked(tdcs_ptr, mapped_page_pamt_ptr->bepoch))
    {
        return_val =  api_error_with_operand_id(TDX_TLB_TRACKING_NOT_DONE, OPERAND_ID_SEPT);
        goto EXIT;
    }


   // Check, lock and map the new TD page
    return_val = check_lock_and_map_explicit_private_4k_hpa(target_pa,
                                                           OPERAND_ID_R8,
                                                           tdr_ptr,
                                                           TDX_RANGE_RW,
                                                           TDX_LOCK_EXCLUSIVE,
                                                           PT_NDA,
                                                           &target_page_pamt_block,
                                                           &target_page_pamt_entry_ptr,
                                                           &target_page_locked_flag,
                                                           (void**)&target_ptr);
   if (return_val != TDX_SUCCESS)
   {
       TDX_ERROR("Failed to check/lock/map the new TD page - error = %llx\n", return_val);
       goto EXIT;
   }

   if (get_sept_entry_state(&mapped_page_sept_entry_copy, mapped_page_level_entry) == SEPTE_BLOCKED)
    {
        // Copy the current mapped page content to the target page, using the TDs
       // ephemeral private HKID and direct writes(MOVDIR64B)
       mapped_ptr = map_pa_with_hkid(source_pa.raw_void,
                                     tdr_ptr->key_management_fields.hkid, TDX_RANGE_RO);
       cache_aligned_copy_direct((uint64_t)mapped_ptr, (uint64_t)target_ptr, TDX_PAGE_SIZE_IN_BYTES);
    }

   // Free the currently mapped HPA by setting its PAMT to PT_NDA
   mapped_page_pamt_ptr->pt = PT_NDA;

   // Update the target pages PAMT entry with the PT_REG page
   // type and the TDR physical address as the OWNER
   target_page_pamt_entry_ptr->pt = PT_REG;
   target_page_pamt_entry_ptr->owner = tdr_pa.page_4k_num;

   // Update the Secure EPT entry with the target page
   // HPA and SEPT_PRESENT state
   ia32e_sept_t epte_val = {.raw = mapped_page_sept_entry_copy.raw};
   epte_val.fields_ps.tdb = 0;
   epte_val.fields_4k.base = target_pa.full_pa >> 12;
   if (epte_val.fields_ps.tdp)
   {
       epte_val.fields_4k.supp_ve = tdcs_ptr->executions_ctl_fields.attributes.sept_ve_disable;
   }
   else
   {
       epte_val.present.rwx = 0x7;
   }

   // Write the whole 64-bit EPT entry in a single operation
   mapped_page_sept_entry_ptr->raw = epte_val.raw;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }
    if (sept_locked_flag)
    {
        release_sharex_lock_ex(&tdcs_ptr->executions_ctl_fields.secure_ept_lock);
        if (mapped_page_sept_entry_ptr != NULL)
        {
            free_la(mapped_page_sept_entry_ptr);
        }
    }
    if (mapped_ptr != NULL)
    {
        free_la(mapped_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if(target_page_locked_flag)
    {
        pamt_unwalk(target_pa, target_page_pamt_block, target_page_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(target_ptr);
    }
    if (mapped_page_locked_flag)
    {
        pamt_implicit_release_lock(mapped_page_pamt_ptr, TDX_LOCK_EXCLUSIVE);
    }

    return return_val;
}
