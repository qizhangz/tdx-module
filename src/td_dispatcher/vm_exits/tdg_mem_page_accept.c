// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_mem_page_accept.c
 * @brief TDGMEMPAGEACCEPT API handler
 */
#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "accessors/ia32_accessors.h"
#include "memory_handlers/sept_manager.h"
#include "x86_defs/x86_defs.h"
#include "accessors/ia32_accessors.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"

static void tdaccept_ept_violation_exit(pa_t gpa, ept_level_t req_level, sept_entry_state sept_state,
                                        bool_t is_leaf, ept_level_t ept_level, ia32e_sept_t* sept_entry_ptr)
{
    vmx_ext_exit_qual_t eeq = { .raw = 0 };
    tdaccept_vmx_eeq_info_t eeq_info = { .raw = 0 };

    eeq_info.req_sept_level = req_level;
    eeq_info.err_sept_level = ept_level;
    eeq_info.err_sept_state = sept_state;
    eeq_info.err_sept_is_leaf = is_leaf;

    eeq.type = VMX_EEQ_ACCEPT;
    eeq.info = eeq_info.raw;

    if (sept_entry_ptr != NULL)
    {
        free_la(sept_entry_ptr);
    }

    vm_vmexit_exit_reason_t vm_exit_reason = { .raw = 0 };
    vm_exit_reason.basic_reason = VMEXIT_REASON_EPT_VIOLATION;

    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, 0, eeq.raw);
}

typedef enum tdaccept_failure_type_e
{
    TDACCEPT_SUCCESS           = 0,
    TDACCEPT_ALREADY_ACCEPTED  = 1,
    TDACCEPT_SIZE_MISMATCH     = 2,
    TDACCEPT_VIOLATION         = 3
} tdaccept_failure_type_t;

static tdaccept_failure_type_t check_tdaccept_failure(bool_t walk_failed, bool_t is_leaf,
                                                      sept_entry_state sept_state)
{
    // SEPT walk fails only when reached level is smaller than requested level
    // i.e. (ept_level > req_accept_level)
    // Because when (ept_level == req_accept_level) - it means walk success
    // And (ept_level < req_accept_level) is impossible, because SEPT walk will break at requested level

    IF_RARE (walk_failed)
    {
        if (is_leaf)
        {
            // Walk failed and terminated due to a PRESENT *leaf* entry > requested ACCEPT size
            // (e.g. 2 MB PTE present for a 4 KB request).
            if (sept_state == SEPTE_PRESENT)
            {
                TDX_WARN("PRESENT *leaf* entry > requested ACCEPT size\n");
                return TDACCEPT_ALREADY_ACCEPTED;
            }
            // Walk failed and terminated due to a BLOCKED, PENDING or PENDING_BLOCKED
            // *leaf* entry > requested ACCEPT size (e.g. 2 MB PTE PENDING leaf for a 4 KB request).
            else if (sept_state == SEPTE_BLOCKED || sept_state == SEPTE_PENDING ||
                     sept_state == SEPTE_PENDING_BLOCKED)
            {
                TDX_WARN("NON-PRESENT *leaf* entry > requested ACCEPT size\n");
                return TDACCEPT_VIOLATION;
            }
            else
            {
                FATAL_ERROR();
            }
        }

        // Walk failed: intermediate paging structure missing at size > requested ACCEPT size
        // (e.g.  missing PDE for a 4 KB request).
        else // (!is_leaf)
        {
            TDX_WARN("Failure due to intermediate paging structure missing\n");
            return TDACCEPT_VIOLATION;
        }
    }
    else // SEPT walk did not fail - i.e. reached the requested level
    {
        IF_RARE ((sept_state != SEPTE_FREE) && !is_leaf)
        {
            // Non-free non-leaf entry == requested ACCEPT size
            // (i.e. requested 2M entry is mapped to a EPT page instead of being a leaf)
            TDX_WARN("Non-free non-leaf entry < requested ACCEPT size\n");
            return TDACCEPT_SIZE_MISMATCH;
        }
        else
        {
            // Secure EPT walk terminated with leaf entry == requested ACCEPT size.
            // Entry state is PRESENT
            if (sept_state == SEPTE_PRESENT)
            {
                TDX_WARN("PRESENT leaf entry at level == requested ACCEPT size\n");
                return TDACCEPT_ALREADY_ACCEPTED;
            }

            // Secure EPT walk terminated with leaf entry == requested ACCEPT size.
            // Entry state is BLOCKED or PENDING_BLOCKED or FREE (leaf)
            if (sept_state != SEPTE_PENDING)
            {
                TDX_WARN("BLOCKED, PENDING_BLOCKED or FREE leaf entry at level == requested ACCEPT size\n");
                return TDACCEPT_VIOLATION;
            }

            // Success in the last case (sept_state == SEPTE_PENDING)
        }
    }

    return TDACCEPT_SUCCESS;
}

static bool_t update_sept_entry(ia32e_sept_t* sept_entry_ptr, ia32e_sept_t sept_entry_expected,
                                ia32e_sept_t new_sept_entry)
{
    ia32e_sept_t prev_sept_entry;
    /* Try to update the SEPT entry */
    prev_sept_entry.raw =  _lock_cmpxchg_64b(sept_entry_expected.raw,
                                             new_sept_entry.raw,
                                             &sept_entry_ptr->raw);

    if (prev_sept_entry.raw != sept_entry_expected.raw)
    {
        // Release SEPT entry guest exclusive lock
        _lock_btr_64b(&sept_entry_ptr->raw, SEPT_ENTRY_TDGL_BIT_POSITION);
        return false;
    }

    return true;
}

static void init_sept_4k_page(tdr_t* tdr_p, ia32e_sept_t sept_entry)
{
    uint64_t page_to_accept_hpa = sept_entry.raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    void* page_to_accept_la = map_pa_with_hkid((void*)page_to_accept_hpa, tdr_p->key_management_fields.hkid, TDX_RANGE_RW);

    // Initialize the 4KB page
    zero_area_cacheline(page_to_accept_la, TDX_PAGE_SIZE_IN_BYTES);

    free_la(page_to_accept_la);
}

api_error_type tdg_mem_page_accept(uint64_t page_to_accept_gpa, bool_t* interrupt_occurred)
{
    api_error_type return_val = TDX_OPERAND_INVALID;
    // Local data
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdr_t* current_tdr = tdx_local_data_ptr->vp_ctx.tdr;

    page_info_api_input_t gpa_mappings = {.raw = page_to_accept_gpa}; // GPA and level
    ia32e_sept_t* sept_entry_ptr = NULL;
    ia32e_sept_t  sept_entry_copy;
    ept_level_t   req_accept_level = gpa_mappings.level;    // SEPT entry level of the page

    pa_t page_gpa = {.raw = 0}; // Target page GPA
    page_gpa.page_4k_num = gpa_mappings.gpa;

    /**
     * Memory operand checks
     */
    // Verify that GPA mapping input reserved fields equal zero
    if (!is_reserved_zero_in_mappings(gpa_mappings))
    {
        TDX_ERROR("Reserved fields in GPA mappings are not zero\n");
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify mapping level input is valid (4KB or 2MB)
    if (req_accept_level > LVL_PD)
    {
        TDX_ERROR("Input GPA level (=%d) is not valid\n", gpa_mappings.level);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Verify GPA is aligned
    if (!is_gpa_aligned(gpa_mappings))
    {
        TDX_ERROR("Page to accept GPA (=%llx) is not aligned.\n", gpa_mappings.gpa);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    tdr_t* tdr_p = tdx_local_data_ptr->vp_ctx.tdr;
    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    tdx_sanity_check(tdr_p != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ACCEPT_LEAF), 0);
    tdx_sanity_check(tdcs_p != NULL, SCEC_TDCALL_SOURCE(TDG_MEM_PAGE_ACCEPT_LEAF), 1);

    if (!check_gpa_validity(page_gpa, tdcs_p->executions_ctl_fields.gpaw, PRIVATE_ONLY))
    {
        TDX_ERROR("Page to accept GPA (=0x%llx) is not not valid\n", page_gpa.raw);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    ept_level_t ept_level = req_accept_level;
    return_val = walk_private_gpa(tdcs_p, page_gpa, tdr_p->key_management_fields.hkid,
                                  &sept_entry_ptr, &ept_level, &sept_entry_copy);

    bool_t is_leaf = is_ept_leaf_entry(&sept_entry_copy, ept_level);
    sept_entry_state sept_state = get_sept_entry_state(&sept_entry_copy, ept_level);

    tdaccept_failure_type_t fail_type = check_tdaccept_failure((return_val != TDX_SUCCESS), is_leaf,
                                                                sept_state);

    IF_RARE (fail_type != TDACCEPT_SUCCESS)
    {
        TDX_WARN("Failing SEPT entry = 0x%llx, failure type = %d\n", sept_entry_copy.raw, fail_type);
        if (fail_type == TDACCEPT_ALREADY_ACCEPTED)
        {
            return_val = api_error_with_operand_id(TDX_PAGE_ALREADY_ACCEPTED, ept_level);
            goto EXIT;
        }
        else if (fail_type == TDACCEPT_SIZE_MISMATCH)
        {
            return_val = api_error_with_operand_id(TDX_PAGE_SIZE_MISMATCH, ept_level);
            goto EXIT;
        }
        else if (fail_type == TDACCEPT_VIOLATION)
        {
            tdaccept_ept_violation_exit(page_gpa, req_accept_level, sept_state,
                                        is_leaf, ept_level, sept_entry_ptr);
        }
        else
        {
            FATAL_ERROR();
        }
    }

    // Try to acquire SEPT entry guest exclusive lock and check entry blocked and pending states
    ia32e_sept_t sept_entry_expected;

    sept_entry_expected.raw = sept_entry_copy.raw;
    sept_entry_expected.fields_4k.tdp = 1;
    sept_entry_expected.fields_4k.tdb = 0;
    sept_entry_expected.fields_4k.tdgl = 0;

    ia32e_sept_t new_sept_entry = {.raw = sept_entry_expected.raw};
    new_sept_entry.fields_4k.tdgl = 1;

    ia32e_sept_t prev_sept_entry =  {
                                     .raw = _lock_cmpxchg_64b(sept_entry_expected.raw,
                                                              new_sept_entry.raw,
                                                              &sept_entry_ptr->raw)
                                    };

    // Check that previous value has the expected value
    if (prev_sept_entry.raw != sept_entry_expected.raw)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
        goto EXIT;
    }

    // Update expected EPTE value
    sept_entry_expected.raw = new_sept_entry.raw;

    /**---------------------------------------------------------------------
       Interruptible page initialization loop
    ---------------------------------------------------------------------**/
    bool_t tdaccept_done = false;

    while (!tdaccept_done)
    {
        init_sept_4k_page(current_tdr, new_sept_entry);

        // Check if initialization is done
        // Initialization is done either in case when we accept only a single 4KB page
        // or when we already initialized all the 512 child 4KB pages in 2MB range
        if ((req_accept_level == LVL_PT) || (new_sept_entry.accept.init_counter == (NUM_OF_4K_PAGES_IN_2MB - 1)))
        {
            if (req_accept_level == LVL_PD)
            {
                new_sept_entry.accept.init_counter = 0;
            }

            new_sept_entry.present.rwx = 0x7;
            new_sept_entry.fields_ps.tdp = 0;
            new_sept_entry.fields_4k.supp_ve = 1;
            new_sept_entry.fields_4k.tdgl = 0;

            tdaccept_done = true;
        }
        else
        {
            // Update next initialized PA
            new_sept_entry.accept.init_counter += 1;
        }

        if (!update_sept_entry(sept_entry_ptr, sept_entry_expected, new_sept_entry))
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RCX);
            goto EXIT;
        }
        sept_entry_expected.raw = new_sept_entry.raw;

        // End of interrupt window, check for interrupt
        if ((!tdaccept_done) && (ia32_rdmsr(IA32_INTR_PENDING_MSR_ADDR) != 0))
        {
            // Release SEPT entry guest exclusive lock
            if (!_lock_btr_64b(&sept_entry_ptr->raw, SEPT_ENTRY_TDGL_BIT_POSITION))
            {
                FATAL_ERROR();
            }

            // Resume TD guest without changing any GPR and without incrementing RIP
            *interrupt_occurred = true;
            goto EXIT;
        }
    }

    return_val = TDX_SUCCESS;

EXIT:
    // Free keyhole mappings
    if (sept_entry_ptr != NULL)
    {
        free_la(sept_entry_ptr);
    }

    return return_val;
}
