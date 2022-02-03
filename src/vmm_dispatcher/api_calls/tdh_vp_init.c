// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_vp_init
 * @brief TDHVPINIT API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "data_structures/td_vmcs_init.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"


_STATIC_INLINE_ void init_vcpu_gprs_and_registers(tdvps_t * tdvps_ptr, tdcs_t * tdcs_ptr, uint64_t init_rcx, uint32_t vcpu_index)
{
    /**
     *  GPRs init
     */
    if (tdcs_ptr->executions_ctl_fields.gpaw)
    {
        tdvps_ptr->guest_state.rbx = MAX_PA_FOR_GPAW;
    }
    else
    {
        tdvps_ptr->guest_state.rbx = MAX_PA_FOR_GPA_NOT_WIDE;
    }
    // Set RCX and R8 to the input parameter's value
    tdvps_ptr->guest_state.rcx = init_rcx;
    tdvps_ptr->guest_state.r8 = init_rcx;

    // CPUID(1).EAX - returns Family/Model/Stepping in EAX - take the saved value by TDHSYSINIT
    tdx_debug_assert(get_cpuid_lookup_entry(0x1, 0x0) < MAX_NUM_CPUID_LOOKUP);
    tdvps_ptr->guest_state.rdx = (uint64_t)get_global_data()->cpuid_values[get_cpuid_lookup_entry(0x1, 0x0)].values.eax;

    /**
     *  Registers init
     */
    tdvps_ptr->guest_state.xcr0 = XCR0_RESET_STATE;
    tdvps_ptr->guest_state.dr6 = DR6_RESET_STATE;


    // Set RSI to the VCPU index
    tdvps_ptr->guest_state.rsi = vcpu_index & BITS(31,0);

    /**
     *  All other GPRs/Registers are set to 0 or
     *  that their INIT state is 0
     *  Doesn’t include values initialized in VMCS
     */
}


_STATIC_INLINE_ void init_vcpu_msrs(tdvps_t * tdvps_ptr)
{
    tdvps_ptr->guest_msr_state.ia32_fmask = IA32_FMASK_MSR_RESET_STATE; // doesn’t include values initialized in VMCS

    /**
     *  All other MSR's are set to 0
     */
}


api_error_type tdh_vp_init(uint64_t target_tdvpr_pa, uint64_t td_vcpu_rcx)
{
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

    // VMCS related variables
    uint16_t              curr_hkid;
    uint64_t              init_rcx = td_vcpu_rcx;               // Initial value of RDX in TDVPS
    uint32_t              vcpu_index;
    pa_t                  vmcs_pa;
    vmcs_header_t       * vmcs_ptr = NULL;                      // Pointer to VMCS header
    bool_t                td_vmcs_loaded = false;               // Indicates whether TD VMCS was loaded
    vmcs_host_values_t    td_vmcs_host_values;                  // Host TD VMCS value (read from SEAM VMCS)

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

    /**
     *  Check the TD state.  No need to check that the TD has been initialized,
     *  this is implied by the fact that the TDVPR page exists
     */
    if (tdr_ptr->management_fields.fatal)
    {
        TDX_ERROR("TDR in fatal state\n");
        return_val = TDX_TD_FATAL;
        goto EXIT;
    }
    if (tdr_ptr->management_fields.lifecycle_state != TD_KEYS_CONFIGURED)
    {
        TDX_ERROR("TDR keys not configured\n");
        return_val = TDX_TD_KEYS_NOT_CONFIGURED;
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);
    if (tdcs_ptr->management_fields.finalized)
    {
        TDX_ERROR("TD is already finalized\n");
        return_val = TDX_TD_FINALIZED;
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

    // Check the VCPU state
    if (tdvps_ptr->management.state != VCPU_UNINITIALIZED)
    {
        TDX_ERROR("TDVPS is already initialized\n");
        return_val = TDX_VCPU_STATE_INCORRECT;
        goto EXIT;
    }

    /*
     * Set the VCPU index and increment the number of VCPUs in the TD
     * MAX_VCPUS can be in the range 0x0001 to 0xFFFF.
     * Thus, VCPU_INDEX is in the range 0x0000 to 0xFFFE.
     * This assures that there in no overflow in the 16b VPID, later assigned as VCPU_INDEX + 1.
     */
    vcpu_index = _lock_xadd_32b(&tdcs_ptr->management_fields.num_vcpus, 1);
    if (vcpu_index >= tdcs_ptr->executions_ctl_fields.max_vcpus)
    {
        _lock_xadd_32b(&tdcs_ptr->management_fields.num_vcpus, (uint32_t)-1);
        TDX_ERROR("Max VCPUS (%d) has been exceeded\n", tdcs_ptr->executions_ctl_fields.max_vcpus);
        return_val = TDX_MAX_VCPUS_EXCEEDED;
        goto EXIT;
    }
    tdvps_ptr->management.vcpu_index = vcpu_index;


    // We read TSC below.  Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    // to help make sure the host VMM doesn't play any trick on us. */
    if (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != get_global_data()->plt_common_config.ia32_tsc_adjust)
    {
        return_val = api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
        goto EXIT;
    }

    // Read TSC and store as the initial value of LAST_EXIT_TSC
    tdvps_ptr->management.last_exit_tsc = ia32_rdtsc();

    // Copy XFAM to TDVPS; in DEBUG mode the debugger is allowed to change it per VCPU
    tdvps_ptr->management.xfam = tdcs_ptr->executions_ctl_fields.xfam;

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    /**
     *  Initialize the TD VCPU GPRs.  Default GPR value is 0.
     *  Initialize the TD VCPU non-GPR register state in TDVPS:
     *  CRs, DRs, XCR0, IWK etc.
     */
    init_vcpu_gprs_and_registers(tdvps_ptr, tdcs_ptr, init_rcx, vcpu_index);

    /**
     *  Initialize the TD VCPU MSR state in TDVPS
     */
    init_vcpu_msrs(tdvps_ptr);

    /**
     *  No need to explicitly initialize TD VCPU extended state pages.
     *  Since the pages are initialized to 0 on TDHVPCREATE/TDVPADDCX.
     */

    // Bit 63 of XCOMP_BV should be set to 1, to indicate compact format.
    // Otherwise XSAVES and XRSTORS won't work
    tdvps_ptr->guest_extension_state.xbuf.xsave_header.xcomp_bv = BIT(63);

    // Initialize TDVPS.LBR_DEPTH to MAX_LBR_DEPTH supported on the core
    if (((ia32_xcr0_t)tdcs_ptr->executions_ctl_fields.xfam).lbr)
    {
        tdvps_ptr->guest_msr_state.ia32_lbr_depth = (uint64_t)get_global_data()->max_lbr_depth;
    }

    /**
     *  No need to explicitly initialize VAPIC page.
     *  Since the pages are initialized to 0 on TDHVPCREATE/TDVPADDCX,
     *  VAPIC page is already 0.
     */
    vmcs_pa = set_hkid_to_pa((pa_t)tdvps_ptr->management.tdvps_pa[TDVPS_VMCS_PAGE_INDEX], curr_hkid);

    /**
     *  Map the TD VMCS page.
     *
     *  @note This is the only place the VMCS page is directly accessed.
     */
    vmcs_ptr = map_pa((void*)vmcs_pa.raw, TDX_RANGE_RW);
    vmcs_ptr->revision.vmcs_revision_identifier =
            get_global_data()->plt_common_config.ia32_vmx_basic.vmcs_revision_id;

    // Clear the TD VMCS
    ia32_vmclear((void*)vmcs_pa.raw);

    /**
     *  No need to explicitly initialize VE_INFO.
     *  Since the pages are initialized to 0 on TDHVPCREATE/TDVPADDCX,
     *  VE_INFO.VALID is already 0.
     */

    // Mark the VCPU as initialized and ready
    tdvps_ptr->management.state = VCPU_READY_ASYNC;

    /**
     *  Save the host VMCS fields before going to TD VMCS context
     */
    save_vmcs_host_fields(&td_vmcs_host_values);


    /**
     *  Associate the VCPU - no checks required
     */
    associate_vcpu_initial(tdvps_ptr, tdcs_ptr, tdr_ptr, &td_vmcs_host_values);
    td_vmcs_loaded = true;

    /**
     *  Initialize the TD VMCS fields
     */
    init_td_vmcs(tdcs_ptr, tdvps_ptr, &td_vmcs_host_values);

EXIT:
    // Check if we need to load the SEAM VMCS
    if (td_vmcs_loaded)
    {
        set_seam_vmcs_as_active();
    }
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
    if (vmcs_ptr != NULL)
    {
        free_la((void*)vmcs_ptr);
    }
    return return_val;
}
