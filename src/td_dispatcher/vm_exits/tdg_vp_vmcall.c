// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_vp_vmcall.c
 * @brief TDGVPVMCALL API handler
 */

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "tdx_td_api_handlers.h"
#include "debug/tdx_debug.h"

#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "accessors/data_accessors.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "x86_defs/x86_defs.h"

#include "td_transitions/td_exit.h"

static void copy_gprs_data_from_td_to_vmm(tdx_module_local_t* tdx_local_data_ptr,
                                          tdvmcall_control_t control)
{
    // Copy guest TD's GPRs, selected by the input parameter, to the host
    // VMM GPRs image.  Clear other non-selected GPRs.

    // RAX is not copied, start from RCX
    control.gpr_select |= (uint16_t)BIT(1);  // RCX is always copied
    for (uint32_t i = 1; i < 16; i++)
    {
        if ((control.gpr_select & BIT(i)) != 0)
        {
            tdx_local_data_ptr->vmm_regs.gprs[i] = tdx_local_data_ptr->vp_ctx.tdvps->guest_state.gprs[i];
        }
        else
        {
            tdx_local_data_ptr->vmm_regs.gprs[i] = 0ULL;
        }
    }
}

api_error_type tdg_vp_vmcall(uint64_t controller_value)
{
    api_error_type retval = TDX_OPERAND_INVALID;
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdvmcall_control_t control = { .raw = controller_value };

    // Bits 0, 1 and 4 and 63:32 of RCX must be 0
    if (((control.gpr_select & (uint16_t)(BIT(0) | BIT(1) | BIT(4))) != 0) ||
         (control.reserved != 0))
    {
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        TDX_ERROR("Unsupported bits in GPR_SELECT field = 0x%x\n", control.gpr_select)
        goto EXIT_FAILURE;
    }

    // TDGVPVMCALL behaves as a trap-like TD exit.
    // TDX-SEAM advances the guest TD RIP (in TD VMCS) to the instruction following TDCALL.
    advance_guest_rip();

    // TDX-SEAM loads the host VMM GPRs (in its LP-scope state save area), except RAX,
    // with the guest TD GPR (from TDVPS).
    copy_gprs_data_from_td_to_vmm(tdx_local_data_ptr, control);


    // Set the exit reason in RAX
    // Check the sticky BUS_LOCK_PREEMPTED flag, report and clear if true.
    vm_vmexit_exit_reason_t vm_exit_reason = { .raw = VMEXIT_REASON_TDCALL};
    if (tdx_local_data_ptr->vp_ctx.bus_lock_preempted)
    {
        vm_exit_reason.bus_lock_preempted = true;
        tdx_local_data_ptr->vp_ctx.bus_lock_preempted = false;
    }
    tdx_local_data_ptr->vmm_regs.rax = vm_exit_reason.raw;

    ia32_xcr0_t xcr0 = { .raw = tdx_local_data_ptr->vp_ctx.xfam };
    xcr0.sse = 1;
    uint64_t scrub_mask = xcr0.raw;


    td_vmexit_to_vmm(VCPU_READY_TDVMCALL, scrub_mask, control.xmm_select, false);
    
    EXIT_FAILURE:

    return retval;
}
