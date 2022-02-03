// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_ept_violation.c
 * @brief VM Exit handler for EPT violation VM exit
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "memory_handlers/sept_manager.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"

void td_ept_violation_exit(vmx_exit_qualification_t exit_qualification, vm_vmexit_exit_reason_t vm_exit_reason)
{
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    tdcs_t* tdcs_p = tdx_local_data_ptr->vp_ctx.tdcs;

    bool_t gpaw = tdcs_p->executions_ctl_fields.gpaw;
    pa_t gpa;

    vmx_guest_inter_state_t guest_inter_state;

    // EPT violation is the only case in TDX-SEAM where NMI may have been unblocked
    // by an IRET instruction before the VM exit happened.  In this case, since we
    // inject a #PF, we re-block NMI.
     if (exit_qualification.ept_violation.nmi_unblocking_due_to_iret)
    {
        ia32_vmread(VMX_GUEST_INTERRUPTIBILITY_ENCODE, &guest_inter_state.raw);
        guest_inter_state.blocking_by_nmi = 1;
        ia32_vmwrite(VMX_GUEST_INTERRUPTIBILITY_ENCODE, guest_inter_state.raw);
    }

    ia32_vmread(VMX_GUEST_PHYSICAL_ADDRESS_INFO_FULL_ENCODE, &gpa.raw);



    // Special treatment for GPAW==0 (i.e., SHARED bit is bit 47) and MAX_PA > 48.
    // If any GPA bit between the SHARED bit and bit (MAX_PA-1) is set,
    // and there is a valid guest linear address, morph the EPT_VIOLATION into a #PF exception.
    if (are_gpa_bits_above_shared_set(gpa.raw, gpaw, MAX_PA) &&
        exit_qualification.ept_violation.gla_valid)
    {
        // Morph into a #PF(PFEC.RSVD=1)
        pfec_t pfec = { .raw = 0 };
        pfec.p  = 1;
        pfec.wr = exit_qualification.ept_violation.data_write;
        pfec.us = (get_guest_td_cpl() == 3);
        pfec.r  = 1;
        pfec.id = exit_qualification.ept_violation.insn_fetch;
        pfec.ss = exit_qualification.ept_violation.ss;

        uint64_t gla;
        ia32_vmread(VMX_VM_EXIT_GUEST_LINEAR_ADDRESS_ENCODE, &gla);

        inject_pf(gla, pfec);
        return;
    }

    tdx_ept_violation_exit_to_vmm(gpa, vm_exit_reason, exit_qualification.raw, 0);
}
