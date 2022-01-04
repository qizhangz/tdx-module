// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_vmexit.c
 * @brief CPUID VMexit handler
 */

#include "td_dispatcher/tdx_td_dispatcher.h"
#include "tdx_api_defs.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/ia32_accessors.h"
#include "accessors/vt_accessors.h"
#include "accessors/data_accessors.h"
#include "x86_defs/vmcs_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "tdx_td_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "vmm_dispatcher/tdx_vmm_dispatcher.h"
#include "helpers/helpers.h"
#include "td_dispatcher/vm_exits/td_vmexit.h"
#include "td_transitions/td_exit.h"
#include "auto_gen/cpuid_configurations.h"

// Clear XFAM-related bits in CPUID values, based on XFAM and the
// provided set of masks (per XFAM bit)
static void apply_cpuid_xfam_masks(cpuid_config_return_values_t* cpuid_values,
                                   uint64_t xfam,
                                   const cpuid_config_return_values_t* cpuid_masks)

{
    uint64_t xfam_mask;   // 1-bit mask

    xfam_mask = 1ULL;
    for (uint32_t xfam_bit = 0; xfam_bit <= XCR0_MAX_VALID_BIT; xfam_bit++)
    {
        if ((xfam & xfam_mask) == 0)
        {
            // Loop on all 4 CPUID values
            for (uint32_t i = 0; i < 4; i++)
            {
                cpuid_values->values[i] &= ~cpuid_masks[xfam_bit].values[i];
            }
        }
        xfam_mask <<= 1;
    }
};


void td_cpuid_exit(void)
{
    uint32_t       leaf;
    uint32_t       subleaf;
    uint32_t       index;
    uint32_t       cpl;
    cpuid_config_return_values_t return_values;
    cpuid_01_ebx_t cpuid_01_ebx;
    cpuid_01_ecx_t cpuid_01_ecx;
    cpuid_07_00_ecx_t cpuid_07_00_ecx;
    ia32_cr4_t     cr4;

    tdx_module_local_t* tdx_local_data_ptr = get_local_data();
    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    vp_ctx_t* vp_ctx = &tdx_local_data_ptr->vp_ctx;

    // Check if the guest TD elected to unconditionally inject a #VE for the guest CPL
    cpl = get_guest_td_cpl();

    if (((cpl == 0) && vp_ctx->tdvps->management.cpuid_supervisor_ve) ||
        ((cpl > 0) && vp_ctx->tdvps->management.cpuid_user_ve))
    {
        tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, vp_ctx->tdvps, 0, 0);
        return;
    }

    leaf = (uint32_t)vp_ctx->tdvps->guest_state.rax;
    subleaf = (uint32_t)vp_ctx->tdvps->guest_state.rcx;

    /* CPUID leaf number that is higher than the maximum for its range is treated as if it were
       the maximum in the base range. */
    if (((leaf < CPUID_RESERVED_START) || (leaf > CPUID_RESERVED_END)) &&
        ((leaf > tdx_global_data_ptr->cpuid_last_extended_leaf) ||
         ((leaf > tdx_global_data_ptr->cpuid_last_base_leaf) && (leaf < CPUID_MAX_EXTENDED_VAL_LEAF))))
    {
        leaf = tdx_global_data_ptr->cpuid_last_base_leaf;
    }


    // Get an index to the CPUID tables
    index = get_cpuid_lookup_entry(leaf, subleaf);

    // Check if this is a faulting leaf/sub-leaf, either implicitly (if not in the tables)
    // or explicitly.  If so, inject a #VE.
    if ((index == (uint32_t)-1) || cpuid_lookup[index].faulting)
    {
        tdx_inject_ve(VMEXIT_REASON_CPUID_INSTRUCTION, 0, vp_ctx->tdvps, 0, 0);
        return;
    }

    // Get the CPUID value calculated by TDH_MNG_INIT from TDCS
    return_values = vp_ctx->tdcs->executions_ctl_fields.cpuid_config_vals[index];

    // Special CPUID Leaves/Sub-Leaves Handling
    //  - XFAM-allowed
    //  - KeyLocker-allowed
    //  - Perfmon-allowed
    //  - Dynamic

    switch (leaf)
    {
    case 0x1:
        // Leaf 0x1 has ECX bits configurable by AVX (XFAM[2]).
        // If XFAM[2] is 0, the applicable bits are cleared.
        if (!((ia32_xcr0_t)vp_ctx->tdvps->management.xfam).avx)
        {
            return_values.ecx &= ~(xfam_mask_0x1_0xffffffff[2].ecx);
        }

        // INITIAL_APIC_ID dynamically reflects VCPU_INDEX
        cpuid_01_ebx.raw = return_values.ebx;
        cpuid_01_ebx.initial_apic_id = vp_ctx->tdvps->management.vcpu_index;
        return_values.ebx = cpuid_01_ebx.raw;

        // OSXSAVE dynamically reflects guest CR4.OSXSAVE
        cpuid_01_ecx.raw = return_values.ecx;
        ia32_vmread(VMX_GUEST_CR4_ENCODE, &cr4.raw);
        cpuid_01_ecx.osxsave = cr4.osxsave;
        return_values.ecx = cpuid_01_ecx.raw;

        break;

    case 0x7:
        // Sub-leaves 0 and 1 have bits configurable by multiple XFAM bits.
        // If an XFAM bit is 0, the applicable CPUID values bits are cleared.
        if (subleaf == 0)
        {
            apply_cpuid_xfam_masks(&return_values,
                                    vp_ctx->tdvps->management.xfam,
                                    xfam_mask_0x7_0x0);


            cpuid_07_00_ecx.raw = return_values.ecx;

            // CPUID(0x7, 0x0).ECX.OSPKE reflects guest CR4.PKE
            ia32_vmread(VMX_GUEST_CR4_ENCODE, &cr4.raw);
            cpuid_07_00_ecx.ospke = cr4.pke;

            // CPUID(0x7, 0x0).ECX.PKS reflects ATTRIBUTES.PKS
            cpuid_07_00_ecx.pks = vp_ctx->tdcs->executions_ctl_fields.attributes.pks;

            // CPUID(0x7, 0x0).ECX.KL_SUPPORTED reflects ATTRIBUTES.KL
            cpuid_07_00_ecx.kl_supported = 0;

            return_values.ecx = cpuid_07_00_ecx.raw;
        }
        else if (subleaf == 1)
        {
            apply_cpuid_xfam_masks(&return_values,
                                    vp_ctx->tdvps->management.xfam,
                                    xfam_mask_0x7_0x1);
        }
        else
        {
            // Should never get here, this sub-leaf is faulting
            TDX_ERROR("CPUID subleaf %d fatal error\n", subleaf);
            FATAL_ERROR();
        }

        break;

    case 0xA:
        // Leaf 0xA's values are defined as "ALLOW_PERFMON", i.e., if ATTRRIBUTES.PERFMON
        // is set they return the native values, else they return 0.
        if (!vp_ctx->tdcs->executions_ctl_fields.attributes.perfmon)
        {
            return_values.high = 0ULL;
            return_values.low = 0ULL;
        }

        break;

    case 0xD:
        // Sub-leaves 0 and 1 have bits configurable by multiple XFAM bits.
        // If an XFAM bit is 0, the applicable CPUID values bits are cleared.
        if (subleaf <= 1)
        {
            if (subleaf == 0)
            {
                apply_cpuid_xfam_masks(&return_values,
                                        vp_ctx->tdvps->management.xfam,
                                        xfam_mask_0xd_0x0);
            }
            else
            {
                apply_cpuid_xfam_masks(&return_values,
                                        vp_ctx->tdvps->management.xfam,
                                        xfam_mask_0xd_0x1);
            }


            // EBX value, the maximum size of the XSAVE/XRSTOR save area required
            // by enabled features in XCR0 (sub-leaf 0) or XCR0 || IA32_XSS
            // (sub-leaf 1) is dynamically retrieved from the CPU.
            // This assumes that the TDX-SEAM module has not changed XCR0 or
            // IA32_XSS since VM exit from the guest TD.
            uint32_t eax, ecx, edx;
            ia32_cpuid(leaf, subleaf, &eax, &return_values.ebx, &ecx, &edx);
        }
        // Each sub-leaf n, where 2 <= n <= 18, is configured by XFAM[n]
        else if (subleaf <= XCR0_MAX_VALID_BIT)
        {
            if ((vp_ctx->tdvps->management.xfam & (1ULL << subleaf)) == 0)
            {
                return_values.high = 0ULL;
                return_values.low = 0ULL;
            }
        }
        else
        {
            // Should never get here, this sub-leaf is faulting
            TDX_ERROR("CPUID subleaf %d fatal error\n", subleaf);
            FATAL_ERROR();
        }

        break;

    case 0x19:
        return_values.high = 0ULL;
        return_values.low = 0ULL;
        break;

    // Leaf 0x14 is wholly configured by PT (XFAM[8])
    case 0x14:
        if (((ia32_xcr0_t)vp_ctx->tdvps->management.xfam).pt == 0)
        {
            return_values.high = 0ULL;
            return_values.low = 0ULL;
        }
        break;

    // Leaf 0x1C is wholly configured by LBR (XFAM[15])
    case 0x1C:
        if (((ia32_xcr0_t)vp_ctx->tdvps->management.xfam).lbr == 0)
        {
            return_values.high = 0ULL;
            return_values.low = 0ULL;
        }
        break;

    // Leaf 0x1D is wholly configured by AMX (XFAM[18:17])
    case 0x1D:
        // Note that we actually require both XFAM bits to be either 00 or 11
        if ((((ia32_xcr0_t)vp_ctx->tdvps->management.xfam).amx_xtilecfg == 0) ||
            (((ia32_xcr0_t)vp_ctx->tdvps->management.xfam).amx_xtiledata == 0))
        {
            return_values.high = 0ULL;
            return_values.low = 0ULL;
        }
        break;

    // Other leaves have no XFAM-related configuration
    default:
        break;
    }

    // Write the CPUID return values into the guest TD's GPR image
    vp_ctx->tdvps->guest_state.rax = return_values.eax;
    vp_ctx->tdvps->guest_state.rbx = return_values.ebx;
    vp_ctx->tdvps->guest_state.rcx = return_values.ecx;
    vp_ctx->tdvps->guest_state.rdx = return_values.edx;
}
