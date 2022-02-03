// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mng_init
 * @brief TDHMNGINIT API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/td_control_structures.h"
#include "x86_defs/vmcs_defs.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "memory_handlers/sept_manager.h"
#include "helpers/helpers.h"
#include "accessors/ia32_accessors.h"
#include "accessors/data_accessors.h"
#include "crypto/sha384.h"
#include "auto_gen/msr_config_lookup.h"
#include "auto_gen/cpuid_configurations.h"


// Calculate TSC multiplier that will be written in every TD VMCS.
static void calculate_tsc_virt_params(uint64_t tsc, uint64_t native_tsc_freq, uint16_t virt_tsc_frequency,
                                      uint64_t* tsc_multiplier, uint64_t* tsc_offset)
{
    // To avoid losing accuracy, temporary results during the calculation have 128-bit accuracy.
    // This is best implemented with embedded assembly code, using:
    // - 64b*64b unsigned multiply (MUL), which produces a 128b result
    // - 128b/64b unsigned divide (DIV), which produces a 64b result

    uint64_t tmp_tsc_multiplier, tmp_tsc_offset;

    // tmp_128b = virt_tsc_frequency * 25000000 * (1ULL < 48);
    // tsc_multiplier = tmp_128b / native_tsc_frequency;

    tdx_sanity_check((native_tsc_freq >= NATIVE_TSC_FREQUENCY_MIN), SCEC_SEAMCALL_SOURCE(TDH_MNG_INIT_LEAF), 0);

    _ASM_VOLATILE_ (
        "mulq %2\n"
        "divq %3\n"
        : "=a"(tmp_tsc_multiplier)
        : "a"((uint64_t)virt_tsc_frequency * VIRT_TSC_FREQUENCY_UNIT), "r"(1ULL << 48), "b"(native_tsc_freq)
        : "%rdx" );

    // tmp_128b = current_tsc * tsc_multiplier;
    // tsc_offset = -(tmp_128b / (1ULL < 48));

    uint128_t tmp_128b;

    _ASM_VOLATILE_ (
        "mulq %3\n"
        : "=a"(tmp_128b.qwords[0]), "=d"(tmp_128b.qwords[1])
        : "a"(tsc), "b"(tmp_tsc_multiplier)
        :);

    tmp_tsc_offset = (tmp_128b.qwords[1] << 16) | (tmp_128b.qwords[0] >> 48);

    *tsc_multiplier = tmp_tsc_multiplier;
    *tsc_offset = -(tmp_tsc_offset);
};


static api_error_type read_and_set_td_configurations(tdcs_t * tdcs_ptr,
                                                     td_params_t * td_params_ptr,
                                                     uint64_t tdx_max_pa,
                                                     uint64_t sept_root_raw_pa,
                                                     uint16_t* virt_tsc_freq)
{
    ia32e_eptp_t   target_eptp = { .raw = 0 };
    pa_t           sept_root_pa = {.raw = sept_root_raw_pa};

    tdx_module_global_t* tdx_global_data_ptr = get_global_data();

    api_error_type return_val = UNINITIALIZE_ERROR;

    // Read and verify ATTRIBUTES
    uint64_t attributes = td_params_ptr->attributes.raw;
    if (((attributes & ~tdx_global_data_ptr->attributes_fixed0) != 0) ||
        ((attributes & tdx_global_data_ptr->attributes_fixed1) != tdx_global_data_ptr->attributes_fixed1))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_ATTRIBUTES);
        goto EXIT;
    }
    tdcs_ptr->executions_ctl_fields.attributes.raw = attributes;

    // Read and verify XFAM
    uint64_t xfam = td_params_ptr->xfam;
    if (!check_xfam(xfam))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_XFAM);
        goto EXIT;
    }

    tdcs_ptr->executions_ctl_fields.xfam = xfam;

    // Calculate the offsets of XSAVE components in XBUFF, which depend on XFAM.  The algorithm
    // is described in the Intel SDM, Vol. 1, - 13.4.3 "Extended Region of an XSAVE Area"
    uint32_t offset = offsetof(xsave_area_t, extended_region);
    for (uint32_t xfam_i = 2; xfam_i <= XCR0_MAX_VALID_BIT; xfam_i++)
    {
        if ((xfam & BIT(xfam_i)) != 0)
        {
            if (tdx_global_data_ptr->xsave_comp[xfam_i].align)
            {
                // Align the offset up to the next 64B boundary
                offset = ROUND_UP(offset, 64U);
            }
            tdcs_ptr->executions_ctl_fields.xbuff_offsets[xfam_i] = offset;
            offset += tdx_global_data_ptr->xsave_comp[xfam_i].size;
        }
    }

    /*
     * Read and verify MAX_VCPUS
     * The value is provided as a 16-bit number, but is stored
     * as 32 bits to avoid rollover in some cases.
     */
    uint32_t max_vcpus = (uint32_t)td_params_ptr->max_vcpus;
    if (max_vcpus == 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_MAX_VCPUS);
        goto EXIT;
    }
    tdcs_ptr->executions_ctl_fields.max_vcpus = max_vcpus;

    // Check reserved0 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_0, TD_PARAMS_RESERVED0_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Read and verify EPTP_CONTROLS
    target_eptp.raw = td_params_ptr->eptp_controls.raw;

    if ((target_eptp.fields.ept_ps_mt != MT_WB) ||
        (target_eptp.fields.ept_pwl < LVL_PML4) ||
        (target_eptp.fields.ept_pwl > LVL_PML5) ||
        (target_eptp.fields.enable_ad_bits != 0) ||
        (target_eptp.fields.enable_sss_control != 0) ||
        (target_eptp.fields.reserved_0 != 0) ||
        (target_eptp.fields.base_pa != 0) ||
        (target_eptp.fields.reserved_1 != 0))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_EPTP_CONTROLS);
        goto EXIT;
    }

    if ((target_eptp.fields.ept_pwl == LVL_PML5) &&
        (tdx_max_pa < MIN_PA_FOR_PML5))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_EPTP_CONTROLS);
        goto EXIT;
    }

    /**
     *  The PA field of EPTP points to the Secure EPT root page in TDCS,
     *  which has already been initialized to 0 during TDADDCX
     */
    target_eptp.fields.base_pa = sept_root_pa.page_4k_num;

    tdcs_ptr->executions_ctl_fields.eptp.raw = target_eptp.raw;

    // Read and verify EXEC_CONTROLS
    exec_controls_t exec_controls_local_var;
    exec_controls_local_var.raw = td_params_ptr->exec_controls.raw;

    if (exec_controls_local_var.gpaw && (target_eptp.fields.ept_pwl == LVL_PML4))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_EXEC_CONTROLS);
        goto EXIT;
    }
    tdcs_ptr->executions_ctl_fields.gpaw = exec_controls_local_var.gpaw;

    if (exec_controls_local_var.reserved != 0)
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_EXEC_CONTROLS);
        goto EXIT;
    }


    *virt_tsc_freq = td_params_ptr->tsc_frequency;
    if ((*virt_tsc_freq < VIRT_TSC_FREQUENCY_MIN) || (*virt_tsc_freq > VIRT_TSC_FREQUENCY_MAX))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_TSC_FREQUENCY);
        goto EXIT;
    }
    tdcs_ptr->executions_ctl_fields.tsc_frequency = *virt_tsc_freq;

    // We read TSC below.  Compare IA32_TSC_ADJUST to the value sampled on TDHSYSINIT
    // to make sure the host VMM doesn't play any trick on us.
    if (ia32_rdmsr(IA32_TSC_ADJ_MSR_ADDR) != tdx_global_data_ptr->plt_common_config.ia32_tsc_adjust)
    {
        return_val = api_error_with_operand_id(TDX_INCONSISTENT_MSR, IA32_TSC_ADJ_MSR_ADDR);
        goto EXIT;
    }

    // Calculate TSC multiplier of offset that will be written in every TD VMCS, such that
    // virtual TSC will advance at the configured frequency, and will start from 0 at this
    // moment.
    calculate_tsc_virt_params(ia32_rdtsc(),tdx_global_data_ptr->native_tsc_frequency,
                              *virt_tsc_freq,
                              &tdcs_ptr->executions_ctl_fields.tsc_multiplier,
                              &tdcs_ptr->executions_ctl_fields.tsc_offset);


    // Check reserved1 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_1, TD_PARAMS_RESERVED1_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    tdx_memcpy(tdcs_ptr->measurement_fields.mr_config_id.bytes, sizeof(measurement_t),
               td_params_ptr->mr_config_id.bytes, sizeof(measurement_t));
    tdx_memcpy(tdcs_ptr->measurement_fields.mr_owner.bytes, sizeof(measurement_t),
               td_params_ptr->mr_owner.bytes, sizeof(measurement_t));
    tdx_memcpy(tdcs_ptr->measurement_fields.mr_owner_config.bytes, sizeof(measurement_t),
               td_params_ptr->mr_owner_config.bytes, sizeof(measurement_t));

    // Check reserved2 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_2, TD_PARAMS_RESERVED2_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}


static api_error_type read_and_set_cpuid_configurations(tdcs_t * tdcs_ptr,
                                                        td_params_t * td_params_ptr,
                                                        tdx_module_global_t * global_data_ptr,
                                                        tdx_module_local_t * local_data_ptr,
                                                        uint16_t virt_tsc_freq)
{
    uint32_t cpuid_index = 0;
    cpuid_config_leaf_subleaf_t cpuid_leaf_subleaf;
    cpuid_config_return_values_t cpuid_values;
    api_error_type return_val = UNINITIALIZE_ERROR;

    for (cpuid_index = 0; cpuid_index < MAX_NUM_CPUID_CONFIG; cpuid_index++)
    {
        cpuid_leaf_subleaf = cpuid_lookup[cpuid_index].leaf_subleaf;
        cpuid_values = td_params_ptr->cpuid_config_vals[cpuid_index];

        tdx_debug_assert((cpuid_leaf_subleaf.raw == cpuid_configurable[cpuid_index].leaf_subleaf.raw));

        // Loop on all 4 CPUID values
        for (uint32_t i = 0; i < 4; i++)
        {
            // Any bit configured to 1 must be either:
            //   - Directly Configurable, or
            //   - Directly Allowable
            if ((cpuid_values.values[i] &
                 ~(cpuid_configurable[cpuid_index].config_direct.values[i] |
                   cpuid_configurable[cpuid_index].allow_direct.values[i])) != 0)
            {
                local_data_ptr->vmm_regs.rcx = cpuid_leaf_subleaf.raw;
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_CPUID_CONFIG);
                goto EXIT;
            }

            // Compute the virtualized CPUID value and store in TDCS:
            // Note:  The bits in the lookup tables are mutually exclusive

            // Start with the native CPUID value, collected on TDH_SYS_INIT.
            // On TDH.SYS.CONFIG, any bits that are FIXED0 or DYNAMIC have been cleared to 0,
            // and any bits that are FIXED1 have been set to 1.
            uint32_t cpuid_value = global_data_ptr->cpuid_values[cpuid_index].values.values[i];

            // Set any bits that are CONFIG_DIRECT to their input values
            cpuid_value &= ~cpuid_configurable[cpuid_index].config_direct.values[i];
            cpuid_value |= cpuid_values.values[i] & cpuid_configurable[cpuid_index].config_direct.values[i];

            // Clear to 0 any bits that are ALLOW_DIRECT, if their input value is 0
            cpuid_value &= cpuid_values.values[i] | ~cpuid_configurable[cpuid_index].allow_direct.values[i];

            // Write in the TDCS
            tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_index].values[i] = cpuid_value;
        }

        /** Record CPUID flags that will be used for MSR virtualization and TD entry/exit.
         * This saves time looking up the value in TDCS.CPUID_VALUES in those flows.
         */



        if (cpuid_leaf_subleaf.leaf == CPUID_VER_INFO_LEAF)
        {
            cpuid_01_ecx_t cpuid_01_ecx;
            cpuid_01_ecx.raw = tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_index].ecx;
            tdcs_ptr->executions_ctl_fields.cpuid_flags.dca_supported = cpuid_01_ecx.dca;
        }
        if (cpuid_leaf_subleaf.leaf == 7)
        {
           if (cpuid_leaf_subleaf.subleaf == 0)
           {
               cpuid_07_00_ecx_t cpuid_07_00_ecx;
               cpuid_07_00_edx_t cpuid_07_00_edx;
               cpuid_07_00_ecx.raw = tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_index].ecx;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.waitpkg_supported = cpuid_07_00_ecx.waitpkg;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.tme_supported = cpuid_07_00_ecx.tme;
               cpuid_07_00_edx.raw = tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_index].edx;
               tdcs_ptr->executions_ctl_fields.cpuid_flags.mktme_supported = cpuid_07_00_edx.pconfig_mktme;
           }
        }
    }

    // Copy CPUID leaves/sub-leaves that are neither CONFIG_DIRECT nor ALLOW_DIRECT
    for (cpuid_index = MAX_NUM_CPUID_CONFIG; cpuid_index < MAX_NUM_CPUID_LOOKUP; cpuid_index++)
    {
        tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_index] = global_data_ptr->cpuid_values[cpuid_index].values;
    }

    // Check reserved3 bits are 0
    if (!tdx_memcmp_to_zero(td_params_ptr->reserved_3, TD_PARAMS_RESERVED3_SIZE))
    {
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Handle CPUID Configuration by XFAM

    /** Calculate CPUID leaf 0xD sub-leaf 0x0 ECX value, the maximum size of the
     *  XSAVE/XRSTOR save area required by supported features in XCR0, by temporarily
     *  setting XCR0 to the user bits in XFAM, then executing CPUID.
     *  This returns in EBX the maximum size required for XFAM-enabled user-level features.
     */

    ia32_xcr0_t tmp_xcr0;
    uint32_t eax, ebx, ecx, edx;

    tmp_xcr0.raw = ia32_xgetbv(0);
    ia32_xsetbv(0, tdcs_ptr->executions_ctl_fields.xfam & XCR0_USER_BIT_MASK);
    uint32_t cpuid_lookup_idx = get_cpuid_lookup_entry(0xD, 0x0);
    ia32_cpuid(0xD, 0x0, &eax, &ebx, &ecx, &edx);
    tdx_debug_assert(cpuid_lookup_idx < MAX_NUM_CPUID_LOOKUP);
    tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_lookup_idx].ecx = ebx;
    ia32_xsetbv(0, tmp_xcr0.raw);

    /** Update CPUID leaf 0xD subleaf 0x1 EAX[2] value.  This bit enumerates XFD support, and is
     * virtualized as 1 only if the CPU supports XFD and any of the applicable extended feature
     * set, per XFAM, supports XFD.
     */
    cpuid_0d_01_eax_t cpuid_0d_01_eax;
    cpuid_lookup_idx = get_cpuid_lookup_entry(0xD, 0x1);
    tdx_debug_assert(cpuid_lookup_idx < MAX_NUM_CPUID_LOOKUP);
    cpuid_0d_01_eax.raw = tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_lookup_idx].eax;
    if (((uint64_t)global_data_ptr->xfd_faulting_mask & tdcs_ptr->executions_ctl_fields.xfam) == 0)
    {
        cpuid_0d_01_eax.xfd_support = 0;
    }
    tdcs_ptr->executions_ctl_fields.cpuid_flags.xfd_supported = cpuid_0d_01_eax.xfd_support;
    tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_lookup_idx].eax = cpuid_0d_01_eax.raw;

     // Handle CPUID Configuration by TSC_FREQUENCY

     // The following assumes:
     // - CPUID(0x15).EAX (denominator) is virtualized as 25Hz, in units of 1Hz
     // - CPUID(0x15).ECX (nominal ART frequency) is virtualized as 25MHz, in units of 1Hz

     // Therefore CPUID(0x15).EBX (numerator) is the configured virtual TSC frequency,
     // in units of 1MHz.

     // The virtual TSC frequency is CPUID(0x15).ECX * CPUID(0x15).EBX / CPUID(0x15).EAX,
     // i.e., the configured virtual TSC frequency, in units of 1Hz.

    cpuid_lookup_idx = get_cpuid_lookup_entry(0x15, 0x0);
    tdx_debug_assert(cpuid_lookup_idx < MAX_NUM_CPUID_LOOKUP);
    tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_lookup_idx].ebx = virt_tsc_freq;
    tdcs_ptr->executions_ctl_fields.cpuid_config_vals[cpuid_lookup_idx].eax = 0x1;

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}

static void set_msr_bitmaps(tdcs_t * tdcs_ptr)
{
    // Assuming that the whole MSR bitmap was initialized to all 1's by TDHMNGADDCX

    for (uint32_t i = 0; i < MAX_NUM_MSR_LOOKUP; i++)
    {
        msr_bitmap_bit_type bit_meaning = msr_lookup[i].bit_meaning;

        for (uint32_t addr = msr_lookup[i].start_address; addr <= msr_lookup[i].end_address; addr++)
        {
            uint32_t byte_offset, bit_offset;
            byte_offset = (addr & ~HIGH_MSR_MASK) ? MSR_BITMAP_SIZE : 0;
            byte_offset += (addr & HIGH_MSR_MASK) / 8;
            bit_offset = (addr & HIGH_MSR_MASK) % 8;

            uint32_t* byte_addr_rd = (uint32_t*)&tdcs_ptr->MSR_BITMAPS[byte_offset];
            uint32_t* byte_addr_wr = (uint32_t*)&tdcs_ptr->MSR_BITMAPS[byte_offset + (MSR_BITMAP_SIZE * 2)];

            if ((bit_meaning == MSR_BITMAP_FIXED_00 ) ||
                ((bit_meaning == MSR_BITMAP_PERFMON && (addr != IA32_MISC_ENABLES_MSR_ADDR)) && is_perfmon_supported_in_tdcs(tdcs_ptr)) ||
                ((bit_meaning == MSR_BITMAP_XFAM_CET) && is_cet_supported_in_tdcs(tdcs_ptr)) ||
                ((bit_meaning == MSR_BITMAP_XFAM_PT)  && is_pt_supported_in_tdcs(tdcs_ptr)) ||
                ((bit_meaning == MSR_BITMAP_XFAM_ULI) && is_uli_supported_in_tdcs(tdcs_ptr)) ||
                ((bit_meaning == MSR_BITMAP_XFAM_LBR) && is_lbr_supported_in_tdcs(tdcs_ptr)) ||
                ((bit_meaning == MSR_BITMAP_OTHER) &&
                (((addr == IA32_UMWAIT_CONTROL) && is_waitpkg_supported_in_tdcs(tdcs_ptr)) ||
                ((addr == IA32_PKRS) && is_pks_supported_in_tdcs(tdcs_ptr)) ||
                ((addr == IA32_XFD_MSR_ADDR || addr == IA32_XFD_ERROR_MSR_ADDR) && is_xfd_supported_in_tdcs(tdcs_ptr)))))
            {
                btr_32b(byte_addr_rd, bit_offset);
                btr_32b(byte_addr_wr, bit_offset);
            }
            else if (bit_meaning == MSR_BITMAP_FIXED_01 || (addr == IA32_MISC_ENABLES_MSR_ADDR && is_perfmon_supported_in_tdcs(tdcs_ptr)))
            {
                btr_32b(byte_addr_rd, bit_offset);
            }
            else if (bit_meaning == MSR_BITMAP_FIXED_10 || addr == IA32_ARCH_CAPABILITIES_MSR_ADDR)
            {
                btr_32b(byte_addr_wr, bit_offset);
            }
            else if (bit_meaning == MSR_BITMAP_OTHER && (addr == IA32_PERF_CAPABILITIES_MSR_ADDR))
            {
                if (is_perfmon_supported_in_tdcs(tdcs_ptr))
                {
                    btr_32b(byte_addr_wr, bit_offset);
                    if (is_pt_supported_in_tdcs(tdcs_ptr))
                    {
                        btr_32b(byte_addr_rd, bit_offset);
                    }
                }
            }
            else
            {
                break; // No reason to continue going over this MSR range
            }
        }
    }
}


api_error_type tdh_mng_init(uint64_t target_tdr_pa, uint64_t target_td_params_pa)
{
    // Global data
    tdx_module_global_t * global_data_ptr = get_global_data();
    // Local data for return values
    tdx_module_local_t  * local_data_ptr = get_local_data();
    // TDR related variables
    pa_t                  tdr_pa;                    // TDR physical address
    tdr_t               * tdr_ptr;                   // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;            // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;        // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;   // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;           // Pointer to the TDCS structure (Multi-page)

    // TD_PARAMS variables
    pa_t                  td_params_pa;              // Physical address of the params structure
    td_params_t         * td_params_ptr = NULL;      // Pointer to the parameters structure

    uint128_t             xmms[16];                  // SSE state backup for crypto
    crypto_api_error      sha_error_code;
    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;
    td_params_pa.raw = target_td_params_pa;

    // By default, no extended error code is returned
    local_data_ptr->vmm_regs.rcx = 0ULL;

    // Boot NT4 bit should not be set
    if ((ia32_rdmsr(IA32_MISC_ENABLES_MSR_ADDR) & MISC_EN_BOOT_NT4_BIT ) != 0)
    {
        return_val = TDX_BOOT_NT4_SET;
        goto EXIT;
    }

    // Check, lock and map the owner TDR page
    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RW,
                                                 TDX_LOCK_EXCLUSIVE,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to check/lock/map a TDR - error = %lld\n", return_val);
        goto EXIT;
    }

    // Check the TD state
    if (tdr_ptr->management_fields.fatal)
    {
        return_val = TDX_TD_FATAL;
        goto EXIT;
    }
    if (tdr_ptr->management_fields.lifecycle_state != TD_KEYS_CONFIGURED)
    {
        return_val = TDX_TD_KEYS_NOT_CONFIGURED;
        goto EXIT;
    }
    if (tdr_ptr->management_fields.init)
    {
        return_val = TDX_TD_INITIALIZED;
        goto EXIT;
    }
    if (tdr_ptr->management_fields.num_tdcx != MAX_NUM_TDCS_PAGES)
    {
        return_val = TDX_TDCX_NUM_INCORRECT;
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    // Check that TD PARAMS page is TD_PARAMS_ALIGN_IN_BYTES
    if (!is_addr_aligned_pwr_of_2(td_params_pa.raw, TD_PARAMS_ALIGN_IN_BYTES))
    {
        TDX_ERROR("TD PARAMS page is not aligned to %x Bytes\n", TD_PARAMS_ALIGN_IN_BYTES);
        return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Verify the TD PARAMS physical address is canonical and shared
    if ((return_val = shared_hpa_check(td_params_pa, SIZE_OF_TD_PARAMS_IN_BYTES)) != TDX_SUCCESS)
    {
        TDX_ERROR("Failed on source shared HPA check - error = %llx\n", return_val);
        return_val = api_error_with_operand_id(return_val, OPERAND_ID_RDX);
        goto EXIT;
    }

    // Map the TD PARAMS address
    td_params_ptr = map_pa((void*)td_params_pa.raw, TDX_RANGE_RO);

    /**
     *  Initialize the TD management fields
     */
    tdcs_ptr->management_fields.finalized = false;
    tdcs_ptr->management_fields.num_vcpus = 0U;
    tdcs_ptr->management_fields.num_assoc_vcpus = 0U;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.td_epoch = 1ULL;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.refcount[0] = 0;
    tdcs_ptr->epoch_tracking.epoch_and_refcount.refcount[1] = 0;

    /**
     *  Read the TD configuration input and set TDCS fields
     */
    uint16_t virt_tsc_freq;

    return_val = read_and_set_td_configurations(tdcs_ptr,
                                                td_params_ptr,
                                                MAX_PA,
                                                tdr_ptr->management_fields.tdcx_pa[SEPT_ROOT_PAGE_INDEX],
                                                &virt_tsc_freq);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("read_and_set_td_configurations failed\n");
        goto EXIT;
    }

    /**
     *  Handle CPUID Configuration
     */
    return_val = read_and_set_cpuid_configurations(tdcs_ptr, td_params_ptr, global_data_ptr,
                                                   local_data_ptr, virt_tsc_freq);

    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("read_and_set_cpuid_configurations failed\n");
        goto EXIT;
    }

    // ALL_CHECKS_PASSED:  The function is guaranteed to succeed

    /**
     *  Build the MSR bitmaps
     */
    set_msr_bitmaps(tdcs_ptr);

    /**
     *  Initialize the TD Measurement Fields
     */

    store_xmms_in_buffer(xmms);

    if ((sha_error_code = sha384_init(&(tdcs_ptr->measurement_fields.td_sha_ctx))) != 0)
    {
        // Unexpected error - Fatal Error
        TDX_ERROR("Unexpected error in SHA384 - error = %d\n", sha_error_code);
        FATAL_ERROR();
    }

    load_xmms_from_buffer(xmms);
    basic_memset_to_zero(xmms, sizeof(xmms));

    // Zero the RTMR hash values
    basic_memset_to_zero(tdcs_ptr->measurement_fields.rtmr, (SIZE_OF_SHA384_HASH_IN_QWORDS<<3)*NUM_RTMRS);

    // TD init phase is complete
    tdr_ptr->management_fields.init = true;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_EXCLUSIVE, PT_4KB);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }
    if (td_params_ptr != NULL)
    {
        free_la(td_params_ptr);
    }
    return return_val;
}
