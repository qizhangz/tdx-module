// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_mng_rd_wr
 * @brief TDHMNGRD and TDHMNGWR API handlers
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"
#include "auto_gen/tdvps_fields_lookup.h"

static bool_t read_from_tdcs_page(tdr_t* tdr_p, uint32_t page_index, uint32_t index_in_page,
                                  uint64_t* rd_value)
{
    uint64_t *page_ptr;
    uint16_t  hkid;

    // We treat the page as an array of 512 8B fields.
    if (index_in_page >= 512)
    {
        return false;
    }

    hkid = tdr_p->key_management_fields.hkid;
    page_ptr = map_pa_with_hkid((void*)tdr_p->management_fields.tdcx_pa[page_index], hkid, TDX_RANGE_RO);

    *rd_value = page_ptr[index_in_page];

    free_la(page_ptr);

    return true;
}

static bool_t get_tdcs_management_field_data(td_ctrl_struct_field_code_t field_code,
		uint64_t* offset, uint64_t* rd_mask)
{
    tdcs_t* tdcs_base = 0;

    if (field_code.raw == TDCS_FINALIZED_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->management_fields.finalized),
                             sizeof(tdcs_base->management_fields.finalized));
    }
    else if (field_code.raw == TDCS_NUM_VCPUS_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->management_fields.num_vcpus),
                             sizeof(tdcs_base->management_fields.num_vcpus));
    }
    else if (field_code.raw == TDCS_NUM_ASSOC_VCPUS_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->management_fields.num_assoc_vcpus),
                             sizeof(tdcs_base->management_fields.num_assoc_vcpus));
    }
    else if ((field_code.raw == TDCS_SECURE_EPT_LOCK_FIELD_CODE) ||
             (field_code.raw == TDCS_EPOCH_LOCK_FIELD_CODE) ||
             (field_code.raw == TDCS_RTMR_LOCK_FIELD_CODE))
    {
        *offset = 0ULL;
        *rd_mask = 0ULL;
    }
    else
    {
        return false;
    }

    return true;
}

static bool_t get_tdcs_exec_control_field_data(td_ctrl_struct_field_code_t field_code, bool_t is_debug,
                                               uint64_t* offset, uint64_t* rd_mask, uint64_t* wr_mask)
{
    tdcs_t* tdcs_base = 0;

    if (field_code.raw == TDCS_ATTRIBUTES_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.attributes.raw),
                             sizeof(tdcs_base->executions_ctl_fields.attributes.raw));
    }
    else if (field_code.raw == TDCS_XFAM_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.xfam),
                             sizeof(tdcs_base->executions_ctl_fields.xfam));
    }
    else if (field_code.raw == TDCS_MAX_VCPUS_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.max_vcpus),
                             sizeof(tdcs_base->executions_ctl_fields.max_vcpus));
    }
    else if (field_code.raw == TDCS_GPAW_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.gpaw),
                             sizeof(tdcs_base->executions_ctl_fields.gpaw));
    }
    else if (field_code.raw == TDCS_EPTP_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.eptp.raw),
                             sizeof(tdcs_base->executions_ctl_fields.eptp.raw));
    }
    else if (field_code.raw == TDCS_TSC_OFFSET_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.tsc_offset),
                             sizeof(tdcs_base->executions_ctl_fields.tsc_offset));
    }
    else if (field_code.raw == TDCS_TSC_MULTIPLIER_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.tsc_multiplier),
                             sizeof(tdcs_base->executions_ctl_fields.tsc_multiplier));
    }

    else if (field_code.raw == TDCS_TSC_FREQUENCY_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.tsc_frequency),
                             sizeof(tdcs_base->executions_ctl_fields.tsc_frequency));
    }

    else if (field_code.raw == TDCS_NOTIFY_ENABLES_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->notify_enables),
                             sizeof(tdcs_base->notify_enables));
        *wr_mask = 0x1ULL;
    }

    else if ((field_code.raw >= TDCS_CPUID_VALUES_FIELD_CODE) &&
             (field_code.raw < (TDCS_CPUID_VALUES_FIELD_CODE + 4 * MAX_NUM_CPUID_LOOKUP)))
    {
        uint64_t cpuid_idx = (field_code.raw - TDCS_CPUID_VALUES_FIELD_CODE) / 4;
        uint64_t reg_idx = (field_code.raw - TDCS_CPUID_VALUES_FIELD_CODE) % 4;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.cpuid_config_vals[cpuid_idx].values[reg_idx]),
                             sizeof(tdcs_base->executions_ctl_fields.cpuid_config_vals[cpuid_idx].values[reg_idx]));
    }
    else if ((field_code.raw >= TDCS_XBUFF_OFFSETS_FIELD_CODE) &&
             (field_code.raw < (TDCS_XBUFF_OFFSETS_FIELD_CODE + XBUFF_OFFSETS_NUM)))
    {
        uint64_t idx = field_code.raw - TDCS_XBUFF_OFFSETS_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.xbuff_offsets[idx]),
                             sizeof(tdcs_base->executions_ctl_fields.xbuff_offsets[idx]));
    }
    else
    {
        return false;
    }
    if (!is_debug)
    {
        if (field_code.raw == TDCS_NOTIFY_ENABLES_FIELD_CODE)
        {
            *rd_mask = 0ULL;
            *wr_mask = 0ULL;
        }
    }

    return true;
}

static bool_t get_tdcs_tlb_epoch_tracking_field_data(td_ctrl_struct_field_code_t field_code,
                                                     uint64_t* offset, uint64_t* rd_mask)
{
    tdcs_t* tdcs_base = 0;

    if (field_code.raw == TDCS_TD_EPOCH_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->epoch_tracking.epoch_and_refcount.td_epoch),
                             sizeof(tdcs_base->epoch_tracking.epoch_and_refcount.td_epoch));
    }
    else if ((field_code.raw >= TDCS_REFCOUNT_FIELD_CODE) &&
             (field_code.raw < (TDCS_REFCOUNT_FIELD_CODE + 2)))
    {
        uint64_t idx = field_code.raw - TDCS_REFCOUNT_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->epoch_tracking.epoch_and_refcount.refcount[idx]),
                             sizeof(tdcs_base->epoch_tracking.epoch_and_refcount.refcount[idx]));
    }
    else
    {
        return false;
    }

    return true;
}

static bool_t get_tdcs_measurement_field_data(td_ctrl_struct_field_code_t field_code, bool_t is_debug,
                                              uint64_t* offset, uint64_t* rd_mask)
{
    tdcs_t* tdcs_base = 0;

    if ((field_code.raw >= TDCS_MRTD_FIELD_CODE) &&
        (field_code.raw < (TDCS_MRTD_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code.raw - TDCS_MRTD_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_td.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_td.qwords[idx]));
    }
    else if ((field_code.raw >= TDCS_MRCONFIGID_FIELD_CODE) &&
             (field_code.raw < (TDCS_MRCONFIGID_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code.raw - TDCS_MRCONFIGID_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_config_id.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_config_id.qwords[idx]));
    }
    else if ((field_code.raw >= TDCS_MROWNER_FIELD_CODE) &&
             (field_code.raw < (TDCS_MROWNER_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code.raw - TDCS_MROWNER_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_owner.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_owner.qwords[idx]));
    }
    else if ((field_code.raw >= TDCS_MROWNERCONFIG_FIELD_CODE) &&
             (field_code.raw < (TDCS_MROWNERCONFIG_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code.raw - TDCS_MROWNERCONFIG_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_owner_config.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_owner_config.qwords[idx]));
    }
    else if ((field_code.raw >= TDCS_RTMR_FIELD_CODE) &&
             (field_code.raw < (TDCS_RTMR_FIELD_CODE + (uint64_t)(SIZE_OF_SHA384_HASH_IN_QWORDS*NUM_RTMRS))))
    {
        uint64_t rtmr_idx = (field_code.raw - TDCS_RTMR_FIELD_CODE) / SIZE_OF_SHA384_HASH_IN_QWORDS;
        uint64_t idx = (field_code.raw - TDCS_RTMR_FIELD_CODE) % SIZE_OF_SHA384_HASH_IN_QWORDS;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.rtmr[rtmr_idx].qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.rtmr[rtmr_idx].qwords[idx]));
    }
    else
    {
        return false;
    }
	if (!is_debug)
    {
	    if ((field_code.raw >= TDCS_RTMR_FIELD_CODE) &&
	        (field_code.raw < (TDCS_RTMR_FIELD_CODE + (uint64_t)(SIZE_OF_SHA384_HASH_IN_QWORDS*NUM_RTMRS))))
	    {
	        *rd_mask = 0ULL;
	    }
    }

    return true;
}

static bool_t get_tdr_td_management_field_data(td_ctrl_struct_field_code_t field_code,
                                               uint64_t* offset, uint64_t* rd_mask)
{
    tdr_t* tdr_base = 0;

    if (field_code.raw == TDR_INIT_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->management_fields.init),
                             sizeof(tdr_base->management_fields.init));
    }
    else if (field_code.raw == TDR_FATAL_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->management_fields.fatal),
                             sizeof(tdr_base->management_fields.fatal));
    }
    else if (field_code.raw == TDR_NUM_TDCX_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->management_fields.num_tdcx),
                             sizeof(tdr_base->management_fields.num_tdcx));
    }
    else if (field_code.raw == TDR_CHLDCNT_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->management_fields.chldcnt),
                             sizeof(tdr_base->management_fields.chldcnt));
    }
    else if ((field_code.raw >= TDR_TDCX_PA_FIELD_CODE) &&
             (field_code.raw < (TDR_TDCX_PA_FIELD_CODE + MAX_NUM_TDCS_PAGES)))
    {
        uint64_t idx = field_code.raw - TDR_TDCX_PA_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->management_fields.tdcx_pa[idx]),
                             sizeof(tdr_base->management_fields.tdcx_pa[idx]));
    }
    else if (field_code.raw == TDR_LIFECYCLE_STATE_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->management_fields.lifecycle_state),
                             sizeof(tdr_base->management_fields.lifecycle_state));
    }
    else
    {
        return false;
    }

    return true;
}

static bool_t get_tdr_key_management_field_data(td_ctrl_struct_field_code_t field_code,
                                                uint64_t* offset, uint64_t* rd_mask)
{
    tdr_t* tdr_base = 0;

    if (field_code.raw == TDR_HKID_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->key_management_fields.hkid),
                             sizeof(tdr_base->key_management_fields.hkid));
    }
    else if (field_code.raw == TDR_PKG_CONFIG_BITMAP_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdr_base->key_management_fields.pkg_config_bitmap),
                             sizeof(tdr_base->key_management_fields.pkg_config_bitmap));
    }
    else
    {
        return false;
    }

    return true;
}

static bool_t get_tdcs_msr_bitmaps_field_data(td_ctrl_struct_field_code_t field_code, uint64_t* rd_value,
                    uint64_t* rd_mask, uint64_t* wr_mask, tdcs_t* tdcs_ptr, tdr_t* tdr_ptr)
{
    if ((field_code.reserved != 0 || field_code.non_arch != 0) ||
            !read_from_tdcs_page(tdr_ptr, MSR_BITMAPS_PAGE_INDEX, field_code.field_code, rd_value))
    {
        TDX_ERROR("MSR bitmap field code 0x%llx invalid!\n", field_code.raw);
        return false;
    }
    *wr_mask = 0ULL;
    if (!tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        *rd_mask = 0ULL;
    }

    return true;

}

static bool_t get_tdcs_sept_root_field_data(td_ctrl_struct_field_code_t field_code, uint64_t* rd_value,
                    uint64_t* rd_mask, uint64_t* wr_mask, tdcs_t* tdcs_ptr, tdr_t* tdr_ptr)
{
    if ((field_code.reserved != 0 || field_code.non_arch != 0) ||
            !read_from_tdcs_page(tdr_ptr, SEPT_ROOT_PAGE_INDEX, field_code.field_code, rd_value))
    {
        TDX_ERROR("SEPT root field code 0x%llx invalid!\n", field_code.raw);
        return false;
    }
    *wr_mask = 0ULL;
    if (!tdcs_ptr->executions_ctl_fields.attributes.debug)
    {
        *rd_mask = 0ULL;
    }

    return true;
}

static bool_t get_tdcs_field_data(td_ctrl_struct_field_code_t field_code, bool_t is_debug, uint64_t* offset,
        uint64_t* rd_mask, uint64_t* wr_mask)
{
    switch(field_code.class_code)
    {
        case TDCS_TD_MANAGEMENT_CLASS_CODE:
            return get_tdcs_management_field_data(field_code, offset, rd_mask);
        case TDCS_EXECUTION_CONTROLS_CLASS_CODE:
            return get_tdcs_exec_control_field_data(field_code, is_debug, offset, rd_mask, wr_mask);
        case TDCS_TLB_EPOCH_TRACKING_CLASS_CODE:
            return get_tdcs_tlb_epoch_tracking_field_data(field_code, offset, rd_mask);
        case TDCS_MEASUREMENT_CLASS_CODE:
            return get_tdcs_measurement_field_data(field_code, is_debug, offset, rd_mask);
    }

    return false;
}

static bool_t get_tdr_field_data(td_ctrl_struct_field_code_t field_code, uint64_t* offset, uint64_t* rd_mask)
{
    switch (field_code.class_code)
    {
        case TDR_TD_MANAGEMENT_CLASS_CODE:
            return get_tdr_td_management_field_data(field_code, offset, rd_mask);
        case TDR_KEY_MANAGEMENT_CLASS_CODE:
            return get_tdr_key_management_field_data(field_code, offset, rd_mask);
    }

    return false;
}

static api_error_type tdh_mng_rd_wr(uint64_t target_tdr_pa, uint64_t requested_field_code,
        bool_t write, uint64_t wr_value, uint64_t wr_request_mask)
{

    tdx_module_local_t * local_data = get_local_data();

    // TDR related variables
    pa_t                  tdr_pa;
    tdr_t               * tdr_ptr = NULL;                       // Pointer to the TDR page (linear address)
    pamt_block_t          tdr_pamt_block;                       // TDR PAMT block
    pamt_entry_t        * tdr_pamt_entry_ptr;                   // Pointer to the TDR PAMT entry
    bool_t                tdr_locked_flag = false;              // Indicate TDR is locked

    tdcs_t              * tdcs_ptr = NULL;                      // Pointer to the TDCS structure (Multi-page)

    td_ctrl_struct_field_code_t    field_code = { .raw = requested_field_code };
    uint64_t              *field_p = NULL;
    uint64_t              rd_value = 0;
    uint64_t              rd_mask = (uint64_t)-1;
    uint64_t              wr_mask = 0ULL;
    uint64_t              offset = 0;

    api_error_type        return_val = UNINITIALIZE_ERROR;

    tdr_pa.raw = target_tdr_pa;

    // Initialize output registers to default values
    local_data->vmm_regs.r8 = 0ULL;

    return_val = check_lock_and_map_explicit_tdr(tdr_pa,
                                                 OPERAND_ID_RCX,
                                                 TDX_RANGE_RO,
                                                 TDX_LOCK_SHARED,
                                                 PT_TDR,
                                                 &tdr_pamt_block,
                                                 &tdr_pamt_entry_ptr,
                                                 &tdr_locked_flag,
                                                 &tdr_ptr);
    if (return_val != TDX_SUCCESS)
    {
        TDX_ERROR("Failed to lock/map a TDR page - error = %llx\n", return_val);
        goto EXIT;
    }

    // Check the TD state
    if ((return_val = check_td_in_correct_build_state(tdr_ptr)) != TDX_SUCCESS)
    {
        TDX_ERROR("TD is not in build state - error = %lld\n", return_val);
        goto EXIT;
    }

    // Map the TDCS structure and check the state.  No need to lock
    tdcs_ptr = map_implicit_tdcs(tdr_ptr, TDX_RANGE_RW);

    switch (field_code.class_code)
    {
        case TDR_TD_MANAGEMENT_CLASS_CODE:
        case TDR_KEY_MANAGEMENT_CLASS_CODE:
            if (!get_tdr_field_data(field_code, &offset, &rd_mask))
            {
                TDX_ERROR("TDR field code 0x%llx invalid!\n", field_code.raw);
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
                goto EXIT;
            }
            field_p = (uint64_t*)((uint8_t*)tdr_ptr + offset);
            rd_value = *field_p;

            break;

        case TDCS_TD_MANAGEMENT_CLASS_CODE:
        case TDCS_EXECUTION_CONTROLS_CLASS_CODE:
        case TDCS_TLB_EPOCH_TRACKING_CLASS_CODE:
        case TDCS_MEASUREMENT_CLASS_CODE:
            if (!get_tdcs_field_data(field_code, tdcs_ptr->executions_ctl_fields.attributes.debug, &offset, &rd_mask, &wr_mask))
            {
                TDX_ERROR("TDCS field code 0x%llx invalid!\n", field_code.raw);
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
                goto EXIT;
            }
            field_p = (uint64_t*)((uint8_t*)tdcs_ptr + offset);
            rd_value = *field_p;

            break;

        case TDCS_MSR_BITMAPS_CLASS_CODE:
            if (!get_tdcs_msr_bitmaps_field_data(field_code, &rd_value, &rd_mask, &wr_mask, tdcs_ptr, tdr_ptr))
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
                goto EXIT;
            }

            break;

        case TDCS_SEPT_ROOT_CLASS_CODE:
            if (!get_tdcs_sept_root_field_data(field_code, &rd_value, &rd_mask, &wr_mask, tdcs_ptr, tdr_ptr))
            {
                return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
                goto EXIT;
            }


            break;

        default:
            TDX_ERROR("Class code 0x%x invalid!\n", field_code.class_code);
            return_val = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            goto EXIT;
    }

    if (write)
    {
        // Narrow down the bits to be written with the input mask
        wr_mask &= wr_request_mask;

        /* Check if the requested field is writable.
           Note that there is no check for readable; we don't have write-only
           fields.
        */
        if (wr_mask == 0)
        {
            TDX_ERROR("TDR field code 0x%llx is not writable!\n", field_code.raw);
            return_val = TDX_FIELD_NOT_WRITABLE;
            goto EXIT;
        }

        // Insert the bits to be written
        wr_value = (rd_value & ~wr_mask) | (wr_value & wr_mask);

        // Attempt to write the value using an atomic operation
        tdx_debug_assert(((uint64_t)field_p & 0x7) == 0);   // Aligned on 8 bytes
        tdx_debug_assert(field_p != NULL);

        uint64_t prev_value;
        if (rd_mask == BIT_MASK_8BITS)
        {
            prev_value = (uint64_t)_lock_cmpxchg_8bit((uint8_t)rd_value, (uint8_t)wr_value, (uint8_t*)field_p);
        }
        else if (rd_mask == BIT_MASK_16BITS)
        {
            prev_value = (uint64_t)_lock_cmpxchg_16b((uint16_t)rd_value, (uint16_t)wr_value, (uint16_t*)field_p);
        }
        else if (rd_mask == BIT_MASK_32BITS)
        {
            prev_value = (uint64_t)_lock_cmpxchg_32b((uint32_t)rd_value, (uint32_t)wr_value, (uint32_t*)field_p);
        }
        else
        {
            prev_value = _lock_cmpxchg_64b(rd_value, wr_value, field_p);
        }

        // Check that previous value has the expected value
        if (prev_value != rd_value)
        {
            return_val = api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RDX);
            goto EXIT;
        }
    }
    else //Read
    {
        if (rd_mask == 0)
        {
            TDX_ERROR("TDR field code 0x%llx is not readable!\n", field_code.raw);
            return_val = TDX_FIELD_NOT_READABLE;
            goto EXIT;
        }
    }

    local_data->vmm_regs.r8 = rd_value & rd_mask;

    return_val = TDX_SUCCESS;

EXIT:
    // Release all acquired locks and free keyhole mappings
    if (tdr_locked_flag)
    {
        pamt_unwalk(tdr_pa, tdr_pamt_block, tdr_pamt_entry_ptr, TDX_LOCK_SHARED, PT_4KB);
        free_la(tdr_ptr);
    }
    if (tdcs_ptr != NULL)
    {
        free_la(tdcs_ptr);
    }

    return return_val;
}

api_error_type tdh_mng_rd(uint64_t target_tdr_pa, uint64_t requested_field_code)
{
    return tdh_mng_rd_wr(target_tdr_pa, requested_field_code, false, 0, 0);
}

api_error_type tdh_mng_wr(uint64_t target_tdr_pa, uint64_t requested_field_code,
        uint64_t data, uint64_t wr_request_mask)
{
    return tdh_mng_rd_wr(target_tdr_pa, requested_field_code, true, data, wr_request_mask);
}
