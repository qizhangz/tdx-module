// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_vm_rd_wr.c
 * @brief TDGVMRDWR API handler
 */

#include "tdx_td_api_handlers.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "x86_defs/x86_defs.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"

static bool_t get_tdcs_management_field_data(uint64_t field_code,
        uint64_t* offset, uint64_t* rd_mask, uint64_t* wr_mask)
{
    tdcs_t* tdcs_base = 0;

    if (field_code == TDCS_FINALIZED_FIELD_CODE ||
        field_code == TDCS_NUM_ASSOC_VCPUS_FIELD_CODE ||
        field_code == TDCS_SECURE_EPT_LOCK_FIELD_CODE ||
        field_code == TDCS_EPOCH_LOCK_FIELD_CODE ||
        field_code == TDCS_RTMR_LOCK_FIELD_CODE)
    {
        *offset = 0ULL;
        *rd_mask = 0ULL;
        *wr_mask = 0ULL;
        return true;
    }
    else if (field_code == TDCS_NUM_VCPUS_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                 (uint64_t)&(tdcs_base->management_fields.num_vcpus),
                 sizeof(tdcs_base->management_fields.num_vcpus));
        *wr_mask = 0ULL;
        return true;
    }

    return false;
}

static bool_t get_tdcs_exec_control_field_data(uint64_t field_code,
        uint64_t* offset, uint64_t* rd_mask, uint64_t* wr_mask)
{
    tdcs_t* tdcs_base = 0;

    if (field_code == TDCS_ATTRIBUTES_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                         (uint64_t)&(tdcs_base->executions_ctl_fields.attributes.raw),
                         sizeof(tdcs_base->executions_ctl_fields.attributes.raw));
        *wr_mask = 0ULL;
    }
    else if (field_code == TDCS_XFAM_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.xfam),
                             sizeof(tdcs_base->executions_ctl_fields.xfam));
        *wr_mask = 0ULL;
    }
    else if (field_code == TDCS_MAX_VCPUS_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.max_vcpus),
                             sizeof(tdcs_base->executions_ctl_fields.max_vcpus));
        *wr_mask = 0ULL;
    }
    else if (field_code == TDCS_GPAW_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->executions_ctl_fields.gpaw),
                             sizeof(tdcs_base->executions_ctl_fields.gpaw));
        *wr_mask = 0ULL;
    }
    else if (field_code == TDCS_TSC_FREQUENCY_FIELD_CODE)
    {
        calc_offset_and_mask(offset, rd_mask,
                            (uint64_t)&(tdcs_base->executions_ctl_fields.tsc_frequency),
                            sizeof(tdcs_base->executions_ctl_fields.tsc_frequency));
        *wr_mask = 0ULL;

    }
    else if (field_code == TDCS_NOTIFY_ENABLES_FIELD_CODE)
    {
        *offset = (uint64_t)&(tdcs_base->notify_enables);
        *rd_mask = 0x1ULL;
        *wr_mask = 0x1ULL;
    }
    else if (field_code == TDCS_EPTP_FIELD_CODE ||
            field_code == TDCS_TSC_OFFSET_FIELD_CODE ||
            field_code == TDCS_TSC_MULTIPLIER_FIELD_CODE ||
            ((field_code >= TDCS_CPUID_VALUES_FIELD_CODE) &&
                     (field_code < (TDCS_CPUID_VALUES_FIELD_CODE + 4 * MAX_NUM_CPUID_LOOKUP))) ||
             ((field_code >= TDCS_XBUFF_OFFSETS_FIELD_CODE) &&
                     (field_code < (TDCS_XBUFF_OFFSETS_FIELD_CODE + XBUFF_OFFSETS_NUM))))
    {
        *offset = 0ULL;
        *rd_mask = 0ULL;
        *wr_mask = 0ULL;
    }
    else
    {
        return false;
    }

    return true;
}

static bool_t get_tdcs_tlb_epoch_tracking_field_data(uint64_t field_code,
        uint64_t* offset, uint64_t* rd_mask, uint64_t* wr_mask)
{
    if (field_code == TDCS_TD_EPOCH_FIELD_CODE ||
        ((field_code >= TDCS_REFCOUNT_FIELD_CODE) &&
                (field_code < (TDCS_REFCOUNT_FIELD_CODE + 2))))
    {
        *offset = 0ULL;
        *rd_mask = 0ULL;
        *wr_mask = 0ULL;
        return true;
    }
    return false;
}

static bool_t get_tdcs_measurement_field_data(uint64_t field_code,
        uint64_t* offset, uint64_t* rd_mask, uint64_t* wr_mask)
{
    tdcs_t* tdcs_base = 0;

    if ((field_code >= TDCS_MRTD_FIELD_CODE) &&
        (field_code < (TDCS_MRTD_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code - TDCS_MRTD_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_td.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_td.qwords[idx]));
        *wr_mask = 0ULL;
    }
    else if ((field_code >= TDCS_MRCONFIGID_FIELD_CODE) &&
             (field_code < (TDCS_MRCONFIGID_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code - TDCS_MRCONFIGID_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_config_id.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_config_id.qwords[idx]));
        *wr_mask = 0ULL;
    }
    else if ((field_code >= TDCS_MROWNER_FIELD_CODE) &&
             (field_code < (TDCS_MROWNER_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code - TDCS_MROWNER_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_owner.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_owner.qwords[idx]));
        *wr_mask = 0ULL;
    }
    else if ((field_code >= TDCS_MROWNERCONFIG_FIELD_CODE) &&
             (field_code < (TDCS_MROWNERCONFIG_FIELD_CODE + SIZE_OF_SHA384_HASH_IN_QWORDS)))
    {
        uint64_t idx = field_code - TDCS_MROWNERCONFIG_FIELD_CODE;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.mr_owner_config.qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.mr_owner_config.qwords[idx]));
        *wr_mask = 0ULL;
    }
    else if ((field_code >= TDCS_RTMR_FIELD_CODE) &&
             (field_code < (TDCS_RTMR_FIELD_CODE + (uint64_t)(SIZE_OF_SHA384_HASH_IN_QWORDS*NUM_RTMRS))))
    {
        uint64_t rtmr_idx = (field_code - TDCS_RTMR_FIELD_CODE) / SIZE_OF_SHA384_HASH_IN_QWORDS;
        uint64_t idx = (field_code - TDCS_RTMR_FIELD_CODE) % SIZE_OF_SHA384_HASH_IN_QWORDS;

        calc_offset_and_mask(offset, rd_mask,
                             (uint64_t)&(tdcs_base->measurement_fields.rtmr[rtmr_idx].qwords[idx]),
                             sizeof(tdcs_base->measurement_fields.rtmr[rtmr_idx].qwords[idx]));
        *wr_mask = 0ULL;
    }
    else
    {
        return false;
    }

    return true;
}

static api_error_type tdg_vm_rd_wr(uint64_t vm_id, td_ctrl_struct_field_code_t field_code, tdx_module_local_t * local_data_ptr,
        bool_t write, uint64_t wr_value, uint64_t wr_request_mask)
{
    uint64_t offset = 0;
    uint64_t rd_mask = 0;
    uint64_t wr_mask = 0;
    uint64_t rd_value = 0;

    uint64_t *field_p = NULL;

    local_data_ptr->vp_ctx.tdvps->guest_state.r8 = 0;

    if (vm_id != 0)
    {
        return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
    }

    switch (field_code.class_code)
    {
        case TDCS_TD_MANAGEMENT_CLASS_CODE:
        {
            if (!get_tdcs_management_field_data(field_code.raw, &offset, &rd_mask, &wr_mask))
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }
            break;
        }
        case TDCS_EXECUTION_CONTROLS_CLASS_CODE:
        {
            if (!get_tdcs_exec_control_field_data(field_code.raw, &offset, &rd_mask, &wr_mask))
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }

            break;
        }
        case TDCS_TLB_EPOCH_TRACKING_CLASS_CODE:
        {
            if (!get_tdcs_tlb_epoch_tracking_field_data(field_code.raw, &offset, &rd_mask, &wr_mask))
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }
            break;
        }
        case TDCS_MEASUREMENT_CLASS_CODE:
        {
            if (!get_tdcs_measurement_field_data(field_code.raw, &offset, &rd_mask, &wr_mask))
            {
                return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
            }
            break;
        }
        default:
        {
            TDX_ERROR("Class code 0x%x invalid!\n", field_code.class_code);
            return api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RDX);
        }
    }

    field_p = (uint64_t *)((uint8_t *)local_data_ptr->vp_ctx.tdcs + offset);
    rd_value = *field_p;

    if (write)
    {
        // Narrow down the bits to be written with the input mask
        wr_mask &= wr_request_mask;

        /*
         * Check if the requested field is writable.
         * Note that there is no check for readable (there are no write-only fields).
        */
        if (wr_mask == 0)
        {
            TDX_ERROR("TDR field code 0x%llx is not writable!\n", field_code.raw);
            return TDX_FIELD_NOT_WRITABLE;
        }

        // Insert the bits to be written
        wr_value = (rd_value & ~wr_mask) | (wr_value & wr_mask);

        // Attempt to write the value using an atomic operation
        tdx_debug_assert(((uint64_t)field_p & 0x7) == 0);   // Check field_p is aligned on 8 bytes
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
            return api_error_with_operand_id(TDX_OPERAND_BUSY, OPERAND_ID_RDX);
        }
    }
    else // Read
    {
        if (rd_mask == 0)
        {
            TDX_ERROR("TDR field code 0x%llx is not readable!\n", field_code.raw);
            return TDX_FIELD_NOT_READABLE;
        }
    }

    // Write data to r8
    local_data_ptr->vp_ctx.tdvps->guest_state.r8 = rd_value & rd_mask;
    return TDX_SUCCESS;
}

api_error_type tdg_vm_wr(uint64_t vm_id,
        uint64_t requested_field_code,
        uint64_t wr_data,
        uint64_t wr_mask)
{
    tdx_module_local_t * local_data_ptr = get_local_data();
    td_ctrl_struct_field_code_t    field_code = { .raw = requested_field_code };

    return tdg_vm_rd_wr(vm_id, field_code, local_data_ptr, true, wr_data, wr_mask);
}

api_error_type tdg_vm_rd(uint64_t vm_id, uint64_t requested_field_code)
{
    tdx_module_local_t * local_data_ptr = get_local_data();
    td_ctrl_struct_field_code_t    field_code = { .raw = requested_field_code };

    return tdg_vm_rd_wr(vm_id, field_code, local_data_ptr, false, 0, 0);
}


