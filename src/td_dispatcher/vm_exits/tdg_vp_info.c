// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_vp_info.c
 * @brief TDGVPINFO API handler
 */
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/tdx_tdvps.h"
#include "data_structures/td_control_structures.h"
#include "accessors/data_accessors.h"
#include "tdx_td_api_handlers.h"


api_error_type tdg_vp_info(void)
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    td_num_of_vcpus_t vcpus_info = {.raw = 0};

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Check GPA width
    if (local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.gpaw)
    {
        local_data_ptr->vp_ctx.tdvps->guest_state.rcx = MAX_PA_FOR_GPAW;
    }
    else
    {
        local_data_ptr->vp_ctx.tdvps->guest_state.rcx = MAX_PA_FOR_GPA_NOT_WIDE;
    }

    // Get attributes
    local_data_ptr->vp_ctx.tdvps->guest_state.rdx = local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.attributes.raw;

    // Get VCPUs info
    vcpus_info.max_vcpus = local_data_ptr->vp_ctx.tdcs->executions_ctl_fields.max_vcpus;
    vcpus_info.num_vcpus = local_data_ptr->vp_ctx.tdcs->management_fields.num_vcpus;
    local_data_ptr->vp_ctx.tdvps->guest_state.r8 = vcpus_info.raw;
    local_data_ptr->vp_ctx.tdvps->guest_state.r9 = local_data_ptr->vp_ctx.tdvps->management.vcpu_index;

    // Reserved for future use
    local_data_ptr->vp_ctx.tdvps->guest_state.r10 = 0ULL;
    local_data_ptr->vp_ctx.tdvps->guest_state.r11 = 0ULL;

    return_val = TDX_SUCCESS;

    return return_val;
}
