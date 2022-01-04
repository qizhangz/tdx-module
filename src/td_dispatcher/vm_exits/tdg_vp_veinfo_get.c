// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_vp_veinfo_get.c
 * @brief TDGVPVEINFOGET API handler
 */
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "tdx_td_api_handlers.h"
#include "data_structures/tdx_local_data.h"
#include "data_structures/tdx_tdvps.h"
#include "accessors/data_accessors.h"

api_error_type tdg_vp_veinfo_get(void)
{
    // TDX Local data
    tdx_module_local_t* local_data_ptr = get_local_data();

    api_error_type return_val = TDX_OPERAND_INVALID;

    // Initialize output registers to default values
    local_data_ptr->vp_ctx.tdvps->guest_state.rcx = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.rdx = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.r8 = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.r9 = 0;
    local_data_ptr->vp_ctx.tdvps->guest_state.r10 = 0;

    // Check that VE_INFO has valid contents
    if (local_data_ptr->vp_ctx.tdvps->ve_info.valid == 0)
    {
        TDX_ERROR("VE_INFO has no valid contents\n");
        return_val = TDX_NO_VALID_VE_INFO;
        goto EXIT;
    }
    
    // Retrieve the data from the VE_INFO and put into output registers
    local_data_ptr->vp_ctx.tdvps->guest_state.rcx = (uint64_t)local_data_ptr->vp_ctx.tdvps->ve_info.exit_reason;
    local_data_ptr->vp_ctx.tdvps->guest_state.rdx = local_data_ptr->vp_ctx.tdvps->ve_info.exit_qualification;
    local_data_ptr->vp_ctx.tdvps->guest_state.r8 = local_data_ptr->vp_ctx.tdvps->ve_info.gla;
    local_data_ptr->vp_ctx.tdvps->guest_state.r9 = local_data_ptr->vp_ctx.tdvps->ve_info.gpa;
    local_data_ptr->vp_ctx.tdvps->guest_state.r10 = local_data_ptr->vp_ctx.tdvps->ve_info.inst_len_and_info;

    // Mark VE info as free
    local_data_ptr->vp_ctx.tdvps->ve_info.valid = 0ULL;

    return_val = TDX_SUCCESS;

EXIT:
    return return_val;
}
