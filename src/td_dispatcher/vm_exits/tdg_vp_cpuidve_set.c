// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdg_vp_cpuidve_set.c
 * @brief TDGVPCPUIDVE API handler
 */


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_api_defs.h"

#include "auto_gen/tdx_error_codes_defs.h"
#include "data_structures/tdx_local_data.h"
#include "accessors/data_accessors.h"
#include "tdx_td_api_handlers.h"


api_error_type tdg_vp_cpuidve_set(uint64_t control)
{
    api_error_type retval = UNINITIALIZE_ERROR;
    tdx_module_local_t* tdx_local_data_ptr = get_local_data();

    union
    {
        struct
        {
            uint64_t supervisor : 1;
            uint64_t user       : 1;
            uint64_t reserved   : 62;
        };
        uint64_t raw;
    } cpuid_ve;

    cpuid_ve.raw = control;

    if (cpuid_ve.reserved != 0)
    {
        TDX_ERROR("Reserved field is not 0\n");
        retval = api_error_with_operand_id(TDX_OPERAND_INVALID, OPERAND_ID_RCX);
        goto EXIT;
    }

    tdx_local_data_ptr->vp_ctx.tdvps->management.cpuid_supervisor_ve = cpuid_ve.supervisor;
    tdx_local_data_ptr->vp_ctx.tdvps->management.cpuid_user_ve = cpuid_ve.user;

    retval = TDX_SUCCESS;

EXIT:

    return retval;
}
