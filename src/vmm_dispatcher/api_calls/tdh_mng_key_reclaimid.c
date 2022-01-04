// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_mng_key_reclaimid
 * @brief TDHMNGKEYRECLAIMID API handler
 */
#include "tdx_vmm_api_handlers.h"
#include "tdx_basic_defs.h"
#include "auto_gen/tdx_error_codes_defs.h"
#include "x86_defs/x86_defs.h"
#include "data_structures/tdx_global_data.h"
#include "data_structures/td_control_structures.h"
#include "memory_handlers/keyhole_manager.h"
#include "memory_handlers/pamt_manager.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"


api_error_type tdh_mng_key_reclaimid(uint64_t target_tdr_pa)
{

    UNUSED(target_tdr_pa);

    /**
     *  TDH.MNG.KEY.RECLAIMID is provided for backward compatibility.
     *  It does not do anything except returning a constant TDX_SUCCESS status.
     */

    return TDX_SUCCESS;
}

