// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdh_sys_lp_shutdown
 * @brief TDHSYSLPSHUTDOWN API handler
 */

#include "tdx_api_defs.h"
#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "tdx_vmm_api_handlers.h"
#include "auto_gen/tdx_error_codes_defs.h"

#include "data_structures/tdx_global_data.h"
#include "helpers/tdx_locks.h"
#include "helpers/helpers.h"
#include "accessors/data_accessors.h"
#include "accessors/vt_accessors.h"


api_error_type tdh_sys_lp_shutdown(void)
{
    // Global data
    tdx_module_global_t * global_data = get_global_data();

    bool_t global_locked_flag = false;
    api_error_type ret_val = TDX_OPERAND_INVALID;

    // Acquire a shared lock to the whole TDX-SEAM module
    if (acquire_sharex_lock_sh(&global_data->global_lock) != LOCK_RET_SUCCESS)
    {
        ret_val = TDX_SYS_BUSY;
        goto EXIT;
    }
    global_locked_flag = true;

    // Mark the TDX-SEAM module as being shut down
    global_data->global_state.sys_state = SYS_SHUTDOWN;

    /**
     *   Prevent further SEAMCALL on the current LP by setting the SEAM VMCS’
     *   HOST RIP field to the value of SYS_INFO_TABLE.SHUTDOWN_HOST_RIP,
     *   originally configured by the SEAMLDR.
     */
    ia32_vmwrite(VMX_HOST_RIP_ENCODE, global_data->shutdown_host_rip);

    // Do a global EPT flush.  This is a defense-in-depth
    const ept_descriptor_t zero_descriptor = { 0 };
    ia32_invept(&zero_descriptor, INVEPT_TYPE_2);

    ret_val = TDX_SUCCESS;

EXIT:
    // Release all locks
    if (global_locked_flag)
    {
        release_sharex_lock_sh(&global_data->global_lock);
    }
    return ret_val;
}
