// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_vmm_dispatcher.h
 * @brief VMM entry point and API dispatcher
 */
#ifndef __TDX_VMM_DISPATCHER_H_INCLUDED__
#define __TDX_VMM_DISPATCHER_H_INCLUDED__


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"


/**
 * @brief Entry point to TDX module from VMM
 *
 * @note Written in assembly and defined as the binary's entry point
 *
 * @return None
 */
void tdx_seamcall_entry_point(void);


/**
 * @brief Dispatcher for VMM side API calls
 *
 * @note
 *
 * @return None
 */
void tdx_vmm_dispatcher(void);


/**
 * @brief Return sequence from the module to the VMM
 *
 * Restores VMM state and eventually calls SEAMRET
 *
 * @return None
 */
void tdx_vmm_post_dispatching(void);


/**
 * @brief Exit the module
 *
 * @note Written in assembly
 *
 * @return None
 */
__attribute__((visibility("hidden"))) void tdx_seamret_to_vmm(void);


#endif // __TDX_VMM_DISPATCHER_H_INCLUDED__
