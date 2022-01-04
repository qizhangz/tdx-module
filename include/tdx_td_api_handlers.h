// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_api_handlers.h
 * @brief TDX TD API Handelrs
 */

#ifndef INCLUDE_TDX_TD_API_HANDLERS_H_
#define INCLUDE_TDX_TD_API_HANDLERS_H_

#include "tdx_api_defs.h"
#include "x86_defs/vmcs_defs.h"


/**
 * @brief Initialize a pending private page
 *
 * Accept a pending private page and initialize the page to 0 using the TD ephemeral private key.
 *
 * @note
 *
 * @param page_to_accept_gpa Guest physical address of the private page to accept
 * @param interrupt_occurred flag indicate if interrupt occurred
 *
 * @return Success or Error type
 */
api_error_type tdg_mem_page_accept(uint64_t page_to_accept_gpa, bool_t* interrupt_occurred);


/**
 * @brief Extend a TDCS.RTMR measurement register.
 *
 * @note
 *
 * @param extension_data_gpa 64B-aligned guest physical address of a 48B extension data
 * @param index Index of the measurement register to be extended
 *
 * @return Success or Error type
 */
api_error_type tdg_mr_rtmr_extend(uint64_t extension_data_gpa, uint64_t index);


/**
 * @brief Get Virtualization Exception Information for the recent #VE exception
 *
 * @note
 *
 * @return Success or Error type
 */
api_error_type tdg_vp_veinfo_get(void);


/**
 * @brief Get guest TD execution environment information.
 *
 * @note
 *
 * @return Success
 */
api_error_type tdg_vp_info(void);


/**
 * @brief Creates a TDREPORT_STRUCT structure
 *
 * Creates a TDREPORT_STRUCT structure that contains the measurements/configuration
 * information of the guest TD that called the function, measurements/configuration
 * information of the TDX-SEAM module and a REPORTMACSTRUCT.
 *
 * @note
 *
 * @param report_struct_gpa 1024B-aligned guest physical address of newly created report structure
 * @param additional_data_gpa 64B-aligned guest physical address of additional data to be signed
 * @param sub_type Report sub type
 *
 * @return Success or Error type
 */
api_error_type tdg_mr_report(uint64_t report_struct_gpa, uint64_t additional_data_gpa, uint64_t sub_type);

/**
 * @brief Controls unconditional #VE on CPUID execution by the guest TD.
 *
 * @param Controls whether CPUID executed by the guest TD will cause #VE unconditionally
 * @return Success or Error type
 */
api_error_type tdg_vp_cpuidve_set(uint64_t control);

/**
 * @brief Perform a TD Exit to the host VMM.
 *
 * @note
 *
 * @param controler_value Controls which part of the guest TD state is passed as-is to the VMM and back.
 *
 * @return Success
 */
api_error_type tdg_vp_vmcall(uint64_t controller_value);
/**
 * @brief Read a VM-scope metadata field (control structure field) of a TD.
 *
 * @note
 *
 * @param field_code is the Field identifier
 *
 * @return Success or Error type
 */
api_error_type tdg_vm_rd(uint64_t vm_id, uint64_t field_code);
/**
 * @brief Write a VM-scope metadata field (control structure field) of a TD.
 *
 * @note
 *
 * @param field_code is the Field identifier
 * @param wr_data is the data to write to the field
 * @param wr_mask is a 64b write mask to indicate which bits of the value in R8 are to be written to the field
 *
 * @return Success or Error type
 */
api_error_type tdg_vm_wr(uint64_t vm_id,
        uint64_t field_code,
        uint64_t wr_data,
        uint64_t wr_mask);

#endif /* INCLUDE_TDX_TD_API_HANDLERS_H_ */
