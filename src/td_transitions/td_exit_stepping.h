// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_exit_stepping.h
 * @brief
 */

#ifndef SRC_TD_TRANSITIONS_TD_EXIT_STEPPING_H_
#define SRC_TD_TRANSITIONS_TD_EXIT_STEPPING_H_

#include "auto_gen/tdx_error_codes_defs.h"

typedef enum {
    FILTER_OK_CONTINUE,
    FILTER_OK_RESUME_TD,
    FILTER_FAIL_TDEXIT_WRONG_APIC_MODE,
    FILTER_FAIL_TDENTER_EPFS,
    FILTER_FAIL_TDENTER_SEPT_BUSY,
} stepping_filter_e;

#define STEPPING_EPF_THRESHOLD 6   // Threshold of confidence in detecting EPT fault-based stepping in progress
#define STEPPING_TSC_THRESHOLD _4KB // Threshold (in cycles) of time interval between successive TD vCPU async interruptions

/**
 * @brief .
 *
 * @param vm_exit_reason
 * @param vm_exit_qualification
 * @param vm_entry_inter_info
 */
stepping_filter_e vmexit_stepping_filter(
        vm_vmexit_exit_reason_t vm_exit_reason,
        vmx_exit_qualification_t vm_exit_qualification,
        vmx_exit_inter_info_t vm_exit_inter_info);


/**
 * @brief .
 *
 * @param faulting_gpa
 * @param tdvps_p
 * @param tdr_p
 * @param tdcs_p
 * @param is_sept_locked
 *
 * @return
 */
stepping_filter_e td_entry_stepping_filter(pa_t* faulting_gpa, tdvps_t* tdvps_p, tdr_t* tdr_p, tdcs_t* tdcs_p,
                                           bool_t* is_sept_locked);


#endif /* SRC_TD_TRANSITIONS_TD_EXIT_STEPPING_H_ */
