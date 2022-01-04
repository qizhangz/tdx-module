// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_vmcs_init.h
 * @brief Predefined init fields for TD's VMCS
 */

#ifndef __TD_VMCS_INIT_H_INCLUDED__
#define __TD_VMCS_INIT_H_INCLUDED__

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "data_structures/td_control_structures.h"
#include "data_structures/tdx_tdvps.h"

#define VM_EXECUTION_CONTROL_PIN_BASED_VALUE (BIT(0) | BIT(3) | BIT(5))

#define VM_EXECUTION_CONTROL_PROC_BASED_FIXED_VALUES ( BIT(3) | BIT(7) | BIT(10) | \
                                                      BIT(17) | BIT(21) | BIT(24) | \
                                                      BIT(28) | BIT(29) | BIT(31))

#define VMCS_TSC_OFFSET_BIT_LOCATION                 3
#define VMCS_RDPMC_BIT_LOCAITON                      11

#define VM_EXECUTION_CONTROL_SECONDARY_PROC_BASED_FIXED_VALUES (BIT(1) | BIT(3) | BIT(4) | BIT(5) | \
                                                                BIT(6) | BIT(7) | BIT(8) | BIT(9) | \
                                                                BIT(12) | BIT(13) | BIT(15) | BIT(18) | \
                                                                BIT(19) | BIT(20) | BIT(21) | BIT(24) | \
                                                                BIT(25) | BIT(28))

#define VMCS_TSC_SCALING_BIT_LOCATION                25
#define VMCS_ENABLE_USER_LEVEL_OFFSET_BIT_LOCATION   26
#define VMCS_ENABLE_PCONFIG_OFFSET_BIT_LOCATION      27

#define VM_EXECUTION_CONTROL_TERTIARY_PROC_BASED_FIXED_VALUES 0
#define VMCS_LOADIWKEY_BIT_LOCATION                           0
#define VMCS_GPAW_BIT_LOCATION                                5

#define VM_EXIT_CONTROL_FIXED_VALUES (BIT(2) | BIT(9) | BIT(15) | BIT(18) | BIT(19) | \
                                      BIT(20) | BIT(21) | BIT(24) | BIT(25) | \
                                      BIT(26) | BIT(27) | BIT(28))

#define VMCS_EXIT_LOAD_PERF_GLBL_CTRL_BIT_LOCATION        12
#define VMCS_EXIT_SAVE_PERF_GLBL_CTRL_BIT_LOCATION        30

#define VM_ENTRY_CONTROL_ENCODE_FIXED_VALUES (BIT(2) | BIT(14) | BIT(15) | BIT(17) | \
                                              BIT(18) | BIT(19) | BIT(20) | BIT(21))

#define VMCS_ENTRY_LOAD_PERF_GLBL_CTRL_BIT_LOCATION       13
#define VMCS_ENTRY_LOAD_PKRS_BIT_LOCATION                22

typedef struct vmcs_fields_info_s
{
    uint64_t encoding;
    uint64_t value;
} vmcs_fields_info_t;

/**
 *  @brief Host TD VMCS values
 */
typedef struct vmcs_host_values_s
{
    vmcs_fields_info_t CR0;
    vmcs_fields_info_t CR3;
    vmcs_fields_info_t CR4;
    vmcs_fields_info_t CS;
    vmcs_fields_info_t SS;
    vmcs_fields_info_t FS;
    vmcs_fields_info_t GS;
    vmcs_fields_info_t TR;
    vmcs_fields_info_t IA32_S_CET;
    vmcs_fields_info_t IA32_PAT;
    vmcs_fields_info_t IA32_EFER;
    vmcs_fields_info_t FS_BASE;
    vmcs_fields_info_t RSP;
    vmcs_fields_info_t SSP;
    vmcs_fields_info_t GS_BASE;
} vmcs_host_values_t;


/**
 *  @brief Write the TD VMCS host fields into the host_fields_ptr
 */
void save_vmcs_host_fields(vmcs_host_values_t* host_fields_ptr);

void init_guest_td_address_fields(tdr_t* tdr_ptr, tdvps_t* tdvps_ptr, uint16_t curr_hkid);

/**
 *  @brief Initialize the TD VMCS fields
 *
 *  Zero fields are initialized by default (done on TDHVPADDCX)
 */
void init_td_vmcs(tdcs_t * tdcs_ptr, tdvps_t* tdvps_ptr, vmcs_host_values_t* host_fields_ptr);

#endif // __TD_VMCS_INIT_H_INCLUDED__

