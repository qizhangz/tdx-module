// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file td_vmexit.h
 * @brief Everything related to handling of VMEXIT's and VT-related flows
 */

#ifndef SRC_TD_DISPATCHER_VM_EXITS_TD_VMEXIT_H_
#define SRC_TD_DISPATCHER_VM_EXITS_TD_VMEXIT_H_

/**
 * @brief Handler for XSETBV instruction exit
 */
void td_xsetbv_instruction_exit(void);

/**
 * @brief Handler for EPT violation exit
 *
 * @param exit_qualification
 * @param vm_exit_reason
 */
void td_ept_violation_exit(vmx_exit_qualification_t exit_qualification, vm_vmexit_exit_reason_t vm_exit_reason);

/**
 * @brief Handler for EPT misconfiguration exit
 *
 * @param vm_exit_reason
 */
void td_ept_misconfiguration_exit(vm_vmexit_exit_reason_t vm_exit_reason);

/**
 * @brief Handler for CPUID exit
 */
void td_cpuid_exit(void);

/**
 * @brief Handler for RDPMC exit
 *
 * @param vm_exit_reason
 * @param vm_exit_qualification
 */
void td_rdpmc_exit(vm_vmexit_exit_reason_t vm_exit_reason, uint64_t  vm_exit_qualification);

/**
 * @brief Handler for CR access exit
 *
 * @param vm_exit_qualification
 */
void td_cr_access_exit(vmx_exit_qualification_t vm_exit_qualification);

/**
 * @brief Handler for Exception/NMI exit
 *
 * @param vm_exit_reason
 * @param vm_exit_qualification
 * @param vm_exit_inter_info
 */
void td_exception_or_nmi_exit(vm_vmexit_exit_reason_t vm_exit_reason,
                              vmx_exit_qualification_t vm_exit_qualification,
                              vmx_exit_inter_info_t vm_exit_inter_info);

/**
 * @brief Handler for RDMSR exit
 *
 */
void td_rdmsr_exit(void);


/**
 * @brief Handler for WRMSR exit
 *
 */
void td_wrmsr_exit(void);


// VM-transitions and injections helper flows

/**
 * @brief Sets output operands for EPT violation, and continues to async_td_exit_to_vmm routine
 *
 * @param gpa                    - Violating GPA
 * @param exit_qualification     - VM-exit qualification to be passed to VMM
 * @param ext_exit_qual          - VM-exit extended qualification
 */
void tdx_ept_violation_exit_to_vmm(pa_t gpa, vm_vmexit_exit_reason_t vm_exit_reason, uint64_t exit_qual, uint64_t ext_exit_qual);

/**
 * @brief Sets output operands for EPT misconfiguration, and continues to async_td_exit_to_vmm routine
 *
 * @param gpa                    - Misconfigured GPA
 */
void tdx_ept_misconfig_exit_to_vmm(pa_t gpa);

/**
 * @brief Handles #VE injection according to the current valid state of VE_AREA in TDVPS.
 *        Injects #VE to the guest if the VE_AREA not valid, and #DF if valid, and calls tdx_return_to_td routine
 *
 * @param vm_exit_reason     - Exit reason to be stored in the VE_AREA
 * @param exit_qualification - VM-exit qualification to be stored in the VE AREA
 * @param tdvps_p            - TDVPS where the VE_AREA is located
 * @param gpa                - guest physical address to be stored in the VE_AREA
 * @param glp                - guest linear address to be stored in the VE_AREA
 */
void tdx_inject_ve(uint32_t vm_exit_reason, uint64_t exit_qualification, tdvps_t* tdvps_p,
        uint64_t gpa, uint64_t gla);

/**
 * @brief Handler for nmi exit, Inject an NMI if applicable
 *
 * @param tdx_local_data_ptr - pointer to local data
 */
void td_nmi_exit(tdx_module_local_t* tdx_local_data_ptr);

#endif /* SRC_TD_DISPATCHER_VM_EXITS_TD_VMEXIT_H_ */
