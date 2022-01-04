// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_tdvps.h
 * @brief TDVPS definitions
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_TDX_TDVPS_H_
#define SRC_COMMON_DATA_STRUCTURES_TDX_TDVPS_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"

#include "x86_defs/x86_defs.h"
#include "x86_defs/msr_defs.h"


typedef enum
{
    TDVPS_VE_INFO_PAGE_INDEX = 0,
    TDVPS_VMCS_PAGE_INDEX    = 1,
    TDVPS_VAPIC_PAGE_INDEX   = 2,
    MAX_TDVPS_PAGES          = 6
} tdvps_pages_e;

#define VCPU_UNINITIALIZED  0x0
#define VCPU_READY          0x2 // This is a super state and should not be used. Use the sub states :VCPU_READY_ASYNC, VCPU_READY_TDVMCALL
#define VCPU_READY_ASYNC    (VCPU_READY | 0x0)
#define VCPU_READY_TDVMCALL (VCPU_READY | 0x1)
#define VCPU_ACTIVE         0x4
#define VCPU_DISABLED       0x8


#define SIZE_OF_VE_INFO_STRUCT_IN_BYTES 128
#define OFFSET_OF_VE_INFO_STRUCT_IN_BYTES 0
#define TDVPS_VE_INFO_VALID_CONTENT     0xFFFFFFFF // a 32-bit value
#define TDVPS_VE_INFO_NOT_VALID         0

#define VE_INFO_CONTENTS_VALID          0xFFFFFFFF

#pragma pack(push, 1)

/**
 * @struct tdvps_ve_info_t
 *
 * @brief Holds the ve info
 */
typedef struct tdvps_ve_info_s
{
    uint32_t  exit_reason;
    uint32_t  valid; /**< 0xFFFFFFFF:  valid, 0x00000000:  not valid */
    uint64_t  exit_qualification;
    uint64_t  gla;
    uint64_t  gpa;
    uint16_t  eptp_index;

    // Non-Architectural Fields

    uint8_t              reserved0[2];
    union
    {
        struct
        {
            uint32_t instruction_length;
            uint32_t instruction_info;
        };
        uint64_t inst_len_and_info;
    };
    uint8_t              reserved1[84];
} tdvps_ve_info_t;
tdx_static_assert(sizeof(tdvps_ve_info_t) == SIZE_OF_VE_INFO_STRUCT_IN_BYTES, tdvps_ve_info_t);

/**
 * @struct vcpu_state__t
 *
 * @brief vcpu state details is a virtual TDVPS field. It is calculated on read
 */
typedef union vcpu_state_s
{
    struct
    {
        uint64_t vmxip    : 1;
        uint64_t reserved : 63;
    };
    uint64_t raw;
}vcpu_state_t;


#define SIZE_OF_TDVPS_MANAGEMENT_STRUCT_IN_BYTES 768
#define EPF_GPA_LIST_SIZE 32

/**
 * @struct tdvps_management_t
 *
 * @brief Holds the TDVPS management fields
 */
typedef struct tdvps_management_s
{
    uint8_t   state; /**< The activity state of the VCPU */
    /**
     * A boolean flag, indicating whether the TD VCPU has been VMLAUNCH’ed
     * on this LP since it has last been associated with this VCPU. If TRUE,
     * VM entry should use VMRESUME. Else, VM entry should use VMLAUNCH.
     */
    bool_t    launched;
    /**
     * Sequential index of the VCPU in the parent TD. VCPU_INDEX indicates the order
     * of VCPU initialization (by TDHVPINIT), starting from 0, and is made available to
     * the TD via TDINFO. VCPU_INDEX is in the range 0 to (MAX_VCPUS_PER_TD - 1)
     */
    uint32_t  vcpu_index;
    uint8_t   num_tdvpx; /**< A counter of the number of child TDVPX pages associated with this TDVPR */

    uint8_t   reserved_0[1]; /**< Reserved for aligning the next field */
    /**
     * An array of (TDVPS_PAGES) physical address pointers to the TDVPX pages
     *
     * PA is without HKID bits
     * Page 0 is the PA of the TDVPR page
     * Pages 1,2,... are PAs of the TDVPX pages
    */
    uint64_t  tdvps_pa[MAX_TDVPS_PAGES];
    /**
     * The (unique hardware-derived identifier) of the logical processor on which this VCPU
     * is currently associated (either by TDHVPENTER or by other VCPU-specific SEAMCALL flow).
     * A value of 0xffffffff (-1 in signed) indicates that VCPU is not associated with any LP.
     * Initialized by TDHVPINIT to the LP_ID on which it ran
     */
    uint32_t  assoc_lpid;
    /**
     * The TD's ephemeral private HKID at the last time this VCPU was associated (either
     * by TDHVPENTER or by other VCPU-specific SEAMCALL flow) with an LP.
     * Initialized by TDHVPINIT to the current TD ephemeral private HKID.
     */
    uint32_t  assoc_hkid;
    /**
     * The value of TDCS.TD_EPOCH, sampled at the time this VCPU entered TDX non-root mode
     */
    uint64_t  vcpu_epoch;

    bool_t    cpuid_supervisor_ve;
    bool_t    cpuid_user_ve;
    bool_t    is_shared_eptp_valid;

    uint8_t   reserved_1[5]; /**< Reserved for aligning the next field */

    uint64_t  last_exit_tsc;

    bool_t    pend_nmi;

    uint8_t   reserved_2[7]; /**< Reserved for aligning the next field */

    uint64_t  xfam;
    uint8_t   last_epf_gpa_list_idx;
    uint8_t   possibly_epf_stepping;

    uint8_t   reserved_3[150]; /**< Reserved for aligning the next field */

    uint64_t   last_epf_gpa_list[EPF_GPA_LIST_SIZE];  // Array of GPAs that caused EPF at this TD vCPU instruction

    uint8_t   reserved_4[256]; /**< Reserved for aligning the next field */
} tdvps_management_t;
tdx_static_assert(sizeof(tdvps_management_t) == SIZE_OF_TDVPS_MANAGEMENT_STRUCT_IN_BYTES, tdvps_management_t);


#define SIZE_OF_TDVPS_GUEST_STATE_IN_BYTES 256 // Include Guest state & Guest GPR state (each 128 Byte)
#define OFFSET_OF_TDVPS_GUEST_STATE_IN_BYTES 0x400

/**
 * @struct tdvps_guest_state_t
 *
 * @brief Holds the state of the guests registers
 */
typedef struct tdvps_guest_state_s
{
    union
    {
        struct
        {
            uint64_t rax;
            uint64_t rcx; /**< Provided as an input to TDHVPINIT (same value as R8) */
            /**
             * Bits [31:00]:  Same as RESET value, matches CPUID.1:EAX.
             * CPU version information: Family, Model and Stepping.
             * Bits [63:32]:  Set to 0
             */
            uint64_t rdx;
            /**
             * Bits [05:00]:  GPAW: the effective GPA width (in bits) for this TD (don’t confuse with MAXPA).
             * SHARED bit is at GPA bit GPAW-1. In TDX1, only GPAW values 48 and 52 are possible.
             * Bits [63:06]:  Reserved for future additional details, set to 0, must be ignored by vBIOS
             */
            uint64_t rbx;
            uint64_t rsp_placeholder;
            uint64_t rbp;
            uint64_t rsi;
            uint64_t rdi;
            uint64_t r8; /**< Provided as an input to TDHVPINIT (same value as RCX) */
            uint64_t r9;
            uint64_t r10;
            uint64_t r11;
            uint64_t r12;
            uint64_t r13;
            uint64_t r14;
            uint64_t r15;
        };

        uint64_t gprs[16];
    };

    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t xcr0;
    uint64_t cr2;
    uint8_t  reserved[8]; /**< Reserved for aligning the next field */
    uint128_t  iwk_enckey[2]; /**< Last KeyLocker IWK loader.  Cache line aligned */
    uint128_t  iwk_intkey;
    loadiwkey_ctl_t iwk_flags;
    uint8_t  reserved_2[4]; /**< Reserved for aligning the next field */
    vcpu_state_t vcpu_state_details;
} tdvps_guest_state_t;
tdx_static_assert(sizeof(tdvps_guest_state_t) == SIZE_OF_TDVPS_GUEST_STATE_IN_BYTES, tdvps_guest_state_t);


#define SIZE_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES   384
#define OFFSET_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES 0x500

/**
 * @struct tdvps_guest_msr_state_t
 *
 * @brief Holds the MSRs
 */
typedef struct tdvps_guest_msr_state_s
{
    uint64_t ia32_spec_ctrl;
    uint64_t ia32_umwait_control;
    uint64_t ia32_perfevtsel[NUM_PMC];
    uint64_t ia32_offcore_rsp[2];
    uint64_t ia32_xfd;
    uint64_t ia32_xfd_err;
    uint64_t ia32_fixed_ctr[NUM_FIXED_CTR];
    uint64_t ia32_perf_metrics;
    uint64_t ia32_fixed_ctr_ctrl;
    uint64_t ia32_perf_global_status;
    uint64_t ia32_pebs_enable;
    uint64_t ia32_pebs_data_cfg;
    uint64_t ia32_pebs_ld_lat;
    uint64_t ia32_pebs_frontend;
    uint64_t ia32_a_pmc[NUM_PMC];
    uint64_t ia32_ds_area;
    uint64_t ia32_xss;
    uint64_t ia32_lbr_depth;
    uint64_t ia32_star;
    uint64_t ia32_lstar;
    uint64_t ia32_fmask;
    uint64_t ia32_kernel_gs_base;
    uint64_t ia32_tsc_aux;
    uint8_t  reserved[56]; /**< Reserved for aligning the next field */
} tdvps_guest_msr_state_t;
tdx_static_assert(sizeof(tdvps_guest_msr_state_t) == SIZE_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES, tdvps_guest_msr_state_t);


#define SIZE_OF_TD_VMCS_IN_BYTES   (TDX_PAGE_SIZE_IN_BYTES/2)
#define OFFSET_OF_TDVPS_TD_VMCS_IN_BYTES 0x1000

/**
 * @struct tdvps_td_vmcs_t
 *
 * @brief Holds the TD VMCS page
 */
typedef struct tdvps_td_vmcs_s
{
    uint8_t td_vmcs[SIZE_OF_TD_VMCS_IN_BYTES]; /**< Not mapped in TDX-SEAM LA, access by VMREAD/VMWRITE.*/
} tdvps_td_vmcs_t;
tdx_static_assert(sizeof(tdvps_td_vmcs_t) == SIZE_OF_TD_VMCS_IN_BYTES, tdvps_td_vmcs_t);


#define SIZE_OF_TDVPS_VAPIC_STRUCT_IN_BYTES TDX_PAGE_SIZE_IN_BYTES
#define OFFSET_OF_TDVPS_VAPIC_STRUCT              0x2000
#define APIC_T_SIZE _1KB

#define PPR_INDEX 0xA0

/**
 * @struct tdvps_vapic_t
 *
 * @brief Holds the Virtual APIC Page
 */
typedef union  tdvps_vapic_s
{
    struct
    {
        uint8_t apic[APIC_T_SIZE]; /**< Virtual APIC Page */
        uint8_t reserved[TDX_PAGE_SIZE_IN_BYTES - APIC_T_SIZE];
    };
    uint8_t raw[TDX_PAGE_SIZE_IN_BYTES];
} tdvps_vapic_t;
tdx_static_assert(sizeof(tdvps_vapic_t) == SIZE_OF_TDVPS_VAPIC_STRUCT_IN_BYTES, tdvps_vapic_t);


#define SIZE_OF_TDVPS_GUEST_EXT_STATE_IN_BYTES (3*TDX_PAGE_SIZE_IN_BYTES)
#define OFFSET_OF_TDVPS_GUEST_EXT_STATE     0x3000

/**
 * @struct tdvps_guest_extension_state_t
 *
 * @brief Holds the xbuf
 */
typedef struct tdvps_guest_extension_state_s
{
    union
    {
        xsave_area_t xbuf; /**< XSAVES buffer */
        uint8_t max_size[SIZE_OF_TDVPS_GUEST_EXT_STATE_IN_BYTES];
    };
} tdvps_guest_extension_state_t;
tdx_static_assert(sizeof(tdvps_guest_extension_state_t) == SIZE_OF_TDVPS_GUEST_EXT_STATE_IN_BYTES, tdvps_guest_extension_state_t);


/**
 * @struct tdvps_t
 *
 * @brief Holds the 6 pages of TDVPS. The pages need to be contiguous in physical memory
 */
typedef struct ALIGN(TDX_PAGE_SIZE_IN_BYTES) tdvps_s
{
    tdvps_ve_info_t                ve_info;
    uint8_t                        reserved_0[128]; /**< Reserved for aligning the next field */
    tdvps_management_t             management;
    tdvps_guest_state_t            guest_state;
    tdvps_guest_msr_state_t        guest_msr_state;

    uint8_t                        reserved_1[2432]; /**< Reserved for aligning the next field */

    tdvps_td_vmcs_t                td_vmcs;
    uint8_t                        reserved_2[TDX_PAGE_SIZE_IN_BYTES - SIZE_OF_TD_VMCS_IN_BYTES]; /**< Reserved for aligning the next field */

    tdvps_vapic_t                  vapic;
    tdvps_guest_extension_state_t  guest_extension_state;
} tdvps_t;
tdx_static_assert(sizeof(tdvps_t) == (MAX_TDVPS_PAGES*TDX_PAGE_SIZE_IN_BYTES), tdvps_t);
tdx_static_assert(offsetof(tdvps_t, ve_info) == OFFSET_OF_VE_INFO_STRUCT_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, guest_state) == OFFSET_OF_TDVPS_GUEST_STATE_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, guest_msr_state) == OFFSET_OF_TDVPS_GUEST_MSR_STATE_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, td_vmcs) == OFFSET_OF_TDVPS_TD_VMCS_IN_BYTES, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, vapic) == OFFSET_OF_TDVPS_VAPIC_STRUCT, tdvps_t);
tdx_static_assert(offsetof(tdvps_t, guest_extension_state) == OFFSET_OF_TDVPS_GUEST_EXT_STATE, tdvps_t);


#pragma pack(pop)

#endif /* SRC_COMMON_DATA_STRUCTURES_TDX_TDVPS_H_ */
