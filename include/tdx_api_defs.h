// Intel Proprietary
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_api_defs.h
 * @brief TDX API Definitions
 */
#ifndef __TDX_API_DEFS_H_INCLUDED__
#define __TDX_API_DEFS_H_INCLUDED__

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"
#include "crypto/sha384.h"
#include "auto_gen/cpuid_configurations_defines.h"

#pragma pack(push)
#pragma pack(1)


/**< Enum for SEAMCALL leaves opcodes */
typedef enum
{
    TDH_VP_ENTER_LEAF             = 0,
    TDH_MNG_ADDCX_LEAF            = 1,
    TDH_MEM_PAGE_ADD_LEAF         = 2,
    TDH_MEM_SEPT_ADD_LEAF         = 3,
    TDH_VP_ADDCX_LEAF             = 4,
    TDH_MEM_PAGE_RELOCATE         = 5,
    TDH_MEM_PAGE_AUG_LEAF         = 6,
    TDH_MEM_RANGE_BLOCK_LEAF      = 7,
    TDH_MNG_KEY_CONFIG_LEAF       = 8,
    TDH_MNG_CREATE_LEAF           = 9,
    TDH_VP_CREATE_LEAF            = 10,
    TDH_MNG_RD_LEAF               = 11,
    TDH_MEM_RD_LEAF               = 12,
    TDH_MNG_WR_LEAF               = 13,
    TDH_MEM_WR_LEAF               = 14,
    TDH_MEM_PAGE_DEMOTE_LEAF      = 15,
    TDH_MR_EXTEND_LEAF            = 16,
    TDH_MR_FINALIZE_LEAF          = 17,
    TDH_VP_FLUSH_LEAF             = 18,
    TDH_MNG_VPFLUSHDONE_LEAF      = 19,
    TDH_MNG_KEY_FREEID_LEAF       = 20,
    TDH_MNG_INIT_LEAF             = 21,
    TDH_VP_INIT_LEAF              = 22,
    TDH_MEM_PAGE_PROMOTE_LEAF     = 23,
    TDH_PHYMEM_PAGE_RDMD_LEAF     = 24,
    TDH_MEM_SEPT_RD_LEAF          = 25,
    TDH_VP_RD_LEAF                = 26,
    TDH_MNG_KEY_RECLAIMID_LEAF    = 27,
    TDH_PHYMEM_PAGE_RECLAIM_LEAF  = 28,
    TDH_MEM_PAGE_REMOVE_LEAF      = 29,
    TDH_MEM_SEPT_REMOVE_LEAF      = 30,
    TDH_SYS_KEY_CONFIG_LEAF       = 31,
    TDH_SYS_INFO_LEAF             = 32,
    TDH_SYS_INIT_LEAF             = 33,
    TDH_SYS_LP_INIT_LEAF          = 35,
    TDH_SYS_TDMR_INIT_LEAF        = 36,
    TDH_MEM_TRACK_LEAF            = 38,
    TDH_MEM_RANGE_UNBLOCK_LEAF    = 39,
    TDH_PHYMEM_CACHE_WB_LEAF      = 40,
    TDH_PHYMEM_PAGE_WBINVD_LEAF   = 41,
    TDH_MEM_SEPT_WR_LEAF          = 42,
    TDH_VP_WR_LEAF                = 43,
    TDH_SYS_LP_SHUTDOWN_LEAF      = 44,
    TDH_SYS_CONFIG_LEAF           = 45

#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    ,TDDEBUGCONFIG_LEAF = 0xFE
#endif
} SEAMCALL_LEAVES_OPCODES;

/**< Enum for TDCALL leaves opcodes */
typedef enum
{
    TDG_VP_VMCALL_LEAF         = 0,
    TDG_VP_INFO_LEAF           = 1,
    TDG_MR_RTMR_EXTEND_LEAF    = 2,
    TDG_VP_VEINFO_GET_LEAF     = 3,
    TDG_MR_REPORT_LEAF         = 4,
    TDG_VP_CPUIDVE_SET_LEAF    = 5,
    TDG_MEM_PAGE_ACCEPT_LEAF   = 6,
    TDG_VM_RD                  = 7,
    TDG_VM_WR                  = 8

} TDCALL_LEAVES_OPCODES;

/**
 * @struct page_info_api_input_t
 *
 * @brief Input info for SEPT API calls.
 */
typedef union page_info_api_input_s {
    struct
    {
        uint64_t
            level          : 3,  /**< Level */
            reserved_0     : 9,  /**< Must be 0 */
            gpa            : 40, /**< GPA of the page */
            reserved_1     : 12;  /**< Must be 0 */
    };
    uint64_t raw;
} page_info_api_input_t;
tdx_static_assert(sizeof(page_info_api_input_t) == 8, page_info_api_input_t);


/**
 * @struct hkid_api_input_t
 *
 * @brief Input for HKID info
 */
typedef union hkid_api_input_s {
    struct
    {
        uint64_t
            hkid          : 16,  /**< HKID */
            reserved      : 48;  /**< Must be 0 */
    };
    uint64_t raw;
} hkid_api_input_t;
tdx_static_assert(sizeof(hkid_api_input_t) == 8, hkid_api_input_t);


#define PAMT_4K 0
#define PAMT_2M 1
#define PAMT_1G 2

/**
 * @struct page_size_api_input_t
 *
 * @brief Input for page size (level) info
 */
typedef union page_size_api_input_s {
    struct
    {
        uint64_t
            level         : 3,  /**< Level PAMT_4K=0, PAMT_2M=1, PAMT_1G=2 */
            reserved      : 61; /**< Must be 0 */
    };
    uint64_t raw;
} page_size_api_input_t;
tdx_static_assert(sizeof(page_size_api_input_t) == 8, page_size_api_input_t);

typedef enum
{
    TDVPS_VMCS_CLASS_CODE              = 0,
    TDVPS_VAPIC_CLASS_CODE             = 1,
    TDVPS_VE_INFO_CLASS_CODE           = 2,
    TDVPS_GUEST_GPR_STATE_CLASS_CODE   = 16,
    TDVPS_GUEST_OTHER_STATE_CLASS_CODE = 17,
    TDVPS_GUEST_EXT_STATE_CLASS_CODE   = 18,
    TDVPS_GUEST_MSR_STATE_CLASS_CODE   = 19,
    TDVPS_MANAGEMENT_CLASS_CODE        = 32
} tdvps_class_code_e;

typedef enum
{
    TDVPS_VCPU_STATE_DETAILS_FIELD_CODE = 0x00000100ULL,
    XFAM_FIELD_CODE                     = 0x0000000CULL
} tdvps_field_code_e;

typedef enum
{
    TDR_TD_MANAGEMENT_CLASS_CODE       = 0,
    TDR_KEY_MANAGEMENT_CLASS_CODE      = 1,
    TDCS_TD_MANAGEMENT_CLASS_CODE      = 16,
    TDCS_EXECUTION_CONTROLS_CLASS_CODE = 17,
    TDCS_TLB_EPOCH_TRACKING_CLASS_CODE = 18,
    TDCS_MEASUREMENT_CLASS_CODE        = 19,
    TDCS_MSR_BITMAPS_CLASS_CODE        = 32,
    TDCS_SEPT_ROOT_CLASS_CODE          = 33,
} tdr_tdcs_class_code_e;

typedef enum
{
    TDR_INIT_FIELD_CODE              = 0x8000000000000000ULL,
    TDR_FATAL_FIELD_CODE             = 0x8000000000000001ULL,
    TDR_NUM_TDCX_FIELD_CODE          = 0x8000000000000002ULL,
    TDR_CHLDCNT_FIELD_CODE           = 0x8000000000000004ULL,
    TDR_TDCX_PA_FIELD_CODE           = 0x8000000000000010ULL,

    TDR_LIFECYCLE_STATE_FIELD_CODE   = 0x8000000000000005ULL,
    TDR_HKID_FIELD_CODE              = 0x8100000000000001ULL,
    TDR_PKG_CONFIG_BITMAP_FIELD_CODE = 0x8100000000000002ULL
} tdr_base_field_code_e;

typedef enum
{
    TDCS_FINALIZED_FIELD_CODE          = 0x9000000000000000,
    TDCS_NUM_VCPUS_FIELD_CODE          = 0x9000000000000001,
    TDCS_NUM_ASSOC_VCPUS_FIELD_CODE    = 0x9000000000000002,
    TDCS_SECURE_EPT_LOCK_FIELD_CODE    = 0x9000000000000010,
    TDCS_EPOCH_LOCK_FIELD_CODE         = 0x9000000000000011,
    TDCS_RTMR_LOCK_FIELD_CODE          = 0x9000000000000012,

    TDCS_ATTRIBUTES_FIELD_CODE         = 0x1100000000000000,
    TDCS_XFAM_FIELD_CODE               = 0x1100000000000001,
    TDCS_MAX_VCPUS_FIELD_CODE          = 0x1100000000000002,
    TDCS_GPAW_FIELD_CODE               = 0x1100000000000003,
    TDCS_EPTP_FIELD_CODE               = 0x1100000000000004,
    TDCS_TSC_OFFSET_FIELD_CODE         = 0x110000000000000A,
    TDCS_TSC_MULTIPLIER_FIELD_CODE     = 0x110000000000000B,

    TDCS_TSC_FREQUENCY_FIELD_CODE      = 0x110000000000000C,

    TDCS_NOTIFY_ENABLES_FIELD_CODE     = 0x9100000000000010,

    TDCS_CPUID_VALUES_FIELD_CODE       = 0x9100000000000400,
    TDCS_XBUFF_OFFSETS_FIELD_CODE      = 0x1100000000000800,

    TDCS_TD_EPOCH_FIELD_CODE           = 0x9200000000000000,
    TDCS_REFCOUNT_FIELD_CODE           = 0x9200000000000001,

    TDCS_MRTD_FIELD_CODE               = 0x1300000000000000,
    TDCS_MRCONFIGID_FIELD_CODE         = 0x1300000000000010,
    TDCS_MROWNER_FIELD_CODE            = 0x1300000000000018,
    TDCS_MROWNERCONFIG_FIELD_CODE      = 0x1300000000000020,
    TDCS_RTMR_FIELD_CODE               = 0x1300000000000040,

    TDCS_MSR_BITMAPS_FIELD_CODE        = 0x2000000000000000,
    TDCS_SEPT_ROOT_FIELD_CODE          = 0x2100000000000000,
    TDCS_ZERO_PAGE_FIELD_CODE          = 0xA2000000FFFFFFFF

} tdcs_base_field_code_e;

/**
 * @struct tdvmcall_control_t - TDVMCALL RCX input parameter
 */
typedef union tdvmcall_control_u
{
    struct
    {
        uint16_t gpr_select;
        uint16_t xmm_select;
        uint32_t reserved;
    };
    uint64_t raw;
} tdvmcall_control_t;


/**
 * @struct vmcs_field_code_t
 */
typedef union vmcs_field_code_s {

    struct
    {
        uint32_t access_type : 1;
        uint32_t index       : 9;
        uint32_t type        : 2;
        uint32_t reserved0   : 1;
        uint32_t width       : 2;
        uint32_t reserved1   : 17;
    };

    uint32_t raw;
} vmcs_field_code_t;
tdx_static_assert(sizeof(vmcs_field_code_t) == 4, vmcs_field_code_t);

#define VMCS_FIELD_ACCESS_TYPE_FULL         0
#define VMCS_FIELD_ACCESS_TYPE_HIGH         1

#define VMCS_FIELD_WIDTH_16B                0
#define VMCS_FIELD_WIDTH_64B                1
#define VMCS_FIELD_WIDTH_32B                2
#define VMCS_FIELD_WIDTH_NATURAL            3


/**
 * @struct td_ctrl_struct_field_code_t
 *
 * @brief Input for TDR, TDCS and TDVPS read/write fields
 */
typedef union td_ctrl_struct_field_code_s {
    struct
    {
        union
        {
            vmcs_field_code_t vmcs_field_code; /**< For TD VMCS, this is the field code, as specified by the [Intel SDM] */
            uint32_t field_code;
        };
        uint32_t
            reserved    : 24, /**< Must be 0 */
            class_code  : 7,  /**< See tdvps_class_code_e and tdr_tdcs_class_code_e enum */
            non_arch    : 1;
    };
    uint64_t raw;
} td_ctrl_struct_field_code_t;
tdx_static_assert(sizeof(td_ctrl_struct_field_code_t) == 8, td_ctrl_struct_field_code_t);

/**
 * CPUID configurations
 */

typedef union
{
    struct
    {
        uint32_t leaf;     //0..31
        uint32_t subleaf;  //32..63
    };
    uint64_t raw;
} cpuid_config_leaf_subleaf_t;

typedef union
{
    struct
    {
        uint32_t eax;
        uint32_t ebx;
        uint32_t ecx;
        uint32_t edx;
    };
    struct
    {
        uint64_t low;
        uint64_t high;
    };
    uint32_t values[4];
} cpuid_config_return_values_t;

typedef struct
{
    cpuid_config_leaf_subleaf_t leaf_subleaf;
    cpuid_config_return_values_t values;
} cpuid_config_t;


tdx_static_assert(sizeof(cpuid_config_t) == 24, cpuid_config_t);



/**
 * @struct td_param_attributes_t
 *
 * @brief TD attributes.
 *
 * The value set in this field must comply with ATTRIBUTES_FIXED0 and ATTRIBUTES_FIXED1 enumerated by TDSYSINFO
 */
typedef union td_param_attributes_s {
    struct
    {
        uint64_t debug           : 1;   // Bit  0
        uint64_t reserved_tud    : 7;   // Bits 7:1
        uint64_t reserved_sec_1  : 20;  // Bits 27:8
        uint64_t sept_ve_disable : 1;   // Bit  28 - disable #VE on pending page access
        uint64_t reserved_sec_2  : 1;   // Bit  29
        uint64_t pks             : 1;   // Bit  30
        uint64_t kl              : 1;   // Bit  31
        uint64_t reserved_other  : 31;  // Bits 62:32
        uint64_t perfmon         : 1;   // Bit  63
    };
    uint64_t raw;
} td_param_attributes_t;
tdx_static_assert(sizeof(td_param_attributes_t) == 8, td_param_attributes_t);


/**
 * @struct eptp_controls_t
 *
 * @brief Control bits of EPTP, copied to each TD VMCS on TDHVPINIT
 */
typedef union eptp_controls_s {
    struct
    {
        uint64_t ept_ps_mt          : 3;   // Bits 0-2
        uint64_t ept_pwl            : 3;   // 1 less than the EPT page-walk length
        uint64_t enable_ad_bits     : 1;
        uint64_t enable_sss_control : 1;
        uint64_t reserved_0         : 4;
        uint64_t base_pa            : 40; // Root Secure-EPT page address
        uint64_t reserved_1         : 12;
    };
    uint64_t raw;
} eptp_controls_t;
tdx_static_assert(sizeof(eptp_controls_t) == 8, eptp_controls_t);


/**
 * @struct exec_controls_t
 *
 * @brief Non-measured TD-scope execution controls.
 *
 * Most fields are copied to each TD VMCS TSC-offset execution control on TDHVPINIT.
 */
typedef union exec_controls_s {
    struct
    {
        uint64_t
        gpaw                : 1,  /**< TD-scope Guest Physical Address Width execution control. */
        reserved            : 63; /**< Must be 0. */
    };
    uint64_t raw;
} exec_controls_t;
tdx_static_assert(sizeof(exec_controls_t) == 8, exec_controls_t);


#define SIZE_OF_TD_PARAMS_IN_BYTES     1024
#define TD_PARAMS_ALIGN_IN_BYTES       SIZE_OF_TD_PARAMS_IN_BYTES
#define SIZE_OF_SHA384_HASH_IN_QWORDS  6
#define SIZE_OF_SHA256_HASH_IN_QWORDS  4

#define TD_PARAMS_RESERVED0_SIZE       6

#define TD_PARAMS_RESERVED1_SIZE       38

#define TD_PARAMS_RESERVED2_SIZE       32
#define TD_PARAMS_RESERVED3_SIZE       672

/**
 * @struct td_params_t
 *
 * @brief TD_PARAMS is provided as an input to TDHMNGINIT, and some of its fields are included in the TD report.
 *
 * The format of this structure is valid for a specific MAJOR_VERSION of the TDX-SEAM module,
 * as reported by TDSYSINFO.
 */
typedef struct PACKED td_params_s
{
    td_param_attributes_t        attributes;
    /**
     * Extended Features Available Mask.
     * Indicates the extended state features allowed for the TD.
     * XFAM’s format is the same as XCR0 and IA32_XSS MSR
     */
    uint64_t                     xfam;
    uint16_t                     max_vcpus; /**< Maximum number of VCPUs */
    uint8_t                      reserved_0[TD_PARAMS_RESERVED0_SIZE]; /**< Must be 0 */
    eptp_controls_t              eptp_controls;
    exec_controls_t              exec_controls;


    uint16_t                     tsc_frequency;

    uint8_t                      reserved_1[TD_PARAMS_RESERVED1_SIZE]; /**< Must be 0 */

    /**
     * Software defined ID for additional configuration for the SW in the TD
     */
    measurement_t                mr_config_id;
    /**
     * Software defined ID for TD’s owner
     */
    measurement_t                mr_owner;
    /**
     * Software defined ID for TD’s owner configuration
     */
    measurement_t                mr_owner_config;

    uint8_t                      reserved_2[TD_PARAMS_RESERVED2_SIZE]; /**< Must be 0 */

    /**
     * CPUID leaves/sub-leaves configuration.
     * The number and order of entries must be equal to
     * the number and order of configurable CPUID leaves/sub-leaves reported by TDSYSINFO.
     * Note that the leaf and sub-leaf numbers are implicit.
     * Only bits that have been reported as 1 by TDSYSINFO may be set to 1.
     */
    cpuid_config_return_values_t cpuid_config_vals[MAX_NUM_CPUID_CONFIG];

    uint8_t                      reserved_3[TD_PARAMS_RESERVED3_SIZE];
} td_params_t;
tdx_static_assert(sizeof(td_params_t) == SIZE_OF_TD_PARAMS_IN_BYTES, td_params_t);



/**
 * @struct cmr_info_entry_t
 *
 * @brief CMR_INFO provides information about a Convertible Memory Range (CMR).
 *
 * As configured by BIOS and verified and stored securely by MCHECK.
 *
 */
typedef struct PACKED cmr_info_entry_s
{
    /**
     * Base address of the CMR.  Since a CMR is aligned on 4KB, bits 11:0 are always 0.
     */
    uint64_t  cmr_base;
    /**
     * Size of the CMR, in bytes.  Since a CMR is aligned on 4KB, bits 11:0 are always 0.
     * A value of 0 indicates a null entry.
     */
    uint64_t  cmr_size;
} cmr_info_entry_t;
tdx_static_assert(sizeof(cmr_info_entry_t) == 16, cmr_info_entry_t);

typedef union
{
    struct
    {
        uint32_t rsvd :31, debug_module :1;
    };
    uint32_t raw;
} tdsysinfo_attributes_t;


#define SIZE_OF_TDHSYSINFO_STRUCT_IN_BYTES      1024
#define OFFSET_OF_MEMORY_INFO_IN_TDHSYSINFO     32
#define OFFSET_OF_CONTROL_INFO_IN_TDHSYSINFO    48
#define OFFSET_OF_TD_CAPABILITIES_IN_TDHSYSINFO 64

/**
 * @struct td_sys_info_t
 *
 * @brief TDSYSINFO_STRUCT provides enumeration information about the TDX-SEAM module.
 *
 * It is an output of the SEAMCALL(TDSYSINFO) leaf function.
 *
 */
typedef struct PACKED td_sys_info_s
{
    /**
     * TDX Module Info
     */
    tdsysinfo_attributes_t attributes;
    uint32_t vendor_id; /**< 0x8086 for Intel */
    uint32_t build_date;
    uint16_t build_num;
    uint16_t minor_version;
    uint16_t major_version;
    uint8_t reserved_0[14]; /**< Must be 0 */

    /**
     * Memory Info
     */
    uint16_t max_tdmrs; /**< The maximum number of TDMRs supported. */
    uint16_t max_reserved_per_tdmr; /**< The maximum number of reserved areas per TDMR. */
    uint16_t pamt_entry_size; /**< The number of bytes that need to be reserved for the three PAMT areas. */
    uint8_t reserved_1[10]; /**< Must be 0 */

    /**
     * Control Struct Info
     */
    uint16_t tdcs_base_size; /**< Base value for the number of bytes required to hold TDCS. */
    uint8_t reserved_2[2]; /**< Must be 0 */
    uint16_t tdvps_base_size; /**< Base value for the number of bytes required to hold TDVPS. */
    /**
     * A value of 1 indicates that additional TDVPS bytes are required to hold extended state,
     * per the TD’s XFAM.
     * The host VMM can calculate the size using CPUID.0D.01.EBX.
     * A value of 0 indicates that TDVPS_BASE_SIZE already includes the maximum supported extended state.
     */
    bool_t tdvps_xfam_dependent_size;
    uint8_t reserved_3[9]; /**< Must be 0 */

    /**
     * TD Capabilities
     */
    uint64_t attributes_fixed0; /**< If bit X is 0 in ATTRIBUTES_FIXED0, it must be 0 in any TD’s ATTRIBUTES. */
    uint64_t attributes_fixed1; /**< If bit X is 1 in ATTRIBUTES_FIXED1, it must be 1 in any TD’s ATTRIBUTES. */
    uint64_t xfam_fixed0; /**< If bit X is 0 in XFAM_FIXED0, it must be 0 in any TD’s XFAM. */
    uint64_t xfam_fixed1; /**< If bit X is 1 in XFAM_FIXED1, it must be 1 in any TD’s XFAM. */

    uint8_t reserved_4[32]; /**< Must be 0 */

    uint32_t num_cpuid_config;
    cpuid_config_t cpuid_config_list[MAX_NUM_CPUID_CONFIG];
    uint8_t reserved_5[748];
} td_sys_info_t;

tdx_static_assert(offsetof(td_sys_info_t, max_tdmrs) == OFFSET_OF_MEMORY_INFO_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(offsetof(td_sys_info_t, tdcs_base_size) == OFFSET_OF_CONTROL_INFO_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(offsetof(td_sys_info_t, attributes_fixed0) == OFFSET_OF_TD_CAPABILITIES_IN_TDHSYSINFO, td_sys_info_t);
tdx_static_assert(sizeof(td_sys_info_t) == SIZE_OF_TDHSYSINFO_STRUCT_IN_BYTES, td_sys_info_t_incorrect_struct_size);


/**
 * @struct td_gpaw_t
 *
 * @brief Output info for TDGVPINFO API calls.
 */
typedef union td_gpaw_s {
    struct
    {
        uint64_t
            /**
             * The effective GPA width (in bits) for this TD (don’t confuse with MAXPA).
             * SHARED bit is at GPA bit GPAW-1.
             */
            gpaw         : 6,
            reserved     : 58;  /**< Reserved, always 0 */
    };
    uint64_t raw;
} td_gpaw_t;
tdx_static_assert(sizeof(td_gpaw_t) == 8, td_gpaw_t);


/**
 * @struct td_num_of_vcpus_t
 *
 * @brief Output info for TDGVPINFO API calls.
 */
typedef union td_num_of_vcpus_s {
    struct
    {
        uint64_t
            num_vcpus     : 32,  /**< Number of Virtual CPUs that are usable, i.e. either active or ready */
            max_vcpus     : 32;  /**< TD's maximum number of Virtual CPUs (provided as input to TDHMNGINIT) */
    };
    uint64_t raw;
} td_num_of_vcpus_t;
tdx_static_assert(sizeof(td_num_of_vcpus_t) == 8, td_num_of_vcpus_t);


#define TDX_REPORT_TYPE    0x81
#define TDX_REPORT_SUBTYPE 0
#define TDX_REPORT_VERSION 0

/**
 * @struct td_report_type_s
 *
 * @brief REPORTTYPE indicates the reported Trusted Execution Environment (TEE) type, sub-type and version.
 */
typedef union PACKED td_report_type_s
{
    struct
    {
        /**
         * Trusted Execution Environment (TEE) Type:
         *      0x00:   SGX
         *      0x7F-0x01:  Reserved (TEE implemented by CPU)
         *      0x80:   Reserved (TEE implemented by SEAM module)
         *      0x81:   TDX
         *      0xFF-0x82:  Reserved (TEE implemented by SEAM module)
         *
         */
        uint8_t type;
        uint8_t subtype; /**< TYPE-specific subtype */
        uint8_t version; /**< TYPE-specific version. */
        uint8_t reserved; /**< Must be zero */
    };
    uint32_t raw;
} td_report_type_t;
tdx_static_assert(sizeof(td_report_type_t) == 4, td_report_type_t);


#define CPUSVN_SIZE                       16 /**< CPUSVN is a 16B Security Version Number of the CPU. */
#define SIZE_OF_REPORTDATA_IN_BYTES       64
#define SIZE_OF_REPORTMAC_STRUCT_IN_BYTES 256

/**
 * @struct report_mac_struct_s
 *
 * @brief REPORTMACSTRUCT is common to all TEEs (SGX and TDX).
 */
typedef struct PACKED report_mac_struct_s
{
    td_report_type_t  report_type; /**< Type Header Structure */
    uint8_t           reserved_0[12]; /**< Must be 0 */
    uint8_t           cpusvn[CPUSVN_SIZE]; /**< CPU SVN */
    /**
     * SHA384 of TEETCBINFO for TEEs implemented using a SEAM
     */
    uint64_t          tee_tcb_info_hash[SIZE_OF_SHA384_HASH_IN_QWORDS];
    /**
     * SHA384 of TEEINFO, which is a TEE-specific info structure (TDINFO or SGXINFO), or 0 if no TEE is represented
     */
    uint64_t          tee_info_hash[SIZE_OF_SHA384_HASH_IN_QWORDS];
    /**
     * A set of data used for communication between the caller and the target.
     */
    uint8_t           report_data[SIZE_OF_REPORTDATA_IN_BYTES];
    uint8_t           reserved_1[32];
    uint64_t          mac[SIZE_OF_SHA256_HASH_IN_QWORDS]; /**< The MAC over the REPORTMACSTRUCT with model-specific MAC */
} report_mac_struct_t;
tdx_static_assert(sizeof(report_mac_struct_t) == SIZE_OF_REPORTMAC_STRUCT_IN_BYTES, report_mac_struct_t);


#define SIZE_OF_TEE_TCB_SVN_IN_BYTES         16
#define SIZE_OF_TEE_TCB_INFO_STRUCT_IN_BYTES 256

/**
 * @struct tee_tcb_info_t
 *
 * @brief
 */
typedef struct PACKED tee_tcb_info_s
{
    /**
     * Indicates TEE_TCB_INFO fields which are valid.
     * - 1 in the i-th significant bit reflects that the field starting at offset (8 * i)
     * - 0 in the i-th significant bit reflects that either no field starts at offset (8 * i)
     *   or that field is not populated and is set to zero.
     */
    uint64_t       valid;
    uint8_t        tee_tcb_svn[SIZE_OF_TEE_TCB_SVN_IN_BYTES];  /**< TEE_TCB_SVN Array */
    measurement_t  mr_seam;  /**< Measurement of the SEAM module */
    /**
     * Measurement of SEAM module signer if non-intel SEAM module was loaded
     */
    measurement_t  mr_signer_seam;
    uint64_t       attributes;  /**< Additional configuration ATTRIBUTES if non-intel SEAM module was loaded */
    uint8_t        reserved[128];  /**< Must be 0 */
} tee_tcb_info_t;
tdx_static_assert(sizeof(tee_tcb_info_t) == SIZE_OF_TEE_TCB_INFO_STRUCT_IN_BYTES, tee_tcb_info_t);


#define NUM_OF_RTMRS                    4
#define SIZE_OF_TD_INFO_STRUCT_IN_BYTES 512

/**
 * @struct td_info_s
 *
 * @brief TDINFO_STRUCT is the TDX-specific TEEINFO part of TDGMRREPORT.
 *
 * It contains the measurements and initial configuration of the TD that was locked at initialization,
 * and a set of measurement registers that are run-time extendible.
 * These values are copied from the TDCS by the TDGMRREPORT function.
 */
typedef struct PACKED td_info_s
{
    uint64_t       attributes; /**< TD’s ATTRIBUTES */
    uint64_t       xfam; /**< TD’s XFAM**/
    measurement_t  mr_td; /**< Measurement of the initial contents of the TD */
    /**
     * 48 Software defined ID for additional configuration for the software in the TD
     */
    measurement_t  mr_config_id;
    measurement_t  mr_owner; /**< Software defined ID for TD’s owner */
    /**
     * Software defined ID for owner-defined configuration of the guest TD,
     * e.g., specific to the workload rather than the runtime or OS.
     */
    measurement_t  mr_owner_config;
    measurement_t  rtmr[NUM_OF_RTMRS]; /**<  Array of NUM_RTMRS runtime extendable measurement registers */
    uint8_t        reserved[112];
} td_info_t;
tdx_static_assert(sizeof(td_info_t) == SIZE_OF_TD_INFO_STRUCT_IN_BYTES, td_info_t);


#define SIZE_OF_TD_REPORT_STRUCT_IN_BYTES 1024

/**
 * @struct td_report_t
 *
 * @brief TDREPORT_STRUCT is the output of the TDGMRREPORT function.
 *
 * If is composed of a generic MAC structure, a SEAMINFO structure and
 * a TDX-specific TEE info structure.
 */
typedef struct PACKED td_report_s
{
    report_mac_struct_t  report_mac_struct; /**< REPORTMACSTRUCT for the TDGMRREPORT */
    /**
     * Additional attestable elements in the TD’s TCB not reflected in the REPORTMACSTRUCT.CPUSVN.
     * Includes the SEAM measurements.
     */
    tee_tcb_info_t       tee_tcb_info;
    td_info_t            td_info; /**< TD’s attestable properties */
} td_report_t;
tdx_static_assert(sizeof(td_report_t) == SIZE_OF_TD_REPORT_STRUCT_IN_BYTES, td_report_t);


#define SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES 64

/**
 * @struct td_report_data_t
 *
 * @brief TDREPORTDATA is a set of data used for communication between the caller and the target of TDGMRREPORT
 *
 */
typedef struct PACKED td_report_data_s
{
    uint8_t              data[SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES];
} td_report_data_t;
tdx_static_assert(sizeof(td_report_data_t) == SIZE_OF_TD_REPORT_DATA_STRUCT_IN_BYTES, td_report_data_t);


#define TDH_PHYMEM_CACHEWB_START_CMD  0
#define TDH_PHYMEM_CACHEWB_RESUME_CMD 1

typedef union {
    uint64_t operand : 8,
             details : 24,
             cls     : 8,
             reserved: 22,
             recoverable: 1,
             error   : 1;
    uint64_t raw;
} api_error_code_t;

typedef uint64_t api_error_type;

_STATIC_INLINE_ api_error_type api_error_with_operand_id(api_error_type error, uint64_t operand_id)
{
    return error + operand_id;
}

_STATIC_INLINE_ api_error_type api_error_with_multiple_info(api_error_type error, uint8_t info_0,
                                                            uint8_t info_1, uint8_t info_2, uint8_t info_3)
{
    return error + (uint64_t)info_0 + ((uint64_t)info_1 << 8) + ((uint64_t)info_2 << 16) + ((uint64_t)info_3 << 24);
}



#define MAX_RESERVED_AREAS 16U

/**
 * @struct tdmr_info_entry_t
 *
 * @brief TDMR_INFO provides information about a TDMR and its associated PAMT
 *
 * An array of TDMR_INFO entries is passed as input to SEAMCALL(TDHSYSCONFIG) leaf function.
 *
 * - The TDMRs must be sorted from the lowest base address to the highest base address,
 *   and must not overlap with each other.
 *
 * - Within each TDMR entry, all reserved areas must be sorted from the lowest offset to the highest offset,
 *   and must not overlap with each other.
 *
 * - All TDMRs and PAMTs must be contained within CMRs.
 *
 * - A PAMT area must not overlap with another PAMT area (associated with any TDMR), and must not
 *   overlap with non-reserved areas of any TDMR. PAMT areas may reside within reserved areas of TDMRs.
 *
 */
typedef struct PACKED tdmr_info_entry_s
{
    uint64_t tdmr_base;    /**< Base address of the TDMR (HKID bits must be 0). 1GB aligned. */
    uint64_t tdmr_size;    /**< Size of the CMR, in bytes. 1GB aligned. */
    uint64_t pamt_1g_base; /**< Base address of the PAMT_1G range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_1g_size; /**< Size of the PAMT_1G range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_2m_base; /**< Base address of the PAMT_2M range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_2m_size; /**< Size of the PAMT_2M range associated with the above TDMR. 4K aligned. */
    uint64_t pamt_4k_base; /**< Base address of the PAMT_4K range associated with the above TDMR (HKID bits must be 0). 4K aligned. */
    uint64_t pamt_4k_size; /**< Size of the PAMT_4K range associated with the above TDMR. 4K aligned. */

    struct
    {
        uint64_t offset; /**< Offset of reserved range 0 within the TDMR. 4K aligned. */
        uint64_t size;   /**< Size of reserved range 0 within the TDMR. A size of 0 indicates a null entry. 4K aligned. */
    } rsvd_areas[MAX_RESERVED_AREAS];

} tdmr_info_entry_t;

#define TDMR_INFO_ENTRY_PTR_ARRAY_ALIGNMENT              512

#define TD_EXTENDED_STATE_NOT_PASSED_TO_VMM_AND_BACK     0ULL
#define TD_XMM_STATE_PASSED_TO_VMM_AND_BACK              2ULL



#define MAX_CMR             32
// check (MAX_CMRS * cmr_info_entry) equals 512B
tdx_static_assert((MAX_CMR * sizeof(cmr_info_entry_t)) == 512, MAX_CMR);

typedef union sys_attributes_u
{
    struct
    {
        uint64_t reserved : 64;
    };
    uint64_t raw;
} sys_attributes_t;

typedef union tdaccept_vmx_eeq_info_u
{
    struct
    {
        // ACCEPT requsted SEPT level
        uint32_t    req_sept_level   : 3;
        // Level in SEPT in which the error was detected
        uint32_t    err_sept_level   : 3;
        // TDX SEPT state of the entry in which the error was detected
        uint32_t    err_sept_state   : 8;
        // TDX SEPT state of the entry in which the error was detected
        uint32_t    err_sept_is_leaf : 1;
        uint32_t    rsvd             : 17;
    };

    uint32_t raw;
} tdaccept_vmx_eeq_info_t;
tdx_static_assert(sizeof(tdaccept_vmx_eeq_info_t) == 4, tdaccept_vmx_eeq_info_t);

#define NUM_CACHELINES_IN_PAGE 64
#define NUM_SEPT_ENTRIES_IN_CACHELINE 8
#define VCPU_NO_LP ((uint32_t)~0)

#pragma pack(pop)


#endif // __TDX_API_DEFS_H_INCLUDED__
