// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file loader_data.h
 * @brief SEAMLDR interface structures
 */

#ifndef SRC_COMMON_DATA_STRUCTURES_LOADER_DATA_H_
#define SRC_COMMON_DATA_STRUCTURES_LOADER_DATA_H_

#include "tdx_basic_types.h"
#include "tdx_api_defs.h"

#define STACK_CANARY_OFFSET 0x28

/**
 * @struct sysinfo_table_t
 *
 * @brief Holds a SYSINFO table representation that is filled by the SEAMLDR
 *
 */
typedef struct PACKED sysinfo_table_s
{
    union
    {
        struct
        {
            // Fields populated by MCHECK
            uint64_t version;               /**< Structure Version – Set to 0 */
            uint32_t tot_num_lps;           /**< Total number of logical processors in platform */
            uint32_t tot_num_sockets;       /**< Total number of sockets in platform */
            fms_info_t socket_cpuid_table[MAX_PKGS]; /**< List of CPUID.leaf_1.EAX values from all sockets */
            uint8_t reserved_0[16];         /**< Reserved */
            bool_t smrr2_not_supported;
            bool_t tdx_without_integrity;
            uint8_t reserved_1[62];         /**< Reserved */
        } mcheck_fields;
        struct
        {
            //  SYS_INFO_TABLE information is saved to the last global data page (without corrupting the StackCanary field)
            uint8_t  reserved_1[STACK_CANARY_OFFSET];

            uint64_t canary; // Offset 0x28 of the last data page
        } stack_canary;
    };

    cmr_info_entry_t cmr_data[MAX_CMR]; /**< CMR info (base and size) */
    uint8_t reserved_2[1408];       /**< Reserved */

    // Fields initialized to zero by MCHECK and populated by SEAMLDR ACM
    uint64_t seam_status;           /**< SEAM status */
                                    /**< 0: NOT_LOADED   - module not loaded */
                                    /**< 1: LOADED       - module load complete */
                                    /**< 2: LOAD_IN_PROG - module load in progress */
    uint64_t code_rgn_base;         /**< Base address of Code region */
    uint64_t code_rgn_size;         /**< Size of code region in bytes */
    uint64_t data_rgn_base;         /**< Base address of Data region */
    uint64_t data_rgn_size;         /**< Size of data region in bytes */
    uint64_t stack_rgn_base;        /**< Base address of stack region */
    uint64_t stack_rgn_size;        /**< Size of Stack Region in bytes */
    uint64_t keyhole_rgn_base;      /**< Base address of Keyhole region */
    uint64_t keyhole_rgn_size;      /**< Size of the Keyhole region in bytes */
    uint64_t keyhole_edit_rgn_base; /**< Keyhole Edit Region Base */
    uint64_t keyhole_edit_rgn_size; /**< Size of Keyhole Edit Region in bytes */
    uint64_t num_stack_pages;       /**< Data Stack size per thread unit=(# 4K pages) – 1 */
    uint64_t num_tls_pages;         /**< TLS size per thread - unit=(# 4K pages) – 1 */
    uint64_t shutdown_host_rip;     /**< RIP to program into SEAM_CVP on shutdown */
    uint8_t reserved_3[1936];       /**< Reserved */

} sysinfo_table_t;
tdx_static_assert(sizeof(sysinfo_table_t) == TDX_PAGE_SIZE_IN_BYTES, sysinfo_table_t);



#endif /* SRC_COMMON_DATA_STRUCTURES_LOADER_DATA_H_ */
