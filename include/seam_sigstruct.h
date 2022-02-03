// Intel Proprietary
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file seam_sigstruct.h
 * @brief SEAM signature structure
 */
#ifndef INCLUDE_SEAM_SIGSTRUCT_H_
#define INCLUDE_SEAM_SIGSTRUCT_H_

#define SIGSTRUCT_MODULUS_SIZE 384
#define SIGSTRUCT_SIGNATURE_SIZE 384
#define SIGSTRUCT_SEAMHASH_SIZE 48

#include "tdx_basic_types.h"
#include "debug/tdx_debug.h"

#pragma pack(push,1)

typedef struct
{
    uint32_t header;
    uint32_t header_length;
    uint32_t header_version;
    uint32_t module_type;
    uint32_t module_vendor;
    uint32_t date;
    uint32_t size;
    uint32_t key_size;
    uint32_t modulus_size;
    uint32_t exponent_size;
    uint8_t reserved0[88];

    uint8_t modulus[SIGSTRUCT_MODULUS_SIZE];
    uint32_t exponent;
    uint8_t signature[SIGSTRUCT_SIGNATURE_SIZE];

    uint8_t seamhash[SIGSTRUCT_SEAMHASH_SIZE];
    uint16_t seamsvn;
    uint64_t attributes;
    uint32_t rip_offset;
    uint8_t num_stack_pages;
    uint8_t num_tls_pages;
    uint16_t num_keyhole_pages;
    uint16_t num_global_data_pages;
    uint8_t reserved1[56];

    uint32_t cpuid_table_size;
    uint8_t cpuid_table[1020];

} seam_sigstruct_t;

#pragma pack(pop)

tdx_static_assert(sizeof(seam_sigstruct_t) == 2048, seam_sigstruct_t);

#endif /* INCLUDE_SEAM_SIGSTRUCT_H_ */
