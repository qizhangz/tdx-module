// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/*
 * smrrs.h
 *
 *  Created on: 6 Mar 2019
 *      Author: pstedev
 */

#ifndef SRC_COMMON_HELPERS_SMRRS_H_
#define SRC_COMMON_HELPERS_SMRRS_H_

#include "tdx_basic_types.h"

#define MTRR_CAP_MSR_ADDR 0xFE

typedef union ia32_mtrrcap_u
{
    struct
    {
        uint64_t vcnt       : 8,  // 0-7
                 fix        : 1,  // 8
                 rsvd1      : 1,  // 9
                 wc         : 1,  // 10
                 smrr       : 1,  // 11
                 prmrr      : 1,  // 12
                 smrr2      : 1,  // 13
                 smrr_lock  : 1,  // 14
                 seamrr     : 1,  // 15
                 rsvd2      : 48; // 16-64
    };
    uint64_t raw;
} ia32_mtrrcap_t;

#define SMRR_BASE_MSR_ADDR 0x1F2
#define SMRR_MASK_MSR_ADDR 0x1F3

#define SMRR2_BASE_MSR_ADDR 0x1F6
#define SMRR2_MASK_MSR_ADDR 0x1F7

typedef union
{
    struct
    {
        uint64_t rsvd0 :10, // Bits 0-9
                 lock  :1,  // Bit 10
                 vld   :1,  // Bit 11
                 mask  :20, // Bits 12-31
                 rsvd1 :32; // Bits 32-63
    };
    uint64_t raw;
} smrr_mask_t;

typedef union
{
    struct
    {
        uint64_t memtype :8, rsvd0 :4, base :20, rsvd1 :32;
    };
    uint64_t raw;
} smrr_base_t;

typedef struct
{
    smrr_base_t smrr_base;
    smrr_mask_t smrr_mask;
} smrr_range_t;


#endif /* SRC_COMMON_HELPERS_SMRRS_H_ */
