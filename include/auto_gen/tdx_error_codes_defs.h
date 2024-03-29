// Intel Proprietary
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 *  This File is Automatically generated by the TDX xls extract tool
 *  based on architecture commit id "e55731a6" 
 *  Spreadsheet Format Version - '3'
 **/

#ifndef _AUTO_GEN_ERROR_CODES_H_
#define _AUTO_GEN_ERROR_CODES_H_

typedef enum
{
  TDX_SUCCESS                             = 0x0000000000000000,
  TDX_NON_RECOVERABLE_VCPU                = 0x4000000100000000,
  TDX_NON_RECOVERABLE_TD                  = 0x4000000200000000,
  TDX_INTERRUPTED_RESUMABLE               = 0x8000000300000000,
  TDX_INTERRUPTED_RESTARTABLE             = 0x8000000400000000,
  TDX_NON_RECOVERABLE_TD_FATAL            = 0x4000000500000000,
  TDX_INVALID_RESUMPTION                  = 0xC000000600000000,
  TDX_NON_RECOVERABLE_TD_WRONG_APIC_MODE  = 0xC000000700000000,
  TDX_OPERAND_INVALID                     = 0xC000010000000000,
  TDX_OPERAND_ADDR_RANGE_ERROR            = 0xC000010100000000,
  TDX_OPERAND_BUSY                        = 0x8000020000000000,
  TDX_PREVIOUS_TLB_EPOCH_BUSY             = 0x8000020100000000,
  TDX_SYS_BUSY                            = 0x8000020200000000,
  TDX_PAGE_METADATA_INCORRECT             = 0xC000030000000000,
  TDX_PAGE_ALREADY_FREE                   = 0x0000030100000000,
  TDX_PAGE_NOT_OWNED_BY_TD                = 0xC000030200000000,
  TDX_PAGE_NOT_FREE                       = 0xC000030300000000,
  TDX_TD_ASSOCIATED_PAGES_EXIST           = 0xC000040000000000,
  TDX_SYS_INIT_NOT_PENDING                = 0xC000050000000000,
  TDX_SYS_LP_INIT_NOT_DONE                = 0xC000050200000000,
  TDX_SYS_LP_INIT_DONE                    = 0xC000050300000000,
  TDX_SYS_NOT_READY                       = 0xC000050500000000,
  TDX_SYS_SHUTDOWN                        = 0xC000050600000000,
  TDX_SYS_KEY_CONFIG_NOT_PENDING          = 0xC000050700000000,
  TDX_SYS_LP_INIT_NOT_PENDING             = 0xC000050B00000000,
  TDX_SYS_CONFIG_NOT_PENDING              = 0xC000050C00000000,
  TDX_TD_NOT_INITIALIZED                  = 0xC000060000000000,
  TDX_TD_INITIALIZED                      = 0xC000060100000000,
  TDX_TD_NOT_FINALIZED                    = 0xC000060200000000,
  TDX_TD_FINALIZED                        = 0xC000060300000000,
  TDX_TD_FATAL                            = 0xC000060400000000,
  TDX_TD_NON_DEBUG                        = 0xC000060500000000,
  TDX_LIFECYCLE_STATE_INCORRECT           = 0xC000060700000000,
  TDX_TDCX_NUM_INCORRECT                  = 0xC000061000000000,
  TDX_VCPU_STATE_INCORRECT                = 0xC000070000000000,
  TDX_VCPU_ASSOCIATED                     = 0x8000070100000000,
  TDX_VCPU_NOT_ASSOCIATED                 = 0x8000070200000000,
  TDX_TDVPX_NUM_INCORRECT                 = 0xC000070300000000,
  TDX_NO_VALID_VE_INFO                    = 0xC000070400000000,
  TDX_MAX_VCPUS_EXCEEDED                  = 0xC000070500000000,
  TDX_TSC_ROLLBACK                        = 0xC000070600000000,
  TDX_FIELD_NOT_WRITABLE                  = 0xC000072000000000,
  TDX_FIELD_NOT_READABLE                  = 0xC000072100000000,
  TDX_TD_VMCS_FIELD_NOT_INITIALIZED       = 0xC000073000000000,
  TDX_KEY_GENERATION_FAILED               = 0x8000080000000000,
  TDX_TD_KEYS_NOT_CONFIGURED              = 0x8000081000000000,
  TDX_KEY_STATE_INCORRECT                 = 0xC000081100000000,
  TDX_KEY_CONFIGURED                      = 0x0000081500000000,
  TDX_WBCACHE_NOT_COMPLETE                = 0x8000081700000000,
  TDX_HKID_NOT_FREE                       = 0xC000082000000000,
  TDX_NO_HKID_READY_TO_WBCACHE            = 0x0000082100000000,
  TDX_WBCACHE_RESUME_ERROR                = 0xC000082300000000,
  TDX_FLUSHVP_NOT_DONE                    = 0x8000082400000000,
  TDX_NUM_ACTIVATED_HKIDS_NOT_SUPPORTED   = 0xC000082500000000,
  TDX_INCORRECT_CPUID_VALUE               = 0xC000090000000000,
  TDX_BOOT_NT4_SET                        = 0xC000090100000000,
  TDX_INCONSISTENT_CPUID_FIELD            = 0xC000090200000000,
  TDX_CPUID_MAX_SUBLEAVES_UNRECOGNIZED    = 0xC000090300000000,
  TDX_CPUID_LEAF_1F_FORMAT_UNRECOGNIZED   = 0xC000090400000000,
  TDX_INVALID_WBINVD_SCOPE                = 0xC000090500000000,
  TDX_INVALID_PKG_ID                      = 0xC000090600000000,
  TDX_CPUID_LEAF_NOT_SUPPORTED            = 0xC000090800000000,
  TDX_SMRR_NOT_LOCKED                     = 0xC000091000000000,
  TDX_INVALID_SMRR_CONFIGURATION          = 0xC000091100000000,
  TDX_SMRR_OVERLAPS_CMR                   = 0xC000091200000000,
  TDX_SMRR_LOCK_NOT_SUPPORTED             = 0xC000091300000000,
  TDX_SMRR_NOT_SUPPORTED                  = 0xC000091400000000,
  TDX_INCONSISTENT_MSR                    = 0xC000092000000000,
  TDX_INCORRECT_MSR_VALUE                 = 0xC000092100000000,
  TDX_SEAMREPORT_NOT_AVAILABLE            = 0xC000093000000000,
  TDX_INVALID_TDMR                        = 0xC0000A0000000000,
  TDX_NON_ORDERED_TDMR                    = 0xC0000A0100000000,
  TDX_TDMR_OUTSIDE_CMRS                   = 0xC0000A0200000000,
  TDX_TDMR_ALREADY_INITIALIZED            = 0x00000A0300000000,
  TDX_INVALID_PAMT                        = 0xC0000A1000000000,
  TDX_PAMT_OUTSIDE_CMRS                   = 0xC0000A1100000000,
  TDX_PAMT_OVERLAP                        = 0xC0000A1200000000,
  TDX_INVALID_RESERVED_IN_TDMR            = 0xC0000A2000000000,
  TDX_NON_ORDERED_RESERVED_IN_TDMR        = 0xC0000A2100000000,
  TDX_CMR_LIST_INVALID                    = 0xC0000A2200000000,
  TDX_EPT_WALK_FAILED                     = 0xC0000B0000000000,
  TDX_EPT_ENTRY_FREE                      = 0xC0000B0100000000,
  TDX_EPT_ENTRY_NOT_FREE                  = 0xC0000B0200000000,
  TDX_EPT_ENTRY_NOT_PRESENT               = 0xC0000B0300000000,
  TDX_EPT_ENTRY_NOT_LEAF                  = 0xC0000B0400000000,
  TDX_EPT_ENTRY_LEAF                      = 0xC0000B0500000000,
  TDX_GPA_RANGE_NOT_BLOCKED               = 0xC0000B0600000000,
  TDX_GPA_RANGE_ALREADY_BLOCKED           = 0x00000B0700000000,
  TDX_TLB_TRACKING_NOT_DONE               = 0xC0000B0800000000,
  TDX_EPT_INVALID_PROMOTE_CONDITIONS      = 0xC0000B0900000000,
  TDX_PAGE_ALREADY_ACCEPTED               = 0x00000B0A00000000,
  TDX_PAGE_SIZE_MISMATCH                  = 0xC0000B0B00000000,
  UNINITIALIZE_ERROR                      = 0xFFFFFFFFFFFFFFFF
} api_error_code_e;

typedef enum
{
  OPERAND_ID_RAX           = 0,
  OPERAND_ID_RCX           = 1,
  OPERAND_ID_RDX           = 2,
  OPERAND_ID_RBX           = 3,
  OPERAND_ID_Reserved_RSP  = 4,
  OPERAND_ID_RBP           = 5,
  OPERAND_ID_RSI           = 6,
  OPERAND_ID_RDI           = 7,
  OPERAND_ID_R8            = 8,
  OPERAND_ID_R9            = 9,
  OPERAND_ID_R10           = 10,
  OPERAND_ID_R11           = 11,
  OPERAND_ID_R12           = 12,
  OPERAND_ID_R13           = 13,
  OPERAND_ID_R14           = 14,
  OPERAND_ID_R15           = 15,
  OPERAND_ID_ATTRIBUTES    = 64,
  OPERAND_ID_XFAM          = 65,
  OPERAND_ID_EXEC_CONTROLS = 66,
  OPERAND_ID_EPTP_CONTROLS = 67,
  OPERAND_ID_MAX_VCPUS     = 68,
  OPERAND_ID_CPUID_CONFIG  = 69,
  OPERAND_ID_TSC_FREQUENCY = 70,
  OPERAND_ID_TDMR_INFO_PA  = 96,
  OPERAND_ID_TDR           = 128,
  OPERAND_ID_TDCX          = 129,
  OPERAND_ID_TDVPR         = 130,
  OPERAND_ID_TDVPX         = 131,
  OPERAND_ID_TDCS          = 144,
  OPERAND_ID_TDVPS         = 145,
  OPERAND_ID_SEPT          = 146,
  OPERAND_ID_RTMR          = 168,
  OPERAND_ID_TD_EPOCH      = 169,
  OPERAND_ID_SYS           = 184,
  OPERAND_ID_TDMR          = 185,
  OPERAND_ID_KOT           = 186,
  OPERAND_ID_KET           = 187,
  OPERAND_ID_WBCACHE       = 188
} api_error_operand_id_e;

#endif /* _AUTO_GEN_ERROR_CODES_H_ */
