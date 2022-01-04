// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file vmcs_accessors.h
 * @brief VMCS Accessors Definitions
 */

#ifndef SRC_COMMON_ACCESSORS_VT_ACCESSORS_H_
#define SRC_COMMON_ACCESSORS_VT_ACCESSORS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "x86_defs/x86_defs.h"
#include "x86_defs/vmcs_defs.h"
#include "ia32_accessors.h"
#include "helpers/error_reporting.h"

typedef uint64_t vmcs_ptr_t;

/**
 * @brief Read from VMCS entry
 * @param encoding
 *
 * @return value
 */
_STATIC_INLINE_ bool_t ia32_try_vmread(uint64_t encoding, uint64_t *value) {
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmreadq %2,%0\n"
            "pushfq\n"
            "popq %1"
            : "=m"(*value), "=r"(rflags.raw)
            :"r"(encoding)
            :"memory", "cc");

    if (!(rflags.cf == 0 && rflags.zf == 0))
    {
        return false;
    }

    return true;
}

/**
 * @brief Write to VMCS entry
 * @param encoding
 * @param value
 * @return
 */
_STATIC_INLINE_ bool_t ia32_try_vmwrite(uint64_t encoding, uint64_t value)
{
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmwriteq %1,%2\n"
            "pushfq\n"
            "popq %0"
            : "=r"(rflags.raw)
            :"r"(value), "r"(encoding)
            : "cc");

    if (!(rflags.cf == 0 && rflags.zf == 0))
    {
        return false;
    }

    return true;
}

/**
 * @brief Read from VMCS entry
 * @param encoding
 *
 * @return value
 */
_STATIC_INLINE_ void ia32_vmread(uint64_t encoding, uint64_t *value) {
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmreadq %2,%0\n"
			"pushfq\n"
			"popq %1"
			: "=m"(*value), "=r"(rflags.raw)
			:"r"(encoding)
			:"memory", "cc");

	tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), SCEC_VT_ACCESSORS_SOURCE, (uint32_t)encoding);
}

/**
 * @brief Write to VMCS entry
 * @param encoding
 * @param value
 * @return
 */
_STATIC_INLINE_ void ia32_vmwrite(uint64_t encoding, uint64_t value)
{
    //According to SDM, in 64-bit mode the instruction will fail is given an
    //operand that sets encoding bit beyond 32-bit
    tdx_debug_assert(encoding < BIT(32));

    //asm instruction expects both operands to be 64bit.
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ ("vmwriteq %1,%2\n"
			"pushfq\n"
			"popq %0"
			: "=r"(rflags.raw)
            :"r"(value), "r"(encoding)
            : "cc");

	tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), SCEC_VT_ACCESSORS_SOURCE, (uint32_t)encoding);
}

/**
 * @brief Launch Virtual Machine
 */
_STATIC_INLINE_ void ia32_vmlaunch(void) {
	_ASM_VOLATILE_ ("vmlaunch":::"memory" , "cc");
}

/**
 * @brief Resume Virtual Machine
 */
_STATIC_INLINE_ void ia32_vmresume(void) {
	_ASM_VOLATILE_ ("vmresume":::"memory" , "cc");
}

/**
 * @brief Clear VMCS
 * @param vmcs_p
 */
_STATIC_INLINE_ void ia32_vmclear(vmcs_ptr_t *vmcs_p) {
	_ASM_VOLATILE_ ("vmclear %0"::"m"(vmcs_p):"memory" , "cc");
}

/**
 * @brief Load pointer to VMCS
 * @param vmcs_p
 */
_STATIC_INLINE_ void ia32_vmptrld(vmcs_ptr_t *vmcs_p) {
    ia32_rflags_t rflags;
	_ASM_VOLATILE_ ("vmptrld %1\n"
                    "pushfq\n"
                    "popq %0\n"
                    : "=r"(rflags.raw)
	                :"m"(vmcs_p):"memory" , "cc");

	// Runtime assert - VMPTRLD should always succeed
	tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), SCEC_VT_ACCESSORS_SOURCE, 2);
}

/**
 * @brief Store pointer to VMCS
 * @param vmcs_p
 */
_STATIC_INLINE_ uint64_t ia32_vmptrst(void) {
    uint64_t ptr;
    _ASM_VOLATILE_ ("vmptrst %0"::"m"(ptr):"memory" , "cc");

    return ptr;
}

/**
 * @brief Invalidate EPT translations
 * @param ept_descriptor
 * @param instruction
 * @return
 */
_STATIC_INLINE_ void ia32_invept(const ept_descriptor_t * ept_descriptor, uint64_t instruction)
{
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ (
            "invept %1,%2\n"
            "pushfq\n"
            "popq %0"
            : "=r"(rflags.raw)
            : "m"(*ept_descriptor), "r"(instruction)
            :"memory", "cc");

    tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), SCEC_VT_ACCESSORS_SOURCE, 3);
}

/**
 * SEAM ACCESSOR
 */

_STATIC_INLINE_ void ia32_seamret(uint64_t errorcode) {
	_ASM_VOLATILE_ (
#ifdef SEAM_INSTRUCTIONS_SUPPORTED_IN_COMPILER
			"seamret;"
#else
			".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCD;"
#endif
			::"a"(errorcode):);
}

_STATIC_INLINE_ void ia32_seamops_seamreport(void* report_struct_la,
                                             void* report_data_la,
                                             void* tee_info_hash_la,
                                             uint32_t report_type)
{
    uint64_t leaf = 1; // for SEAMREPORT
    ia32_rflags_t rflags;
    _ASM_VOLATILE_ (
            "movq %3, %%r8\n"
            "movq %4, %%r9\n"
#ifdef SEAM_INSTRUCTIONS_SUPPORTED_IN_COMPILER
            "seamops;"
#else
            ".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCE;"
#endif
            "pushfq\n"
            "popq %0"
            : "=r"(rflags.raw)
            :"a"(leaf), "c"(report_struct_la), "r"(report_data_la), "r"(tee_info_hash_la), "d"(report_type)
            :"memory", "cc", "r8", "r9");

    tdx_sanity_check((rflags.cf == 0 && rflags.zf == 0), SCEC_VT_ACCESSORS_SOURCE, 4);
}

_STATIC_INLINE_ uint64_t ia32_seamops_capabilities(void)
{
    uint64_t leaf = 0; // for CAPABILITES
    uint64_t capabilities = 0;

    _ASM_VOLATILE_ (
#ifdef SEAM_INSTRUCTIONS_SUPPORTED_IN_COMPILER
            "seamops;"
#else
            ".byte 0x66; .byte 0x0F; .byte 0x01; .byte 0xCE;"
#endif
            :"=a"(capabilities) : "a"(leaf)
            :"memory", "cc");

    return capabilities;
}

#endif /* SRC_COMMON_ACCESSORS_VT_ACCESSORS_H_ */
