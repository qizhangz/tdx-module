// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file ia32_accessors.h
 * @brief IA32 Accessors Definitions
 */

#ifndef SRC_COMMON_ACCESSORS_IA32_ACCESSORS_H_
#define SRC_COMMON_ACCESSORS_IA32_ACCESSORS_H_

#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"
#include "helpers/error_reporting.h"

#include "x86_defs/mktme.h"
#include "x86_defs/x86_defs.h"

/**
 * @brief Invalidate TLB entries by calling INVLPG instruction
 * @param addr
 */
_STATIC_INLINE_ void ia32_invalidate_tlb_entries(uint64_t addr)
{
	_ASM_VOLATILE_ ("invlpg (%0);"::"r"(addr):"memory");
}

/**
 * @brief Call CPUID instruction
 * @param leaf
 * @param subleaf
 * @param eax
 * @param ebx
 * @param ecx
 * @param edx
 */
_STATIC_INLINE_ void ia32_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{

	_ASM_VOLATILE_ ("cpuid;"              // CPUID
                     : "=a" (*eax),        // Outputs: eax = %eax
                       "=b" (*ebx),        //          ebx = %ebx
                       "=c" (*ecx),        //          ecx = %ecx
                       "=d" (*edx)         //          edx = %edx
                     : "a"  (leaf),        // Inputs:  eax = leaf
                       "c"  (subleaf) );   //          ecx = subleaf
}

_STATIC_INLINE_ void ia32_clear_ac( void )
{
	_ASM_VOLATILE_ ("clac;":::"cc");
}

_STATIC_INLINE_ void ia32_set_ac( void )
{
	_ASM_VOLATILE_ ("stac;":::"cc");
}

/**
 * @brief issue PCONFIG command to program MKTME keys
 * @param key_program_addr
 * @return
 */
_STATIC_INLINE_ uint64_t ia32_mktme_key_program(mktme_key_program_t *key_program_addr)
{
    ia32_rflags_t ret_flags;
    uint64_t error_code;
    _ASM_VOLATILE_ (
        #ifdef PCONFIG_SUPPORTED_IN_COMPILER
            "pconfig;"
        #else
            ".byte 0x0F\n"
            ".byte 0x01\n"
            ".byte 0xC5\n"
        #endif
        "pushfq\n"
        "popq %%rcx"
        : "=a"(error_code), "=c"(ret_flags.raw) : "a"(0), "b"(key_program_addr) : "cc");
    // On return: ZF=0 indicates success; ZF=1 indicates failure (error code in RAX).  ZF is bit 6 in EFLAGS
    return (ret_flags.zf) ? error_code : 0;
}

/**
 * @brief Call WMINVD instruction
 */
_STATIC_INLINE_ void ia32_wbinvd( void )
{
	_ASM_VOLATILE_ ("wbinvd" ::: "memory" ) ;
}

/**
 * @brief call HLT instruction
 * @param leaf
 * @param id
 */
_STATIC_INLINE_ void ia32_hlt( uint64_t leaf, uint64_t id )
{
	_ASM_VOLATILE_ ("hlt" :: "a"(leaf), "b"(id): "memory") ;
}

/**
 * @brief Call UD2 instruction
 */
_STATIC_INLINE_ void ia32_ud2( void )
{
    _ASM_VOLATILE_ ("ud2" ::: "memory") ;
}

_STATIC_INLINE_ uint64_t ia32_rdmsr(uint64_t addr)
{
    uint32_t low,high;
    _ASM_VOLATILE_ ("rdmsr" : "=a"(low), "=d"(high) : "c"(addr));
    return (uint64_t)((((uint64_t)(high)) << 32) | (uint64_t)(low));
}

_STATIC_INLINE_ void ia32_wrmsr(uint64_t addr, uint64_t value)
{
    _ASM_VOLATILE_ ("wrmsr" : : "a"((uint32_t)value), "d"((uint32_t)(value >> 32)), "c"(addr));
}

_STATIC_INLINE_ void ia32_out16(uint16_t port, uint16_t val)
{
    _ASM_VOLATILE_ ("outw %0,%w1" : : "a" (val), "dN" (port));
}

_STATIC_INLINE_ void ia32_pause( void )
{
    _ASM_VOLATILE_ ("pause" ) ;
}

_STATIC_INLINE_ void ia32_out8(uint16_t port, uint8_t val)
{
    _ASM_VOLATILE_ ("outb %0,%w1" : : "a" (val), "dN" (port));
}

_STATIC_INLINE_ uint8_t ia32_in8(uint16_t port)
{
    uint8_t v;

    _ASM_VOLATILE_ ("inb %w1,%0" : "=a" (v) : "Nd" (port));

    return v;
}

_STATIC_INLINE_ bool_t ia32_rdrand(ia32_rflags_t* rflags, uint64_t* rand)
{
    _ASM_VOLATILE_ ("rdrand %0 \n"
                    "pushfq; popq %1\n"
                    : "=r"(*rand) , "=r"(rflags->raw));

    if (!rflags->cf)
    {
        return false;
    }
    return true;
}

_STATIC_INLINE_ uint64_t ia32_rdtsc( void )
{
    uint32_t a, d;

    _ASM_VOLATILE_ ("rdtsc"
                   : "=a"(a), "=d"(d));
    return ( ((uint64_t) d << 32) | (uint64_t) a );
}

_STATIC_INLINE_ uint64_t ia32_set_timeout(uint64_t period)
{
    return ia32_rdtsc() + period;
}

_STATIC_INLINE_ bool_t ia32_is_timeout_expired(uint64_t endtime)
{
    return (int64_t)(endtime - ia32_rdtsc()) < 0;
}
/**
 * Extended State operations
 */
_STATIC_INLINE_ uint64_t ia32_xgetbv(uint64_t xcr)
{
    uint32_t low,high;
    _ASM_VOLATILE_ ("xgetbv" : "=a"(low), "=d"(high) : "c"(xcr));
    return (uint64_t)(((uint64_t)(high) << 32) | (uint64_t)(low));
}

_STATIC_INLINE_ void ia32_xsetbv(uint64_t xcr, uint64_t value)
{
    _ASM_VOLATILE_ ("xsetbv" : : "a"((uint32_t)value), "d"((uint32_t)(value >> 32)), "c"(xcr));
}

_STATIC_INLINE_ void ia32_xsaves(void* xsave_area, uint64_t xfam)
{
    _ASM_VOLATILE_ ( "xsaves %0 \n" : "=m"(*((uint64_t *)xsave_area)) : "d"((uint32_t)(xfam >> 32)),
            "a"((uint32_t)xfam) : "memory");
}


_STATIC_INLINE_ void ia32_xrstors(const void* xsave_area, uint64_t xfam)
{
    _ASM_VOLATILE_ (
        "xrstors %0 \n"
        :
        : "m"(*(uint64_t*)xsave_area), "a"((uint32_t)xfam), "d"((uint32_t)(xfam >> 32))
        : "memory");
}

_STATIC_INLINE_ void ia32_load_cr2(uint64_t cr2)
{
    _ASM_VOLATILE_ ("mov %0, %%cr2" : : "r" (cr2));
}

_STATIC_INLINE_ void ia32_load_cr8(uint64_t cr8)
{
    _ASM_VOLATILE_ ("mov %0, %%cr8" : : "r" (cr8));
}

_STATIC_INLINE_ void ia32_load_dr0(uint64_t dr0)
{
    _ASM_VOLATILE_ ("mov %0, %%dr0" : : "r" (dr0));
}

_STATIC_INLINE_ void ia32_load_dr1(uint64_t dr1)
{
    _ASM_VOLATILE_ ("mov %0, %%dr1" : : "r" (dr1));
}

_STATIC_INLINE_ void ia32_load_dr2(uint64_t dr2)
{
    _ASM_VOLATILE_ ("mov %0, %%dr2" : : "r" (dr2));
}

_STATIC_INLINE_ void ia32_load_dr3(uint64_t dr3)
{
    _ASM_VOLATILE_ ("mov %0, %%dr3" : : "r" (dr3));
}

_STATIC_INLINE_ void ia32_load_dr6(uint64_t dr6)
{
    _ASM_VOLATILE_ ("mov %0, %%dr6" : : "r" (dr6));
}

_STATIC_INLINE_ uint64_t ia32_store_cr2(void)
{
    uint64_t cr2;
    _ASM_VOLATILE_ ("mov %%cr2, %0" :  "=r" (cr2));
    return cr2;
}

_STATIC_INLINE_ uint64_t ia32_store_cr8(void)
{
    uint64_t cr8;
    _ASM_VOLATILE_ ("mov %%cr8, %0" : "=r" (cr8));
    return cr8;
}

_STATIC_INLINE_ uint64_t ia32_store_dr0(void)
{
    uint64_t dr0;
    _ASM_VOLATILE_ ("mov %%dr0, %0" : "=r" (dr0));
    return dr0;
}

_STATIC_INLINE_ uint64_t ia32_store_dr1(void)
{
    uint64_t dr1;
    _ASM_VOLATILE_ ("mov %%dr1, %0" : "=r" (dr1));
    return dr1;
}

_STATIC_INLINE_ uint64_t ia32_store_dr2(void)
{
    uint64_t dr2;
    _ASM_VOLATILE_ ("mov %%dr2, %0" : "=r" (dr2));
    return dr2;
}

_STATIC_INLINE_ uint64_t ia32_store_dr3(void)
{
    uint64_t dr3;
    _ASM_VOLATILE_ ("mov %%dr3, %0" : "=r" (dr3));
    return dr3;
}

_STATIC_INLINE_ uint64_t ia32_store_dr6(void)
{
    uint64_t dr6;
    _ASM_VOLATILE_ ("mov %%dr6, %0" : "=r" (dr6));
    return dr6;
}






/** WRF/GSBASE & RDF/GSBASE
 *
 * Intrinsics:
 * WRFSBASE: void _writefsbase_u32( unsigned int );
 * WRFSBASE: _writefsbase_u64( unsigned __int64 );
 * WRGSBASE: void _writegsbase_u32( unsigned int );
 * WRGSBASE: _writegsbase_u64( unsigned __int64 );
 *
 * RDFSBASE: unsigned int _readfsbase_u32(void );
 * RDFSBASE: unsigned __int64 _readfsbase_u64(void );
 * RDGSBASE: unsigned int _readgsbase_u32(void );
 * RDGSBASE: unsigned __int64 _readgsbase_u64(void );
 */


/*
_STATIC_INLINE_ void ia32_pause( void )
{
	_ASM_VOLATILE_ ("pause" ) ;
}
*/

/**
 * Atomic operations
 */
_STATIC_INLINE_ uint8_t _lock_cmpxchg_8bit(uint8_t cmp_val, uint8_t set_val, uint8_t *sem)
{
    _ASM_VOLATILE_ ("lock\n"
            "cmpxchgb %3,%0"
            : "=m"(*sem), "=a"(set_val)
            : "a"(cmp_val), "r" (set_val)
            : "memory" , "cc");
    return set_val;
}

_STATIC_INLINE_ uint16_t _lock_cmpxchg_16b(uint16_t cmp_val, uint16_t set_val, uint16_t *sem)
{
    _ASM_VOLATILE_ ("lock\n"
            "cmpxchgw %3,%0"
            : "=m"(*sem), "=a"(set_val)
            : "a"(cmp_val), "r" (set_val)
            : "memory" , "cc");
    return set_val;
}

_STATIC_INLINE_ uint32_t _lock_cmpxchg_32b(uint32_t cmp_val, uint32_t set_val, uint32_t *sem)
{
    _ASM_VOLATILE_ ("lock\n"
            "cmpxchgl %3,%0"
            : "=m"(*sem), "=a"(set_val)
            : "a"(cmp_val), "r" (set_val)
            : "memory" , "cc");
    return set_val;
}

_STATIC_INLINE_ uint64_t _lock_cmpxchg_64b(uint64_t cmp_val, uint64_t set_val, uint64_t *sem)
{
    _ASM_VOLATILE_ ("lock\n"
            "cmpxchgq %3,%0"
            : "=m"(*sem), "=a"(set_val)
            : "a"(cmp_val), "r" (set_val)
            : "memory" , "cc");
    return set_val;
}

/**
 * @brief Atomically reads 128 bits using cmpxchg
 * @param src Source to read from
 * @note Uses cmpxchg so requires source to have write access
 * @return
 */
_STATIC_INLINE_ uint128_t _lock_read_128b(uint128_t * src)
{
    // Using cmpxchg to atomically read 128 bits
    uint128_t result;
    _ASM_VOLATILE_ ("lock\n"
            "cmpxchg16b %2"
            : "=a"(result.qwords[0]), "=d"(result.qwords[1])
            : "m"(*src) , "a"(0),"b"(0),"c"(0),"d"(0)
            : "memory" );
    return result;
}

_STATIC_INLINE_ uint16_t _xchg_16b(uint16_t *mem, uint16_t quantum)
{
    //according to SDM, XCHG on memory operand is automatically uses the processor's locking protocol
    //regardless of LOCK prefix
    _ASM_VOLATILE_ ("xchgw %2, %0" : "=m" ( *mem ), "=a"(quantum) : "a"(quantum) : "memory");
    return quantum;
}

_STATIC_INLINE_ uint16_t _lock_xadd_16b(uint16_t *mem, uint16_t quantum)
{
    _ASM_VOLATILE_ ("lock; xaddw %2, %0" : "=m" ( *mem ), "=a"(quantum) : "a"(quantum) : "memory", "cc");
    return quantum;
}

_STATIC_INLINE_ uint32_t _lock_xadd_32b(uint32_t *mem, uint32_t quantum)
{
    _ASM_VOLATILE_ ("lock; xaddl %2, %0" : "=m" ( *mem ), "=a"(quantum) : "a"(quantum) : "memory", "cc");
    return quantum;
}

_STATIC_INLINE_ uint64_t _lock_xadd_64b(uint64_t *mem, uint64_t quantum)
{
    _ASM_VOLATILE_ ("lock; xaddq %2, %0" : "=m" ( *mem ), "=a"(quantum) : "a"(quantum) : "memory", "cc");
    return quantum;
}

_STATIC_INLINE_ bool_t _lock_bts_32b(volatile uint32_t* mem, uint32_t bit)
{
    bool_t result;

    _ASM_VOLATILE_ ("lock; bts %2, %0; adc %1,%1" : "=m" ( *mem ) , "=b"(result) : "a"(bit) , "b"(0) : "cc" , "memory");
    return result;
}

_STATIC_INLINE_ bool_t _lock_btr_32b(volatile uint32_t* mem, uint32_t bit)
{
    bool_t result;

    _ASM_VOLATILE_ ("lock; btr %2, %0; adc %1,%1" : "=m" ( *mem ) , "=b"(result) : "a"(bit) , "b"(0) : "cc" , "memory");
    return result;
}

_STATIC_INLINE_ bool_t _lock_bts_64b(volatile uint64_t* mem, uint64_t bit)
{
    bool_t result;

    _ASM_VOLATILE_ ("lock; bts %2, %0; adc %1,%1" : "=m" ( *mem ) , "=b"(result) : "a"(bit) , "b"(0) : "cc" , "memory");
    return result;
}

_STATIC_INLINE_ bool_t _lock_btr_64b(volatile uint64_t* mem, uint64_t bit)
{
    bool_t result;

    _ASM_VOLATILE_ ("lock; btr %2, %0; adc %1,%1" : "=m" ( *mem ) , "=b"(result) : "a"(bit) , "b"(0) : "cc" , "memory");
    return result;
}

_STATIC_INLINE_ uint64_t bit_scan_forward64(uint64_t mask)
{
    tdx_debug_assert(mask != 0);

    uint64_t lsb_position;
    _ASM_VOLATILE_ ("bsfq %1, %0 \n"
                        :"=r"(lsb_position)
                        :"r"(mask)
                        :"cc");

    return lsb_position;
}

_STATIC_INLINE_ uint64_t bit_scan_reverse64(uint64_t value)
{
    tdx_debug_assert(value != 0);

    uint64_t msb_position;
    _ASM_VOLATILE_ ("bsrq %1, %0 \n"
                            :"=r"(msb_position)
                            :"r"(value)
                            :"cc");
    return msb_position;
}

_STATIC_INLINE_ void bts_32b(volatile uint32_t* mem, uint32_t bit)
{
    _ASM_VOLATILE_ ("bts %1, %0;" : "=m" ( *mem ) : "a"(bit) : "cc" , "memory");
}

_STATIC_INLINE_ void btr_32b(volatile uint32_t* mem, uint32_t bit)
{
    _ASM_VOLATILE_ ("btr %1, %0;" : "=m" ( *mem ) : "a"(bit) : "cc" , "memory");
}

_STATIC_INLINE_ void movdir64b(const void *src, uint64_t dst)
{
    _ASM_VOLATILE_ (".byte  0x66, 0x0F, 0x38, 0xF8," /*movdir64b op*/ "0x37;" /*ModRM = RDI->RSI*/
                    : : "D"(src), "S"(dst) : "memory" );
}

_STATIC_INLINE_ void lfence(void)
{
    _ASM_VOLATILE_ ("lfence" : : : "memory");
}

_STATIC_INLINE_ void mfence(void)
{
    _ASM_VOLATILE_ ("mfence" : : : "memory");
}

_STATIC_INLINE_ void sfence(void)
{
    _ASM_VOLATILE_ ("sfence" : : : "memory");
}

_STATIC_INLINE_ void ia32_clflushopt(volatile void *p)
{
    _ASM_VOLATILE_ ("clflushopt (%0)" :: "r"(p));
}

_STATIC_INLINE_ void store_xmms_in_buffer(uint128_t xmms[16])
{
    _ASM_VOLATILE_ (
         // Storing the existing XMM's
            "movdqa %%xmm0, (%0)\n"
            "movdqa %%xmm1, 0x10(%0)\n"
            "movdqa %%xmm2, 0x20(%0)\n"
            "movdqa %%xmm3, 0x30(%0)\n"
            "movdqa %%xmm4, 0x40(%0)\n"
            "movdqa %%xmm5, 0x50(%0)\n"
            "movdqa %%xmm6, 0x60(%0)\n"
            "movdqa %%xmm7, 0x70(%0)\n"
            "movdqa %%xmm8, 0x80(%0)\n"
            "movdqa %%xmm9, 0x90(%0)\n"
            "movdqa %%xmm10, 0xA0(%0)\n"
            "movdqa %%xmm11, 0xB0(%0)\n"
            "movdqa %%xmm12, 0xC0(%0)\n"
            "movdqa %%xmm13, 0xD0(%0)\n"
            "movdqa %%xmm14, 0xE0(%0)\n"
            "movdqa %%xmm15, 0xF0(%0)\n"

        : : "r"(xmms));
}

_STATIC_INLINE_ void load_xmms_from_buffer(const uint128_t xmms[16])
{
    _ASM_VOLATILE_ (
            "movdqa (%0), %%xmm0\n"
            "movdqa 0x10(%0), %%xmm1\n"
            "movdqa 0x20(%0), %%xmm2\n"
            "movdqa 0x30(%0), %%xmm3\n"
            "movdqa 0x40(%0), %%xmm4\n"
            "movdqa 0x50(%0), %%xmm5\n"
            "movdqa 0x60(%0), %%xmm6\n"
            "movdqa 0x70(%0), %%xmm7\n"
            "movdqa 0x80(%0), %%xmm8\n"
            "movdqa 0x90(%0), %%xmm9\n"
            "movdqa 0xA0(%0), %%xmm10\n"
            "movdqa 0xB0(%0), %%xmm11\n"
            "movdqa 0xC0(%0), %%xmm12\n"
            "movdqa 0xD0(%0), %%xmm13\n"
            "movdqa 0xE0(%0), %%xmm14\n"
            "movdqa 0xF0(%0), %%xmm15\n"

        : : "r"(xmms));
}

_STATIC_INLINE_ void ia32_swapgs(uint64_t value)
{
    /**
     * rdgsbase saves the current GS.base (local data struct) into rax
     * then the value is loaded the value that should go into kernel gs base msr to gs.base
     * and at the end wrgsbase saves rax back into the GS.base
     */
    _ASM_VOLATILE_ ("rdgsbase %%rax\n"
                    "wrgsbase %0\n"
                    "swapgs\n"
                    "wrgsbase %%rax\n"
                    : : "r"(value) : "rax");

}

#endif /* SRC_COMMON_ACCESSORS_IA32_ACCESSORS_H_ */
