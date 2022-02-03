// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_td_transitions.S
 * @brief TD entry and exit points
 */

#include "data_structures/tdx_local_data_offsets.h"

.section .text
.globl tdx_tdexit_entry_point
.globl tdx_tdentry_to_td

tdx_tdexit_entry_point:

    /**
     * Save all TD GPRs on module entry to LP local data
     * Local data is located at GSBASE
     */
    movq %rax,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET
    movq %rcx,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+8
    movq %rdx,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+16
    movq %rbx,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+24
    movq %rsp,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+32
    movq %rbp,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+40
    movq %rsi,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+48
    movq %rdi,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+56
    movq %r8,   %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+64
    movq %r9,   %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+72
    movq %r10,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+80
    movq %r11,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+88
    movq %r12,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+96
    movq %r13,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+104
    movq %r14,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+112
    movq %r15,  %gs:TDX_LOCAL_DATA_TD_GPRS_STATE_OFFSET+120

	/*
	 * clear TD GPRs on entry to the TDX module
	 */
    xor %rax, %rax
    xor %rcx, %rcx
    xor %rdx, %rdx
    xor %rbx, %rbx
    xor %rbp, %rbp
    xor %rsi, %rsi
    xor %rdi, %rdi
    xor %r8, %r8
    xor %r9, %r9
    xor %r10, %r10
    xor %r11, %r11
    xor %r12, %r12
    xor %r13, %r13
    xor %r14, %r14
    xor %r15, %r15

    // Protection against speculative attacks on GPRs
    lfence

    /**
     * Call the VMM API dispatcher
     */
    callq tdx_td_dispatcher
     
    /**
     * Unreachable code.  panic. 
     */
    ud2



tdx_tdentry_to_td:

    /**
     * Restore all TD GPRs on module entry from a TDVPS GPR area ptr passed in RSI
     */
    movq (%rsi),     %rax
    movq 8(%rsi),    %rcx
    movq 16(%rsi),   %rdx
    movq 24(%rsi),   %rbx
    // movq 32(%rsi),   %rsp - keep the RSP of the TDX module for debug purposes.
    // Actual RSP of the TD will be loaded during the VMENTRY from the TDCS (TD VMCS)
    movq 40(%rsi),   %rbp

    // RSI and RDI will be restored later - we are still using them

    movq 64(%rsi),   %r8
    movq 72(%rsi),   %r9
    movq 80(%rsi),   %r10
    movq 88(%rsi),   %r11
    movq 96(%rsi),   %r12
    movq 104(%rsi),  %r13
    movq 112(%rsi),  %r14
    movq 120(%rsi),  %r15

    // Launch state is being passed as a parameter
    test %edi, %edi
    jz vmlaunch_lbl

    movq 56(%rsi),   %rdi
    movq 48(%rsi),   %rsi

    vmresume
    
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    call tdx_failed_vmentry
#endif

    /**
    * Unreachable code.  panic.
    */
    ud2

vmlaunch_lbl:

    movq 56(%rsi),   %rdi
    movq 48(%rsi),   %rsi

    vmlaunch
    
#ifdef DEBUGFEATURE_TDX_DBG_TRACE
    call tdx_failed_vmentry
#endif

    /**
     * Unreachable code.  panic. 
     */
    ud2

