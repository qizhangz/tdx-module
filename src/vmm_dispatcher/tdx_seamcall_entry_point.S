// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_entry_from_vmm.S
 * @brief Module's VMM entry point - saves GPRs to local data and invokes the API dispatcher
 */
#include "data_structures/tdx_local_data_offsets.h"

.hidden tdx_vmm_dispatcher

.section .text
.globl tdx_seamcall_entry_point
.type  tdx_seamcall_entry_point,@function
tdx_seamcall_entry_point:

    /**
     * Save all VMM GPRs on module entry to LP local data
     * Local data is located at GSBASE
     */
    movq %rax,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET
    movq %rcx,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+8
    movq %rdx,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+16
    movq %rbx,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+24
    movq %rsp,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+32 // not actually needed
    movq %rbp,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+40
    movq %rsi,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+48
    movq %rdi,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+56
    movq %r8,   %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+64
    movq %r9,   %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+72
    movq %r10,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+80
    movq %r11,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+88
    movq %r12,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+96
    movq %r13,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+104
    movq %r14,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+112
    movq %r15,  %gs:TDX_LOCAL_DATA_VMM_GPRS_STATE_OFFSET+120

	/*
	 * clear VMM GPRs on entry to the TDX module
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
     callq tdx_vmm_dispatcher

    /**
     * Dispatcher should not retrun to this code
     * It returns to the VMM using SEAMRET
     * Panic with UD2 if reached
     */
    ud2
