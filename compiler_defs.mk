#// Intel Proprietary 
#//
#// Copyright 2021 Intel Corporation All Rights Reserved.
#//
#// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
#// 
#// The Materials are provided \“as is,\” without any express or implied warranty of any kind including warranties
#// of merchantability, non-infringement, title, or fitness for a particular purpose.

# compiler_defs.mk - Compiler definition and flags

include proj_defs.mk

# Compiler
CC = clang
CXX = clang++
CCVERSION = $(shell $(CC) --version | grep ^clang | cut -f1 -d"." | sed 's/^.* //g' )

CC_WITHOUT_CODE_COVERAGE := $(CC)
CXX_WITHOUT_CODE_COVERAGE := $(CXX)

# Standard flags
STD_FLAGS = -MD -MP -m64 -Wall -Wextra -fPIC -fno-builtin-memset -fvisibility=hidden -mcmodel=small \
			-mstack-alignment=16 -mstackrealign -std=c17 -mno-mmx -mno-sse -fno-jump-tables

OPT_FLAGS = -O2

# SecV mandatory flags
SECV_FLAGS = -Wdouble-promotion -Wshadow -Wconversion -Wmissing-prototypes -Wpointer-arith -Wuninitialized -Wunreachable-code -Wunused-function -Werror -D_FORTIFY_SOURCE=2 -fno-zero-initialized-in-bss -fstack-protector-strong

CET_FLAGS = -mshstk -fcf-protection

# Combined flags
CFLAGS = $(STD_FLAGS) $(PROJ_FLAGS) $(OPT_FLAGS) $(SECV_FLAGS) $(CET_FLAGS) $(PRODUCTION_FLAGS) 
ifdef CHECK_DBG_DEFINE
# Add flags to dump preprocessor defines 
CFLAGS += -dM -E
endif

# Entry pointer for the linker
MODULE_ENTRY_POINT = tdx_seamcall_entry_point

# Linker flags
LDFLAGS = -Wl,-shared -Wl,-pie -Wl,-e,$(MODULE_ENTRY_POINT) -Wl,-z,relro -Wl,-z,now -Wl,--wrap=__stack_chk_fail \
		  -disable-red-zone -nostartfiles 

