#// Intel Proprietary 
#//
#// Copyright 2021 Intel Corporation All Rights Reserved.
#//
#// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
#// 
#// The Materials are provided \“as is,\” without any express or implied warranty of any kind including warranties
#// of merchantability, non-infringement, title, or fitness for a particular purpose.

# proj_defs.mk - Project related defintions

PROJ_FLAGS = 

ifndef RELEASE
PROJ_FLAGS += -DDEBUG -g
endif

ifdef DBG_TRACE
PROJ_FLAGS += -DDEBUGFEATURE_TDX_DBG_TRACE
endif

ifdef SEAM_INST_SUPPORT
PROJ_FLAGS += -DSEAM_INSTRUCTIONS_SUPPORTED_IN_COMPILER
endif

ifdef PCONFIG_SUPPORT
PROJ_FLAGS += -DPCONFIG_SUPPORTED_IN_COMPILER
endif

#Versioning
ifdef TDX_MODULE_BUILD_DATE
PROJ_FLAGS += -DTDX_MODULE_BUILD_DATE=$(TDX_MODULE_BUILD_DATE)
else
PROJ_FLAGS += -DTDX_MODULE_BUILD_DATE=$(shell date +%Y%m%d)
endif

ifdef TDX_MODULE_BUILD_NUM
PROJ_FLAGS += -DTDX_MODULE_BUILD_NUM=$(TDX_MODULE_BUILD_NUM)
else
PROJ_FLAGS += -DTDX_MODULE_BUILD_NUM=0
endif

ifdef TDX_MODULE_SEAM_SVN
PROJ_FLAGS += -DTDX_MODULE_SEAM_SVN=$(TDX_MODULE_SEAM_SVN)
else
PROJ_FLAGS += -DTDX_MODULE_SEAM_SVN=0
endif

ifndef TDX_MODULE_MINOR_VER
PROJ_FLAGS += -DTDX_MODULE_MINOR_VER=0
endif

ifndef TDX_MODULE_MAJOR_VER
PROJ_FLAGS += -DTDX_MODULE_MAJOR_VER=1
endif

PRODUCTION_FLAGS = 

PROJ_FLAGS += -D_NO_IPP_DEPRECATED

