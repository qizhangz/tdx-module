// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

#include "perf_meas_util.h"

#include <stdlib.h>
#include <stdio.h>
#include <Uefi.h>
#include <Library/UefiLib.h>
#include "../VT/Include/CommonLib/vmm_defs.h"
#include <Library/MemoryAllocationLib.h>
#include <Library/ShellLib.h>
#include <Library\UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

uint64_t get_tsc(void);
#define ia32_rdtsc   get_tsc
#define  LOG_UTILS_FREE_LA(perf_meas_util_config_p)

typedef struct per_meas_util_StaticData_s
{
    perf_meas_util_config_t *log_util_unaligned_p;
    perf_util_log_point_t *log_points_unaligned_array;
    SHELL_FILE_HANDLE log_file_handle;
    perf_meas_util_config_t *perf_meas_util_config_p;
} per_meas_util_StaticData_t;

static per_meas_util_StaticData_t log_util_static_data  = { 0, 0, 0, 0 };

#include "per_meas_util_file_mgr_inc.c"

void per_meas_util_init(uint64_t log_size)
{
    log_util_static_data.log_file_handle = NULL;
    log_util_static_data.log_util_unaligned_p = AllocatePool(sizeof(*log_util_static_data.perf_meas_util_config_p) + PAGE_4KB_SIZE - 1);
    if (!log_util_static_data.log_util_unaligned_p)
    {
        EnablePrint(true);
        Print(L"Failed to allocate memory for logging struct");
        return;
    }
    log_util_static_data.log_points_unaligned_array = AllocatePool(sizeof(*log_util_static_data.perf_meas_util_config_p->log_points_array) * log_size + PAGE_4KB_SIZE - 1);
    if (!log_util_static_data.log_points_unaligned_array)
    {
        EnablePrint(true);
        Print(L"Failed to allocate memory for logging array");
        return;
    }

    log_util_static_data.perf_meas_util_config_p = (void*)((uint64_t)log_util_static_data.log_util_unaligned_p & ~(PAGE_4KB_SIZE-1)); // 4KB aligned
    perf_meas_util_config_t *perf_meas_util_config_p = log_util_static_data.perf_meas_util_config_p;
    perf_meas_util_config_p->log_points_array_size = log_size;
    perf_meas_util_config_p->log_points_array = (void*)((uint64_t)log_util_static_data.log_points_unaligned_array & ~(PAGE_4KB_SIZE-1));
    perf_meas_util_config_p->current_pos_indx = 0ull;
    perf_meas_util_config_p->head_indx = 0ull;
    perf_meas_util_config_p->num_log_opints = 0ull;
    perf_meas_util_config_p->num_overwrites = 0ull;
    perf_meas_util_config_p->num_overwrites_before_flush = 0ull;
    perf_meas_util_config_p->num_overwrites_before_flush_max = 0ull;
    perf_meas_util_config_p->log_points_mask.seamcall_mask = 0ull;
    perf_meas_util_config_p->log_points_mask.tdcall_mask = 0ull;
}

void per_meas_util_enable_log_point(per_meas_util_log_mask_t mask, bool_t enable)
{
    perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (!perf_meas_util_config_p)
    {
        return;
    }
    if (enable)
    {
    	perf_meas_util_config_p->log_points_mask.seamcall_mask |= mask.seamcall_mask;
    	perf_meas_util_config_p->log_points_mask.tdcall_mask |= mask.tdcall_mask;
    }
    else
    {
    	perf_meas_util_config_p->log_points_mask.seamcall_mask &= ~mask.seamcall_mask;
    	perf_meas_util_config_p->log_points_mask.tdcall_mask &= ~mask.tdcall_mask;
    }

    LOG_UTILS_FREE_LA(perf_meas_util_config_p);
}

per_meas_util_log_mask_t per_meas_util_get_log_points_mask(void)
{
	per_meas_util_log_mask_t mask = { 0 };
    perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (perf_meas_util_config_p)
    {
        LOG_UTILS_FREE_LA(perf_meas_util_config_p);
        return perf_meas_util_config_p->log_points_mask;
    }

    return mask;
}

static bool_t per_meas_util_is_api_log_point_enabled(const perf_meas_util_config_t *perf_meas_util_config_p, const perf_util_log_point_t *log_point)
{
    if ((!log_point) || (!perf_meas_util_config_p))
    {
        return false;
    }
    /* SEAMCALL or SEAMRET or TDENTER are all really SEAMCALLS */
    if ( ( (log_point->log_type_entry.api_log_entry.id == api_log_entry_seamcall) ||
           (log_point->log_type_entry.api_log_entry.id == api_log_entry_seamret) ||
           (log_point->log_type_entry.api_log_entry.id == api_log_entry_tdenter)
         ) &&
         (log_point->log_type_entry.api_log_entry.leaf_number < 64) &&
         (perf_meas_util_config_p->log_points_mask.seamcall_mask & (1ull << log_point->log_type_entry.api_log_entry.leaf_number))
       )
    {
        return true;
    }
    if ((log_point->log_type_entry.api_log_entry.id == api_log_entry_tdcall) && (log_point->log_type_entry.api_log_entry.leaf_number < 64) &&
        (perf_meas_util_config_p->log_points_mask.tdcall_mask & (1ull << log_point->log_type_entry.api_log_entry.leaf_number)))
    {
        return true;
    }

    return false;
}

bool_t per_meas_util_is_log_point_enabled(per_meas_util_log_mask_t mask)
{
    perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (!perf_meas_util_config_p)
    {
        return false;
    }
    if ((perf_meas_util_config_p->log_points_mask.seamcall_mask & mask.seamcall_mask) && (perf_meas_util_config_p->log_points_mask.tdcall_mask & mask.tdcall_mask))
    {
        return true;
    }
    return false;
}

perf_meas_util_config_t * perf_meas_util_get_config(void)
{
    perf_meas_util_config_t *perf_meas_util_config_p = log_util_static_data.perf_meas_util_config_p;

    return perf_meas_util_config_p;
}

static void per_meas_util_UpdateCurrentPos(perf_meas_util_config_t *perf_meas_util_config_p)
{
    ++perf_meas_util_config_p->num_log_opints;
    ++perf_meas_util_config_p->current_pos_indx;
    if (perf_meas_util_config_p->current_pos_indx == perf_meas_util_config_p->log_points_array_size)
    {
        /* cyclic buffer wrap around*/
    	perf_meas_util_config_p->current_pos_indx = 0;
    }

    if (perf_meas_util_config_p->current_pos_indx == perf_meas_util_config_p->head_indx)
    {
        /* if buffer is full, overwrite the first log point */
        ++perf_meas_util_config_p->head_indx;
        if (perf_meas_util_config_p->head_indx == perf_meas_util_config_p->log_points_array_size)
        {
        	perf_meas_util_config_p->head_indx = 0ull;
        }
        ++perf_meas_util_config_p->num_overwrites;
        ++perf_meas_util_config_p->num_overwrites_before_flush;

        static int scip_count = 100;
        if (scip_count++ >= 100) {
            scip_count = 0;
            Print(L"*** Log Util: log point overwrite: head=0x%llx - overwrite=0x%llx - owbf=0x%llx - owbf_max=0x%llx\n",
            		perf_meas_util_config_p->head_indx, perf_meas_util_config_p->num_overwrites,
					perf_meas_util_config_p->num_overwrites_before_flush, perf_meas_util_config_p->num_overwrites_before_flush_max);
        }
    }
}

static perf_util_log_point_t *per_meas_util_GetLogPointsArray(perf_meas_util_config_t *perf_meas_util_config_p, uint64_t indx)
{
    return &perf_meas_util_config_p->log_points_array[indx];
}

void per_meas_util_api_start(const perf_util_log_point_t *log_point)
{
    if (!log_point)
    {
        return;
    }

    perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (!perf_meas_util_config_p)
    {
        return;
    }
    if (!per_meas_util_is_api_log_point_enabled(perf_meas_util_config_p, log_point))
    {
        return;
    }

    perf_util_log_point_t *log_points_array = per_meas_util_GetLogPointsArray(perf_meas_util_config_p, perf_meas_util_config_p->current_pos_indx);

    *log_points_array = *log_point;
    log_points_array->log_type = perf_util_log_point_type_api;
    log_points_array->start_end = 1;
    log_points_array->time_stamp = ia32_rdtsc();

    per_meas_util_UpdateCurrentPos(perf_meas_util_config_p);

    LOG_UTILS_FREE_LA(log_points_array);
    LOG_UTILS_FREE_LA(perf_meas_util_config_p);
}

void per_meas_util_api_end(const perf_util_log_point_t *log_point)
{
    if (!log_point)
    {
        return;
    }

    perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (!perf_meas_util_config_p)
    {
        return;
    }

    if (!per_meas_util_is_api_log_point_enabled(perf_meas_util_config_p, log_point))
    {
        return;
    }

    perf_util_log_point_t *log_points_array = per_meas_util_GetLogPointsArray(perf_meas_util_config_p, perf_meas_util_config_p->current_pos_indx);

    *log_points_array = *log_point;
    log_points_array->log_type = perf_util_log_point_type_api;
    log_points_array->start_end = 0;
    log_points_array->time_stamp = ia32_rdtsc();

    per_meas_util_UpdateCurrentPos(perf_meas_util_config_p);

    LOG_UTILS_FREE_LA(log_points_array);
    LOG_UTILS_FREE_LA(perf_meas_util_config_p);
}

/**
 * Debug utility - adds a log point without any modifications.
 * It is the responsibility of the caller to set all log point member variables' values
 */
void per_meas_util_add_log_point(const perf_util_log_point_t *log_point)
{
    if (!log_point)
    {
        return;
    }

	perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (!perf_meas_util_config_p)
    {
        return;
    }

    perf_util_log_point_t *log_points_array = per_meas_util_GetLogPointsArray(perf_meas_util_config_p, perf_meas_util_config_p->current_pos_indx);

    *log_points_array = *log_point;

    per_meas_util_UpdateCurrentPos(perf_meas_util_config_p);

    LOG_UTILS_FREE_LA(log_points_array);
    LOG_UTILS_FREE_LA(perf_meas_util_config_p);
}

void per_meas_util_internal_flow_start(const perf_util_log_point_t *log_point)
{
    if (!log_point)
    {
        return;
    }

    perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (!perf_meas_util_config_p)
    {
        return;
    }

    perf_util_log_point_t *log_points_array = per_meas_util_GetLogPointsArray(perf_meas_util_config_p, perf_meas_util_config_p->current_pos_indx);

    *log_points_array = *log_point;
    log_points_array->log_type = perf_util_log_point_type_custom;
    log_points_array->start_end = 1;

    per_meas_util_UpdateCurrentPos(perf_meas_util_config_p);

    log_points_array->time_stamp = ia32_rdtsc();

    LOG_UTILS_FREE_LA(log_points_array);
    LOG_UTILS_FREE_LA(perf_meas_util_config_p);
}

void per_meas_util_internal_flow_end(const perf_util_log_point_t *log_point)
{
    if (!log_point)
    {
        return;
    }

    uint64_t time_stamp = ia32_rdtsc();

    perf_meas_util_config_t *perf_meas_util_config_p = perf_meas_util_get_config();
    if (!perf_meas_util_config_p)
    {
        return;
    }

    perf_util_log_point_t *log_points_array = per_meas_util_GetLogPointsArray(perf_meas_util_config_p, perf_meas_util_config_p->current_pos_indx);

    *log_points_array = *log_point;
    log_points_array->log_type = perf_util_log_point_type_custom;
    log_points_array->start_end = 0;
    log_points_array->time_stamp = time_stamp;

    per_meas_util_UpdateCurrentPos(perf_meas_util_config_p);

    LOG_UTILS_FREE_LA(log_points_array);
    LOG_UTILS_FREE_LA(perf_meas_util_config_p);
}
