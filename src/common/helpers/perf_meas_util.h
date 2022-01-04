// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

#ifndef PERF_MEAS_UTILS_H
#define PERF_MEAS_UTILS_H

typedef UINT64  uint64_t;
typedef UINT8   uint8_t;
typedef BOOLEAN bool_t;


#define API_ENTRY_GPRS_SIZE 3
#define INTERNAL_ENTRY_PARAMS_SIZE 5

typedef enum {perf_util_log_point_type_api, perf_util_log_point_type_custom} perf_util_log_point_type_t;
typedef enum {api_log_entry_seamcall, api_log_entry_tdcall, api_log_entry_seamret, api_log_entry_tdenter} api_log_entry_id_t;
#define perf_util_log_point_type_custom_id_seamcall 0
#define perf_util_log_point_type_custom_id_tdcall   1
#define perf_util_log_point_type_custom_id_tdexit   2
#define perf_util_log_point_type_custom_id_td_save_state      0x10
#define perf_util_log_point_type_custom_id_vmm_restore_state  0x20
#define perf_util_log_point_type_custom_id_pconfig            0x30
#define perf_util_log_point_type_custom_aug_page_internal     0x40

#define PERF_MEAS_UTIL_CSTM(lgp, lgp_id, p0, p1, p2, p3)            \
        (lgp).log_type = perf_util_log_point_type_custom;           \
        (lgp).log_type_entry.internal_log_entry.id = lgp_id;        \
        (lgp).log_type_entry.internal_log_entry.params[0] = (p0);   \
        (lgp).log_type_entry.internal_log_entry.params[1] = (p1);   \
        (lgp).log_type_entry.internal_log_entry.params[2] = (p2);   \
        (lgp).log_type_entry.internal_log_entry.params[3] = (p3);   \
        (lgp).log_type_entry.internal_log_entry.params[4] = 0;

#define PERF_MEAS_UTIL_CUSTOM_START(lgp, lgp_id, p0, p1, p2, p3) /*   \
        PERF_MEAS_UTIL_CSTM((lgp), (lgp_id), (p0), (p1), (p2), (p3)); \
        per_meas_util_internal_flow_start(&(lgp));*/

#define PERF_MEAS_CUSTOM_END(lgp, lgp_id, p0, p1, p3)  /*             \
        PERF_MEAS_UTIL_CSTM((lgp), (lgp_id), (p0), (p1), (p2), (p3)); \
        per_meas_util_internal_flow_end(&(lgp));*/


typedef struct api_log_entry_s
{
    api_log_entry_id_t id; // SEAMCALL, TDCALL
    uint64_t leaf_number;
    uint64_t exit_code;
    uint64_t gprs[API_ENTRY_GPRS_SIZE]; // RAX, RCX, RDX, R8, R9 - set to "0" if not used
} api_log_entry_t;

typedef struct internal_log_entry_s
{
	uint64_t id; // user defined ID's
    union {
		uint64_t params[INTERNAL_ENTRY_PARAMS_SIZE]; // HPA, GPA, walk length, ..., status, ...
        struct {
			uint64_t unused[INTERNAL_ENTRY_PARAMS_SIZE - 1];
			uint64_t status; // === params[INTERNAL_ENTRY_PARAMS_SIZE - 1]
        };
    };
} internal_log_entry_t;

typedef struct perf_util_log_point_s
{
	uint64_t time_stamp;
    perf_util_log_point_type_t  log_type;
    uint8_t  start_end; // Log point begin or end
    union {
        api_log_entry_t api_log_entry;
        internal_log_entry_t internal_log_entry;
    } log_type_entry;
//    uint64_t lp_number; // or thread ID
} perf_util_log_point_t;

typedef struct per_meas_util_log_mask_s
{
	uint64_t  seamcall_mask;
	uint64_t  tdcall_mask;
} per_meas_util_log_mask_t;

typedef struct perf_meas_util_config_s
{
	per_meas_util_log_mask_t log_points_mask;
    uint64_t log_points_array_size;
    perf_util_log_point_t *log_points_array;
    uint64_t head_indx, current_pos_indx;
    uint64_t num_log_opints;

    /* The following 3 vars are used for debugging purposes only */
    uint64_t num_overwrites;
    uint64_t num_overwrites_before_flush;
    uint64_t num_overwrites_before_flush_max;
} perf_meas_util_config_t;

void per_meas_util_init(uint64_t log_size);
void per_meas_util_flush_to_file(void);
void per_meas_util_cLeanup(void);
void per_meas_util_print_log_point_by_indx(uint64_t index);
perf_meas_util_config_t * perf_meas_util_get_config(void);
void per_meas_util_enable_log_point(per_meas_util_log_mask_t mask, bool_t enable);
per_meas_util_log_mask_t per_meas_util_get_log_points_mask(void);
bool_t per_meas_util_is_log_point_enabled(per_meas_util_log_mask_t mask);
void per_meas_util_api_start(const perf_util_log_point_t *log_point);
void per_meas_util_api_end(const perf_util_log_point_t *log_point);
void per_meas_util_internal_flow_start(const perf_util_log_point_t *log_point);
void per_meas_util_internal_flow_end(const perf_util_log_point_t *log_point);

void per_meas_util_add_log_point(const perf_util_log_point_t *log_point);

#endif // PERF_MEAS_UTILS_H
