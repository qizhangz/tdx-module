// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file sept_manager.h
 * @brief SEPT manager headers
 */

#ifndef SRC_COMMON_MEMORY_HANDLERS_SEPT_MANAGER_H_
#define SRC_COMMON_MEMORY_HANDLERS_SEPT_MANAGER_H_

#include "x86_defs/x86_defs.h"

// A free Secure-EPT init value with suppress VE set (bit 63)
#define SEPTE_INIT_VALUE        BIT(63)

// Secure EPT state and level as returned in RDX by many API functions
typedef union sept_entry_arch_info_u
{
    struct
    {
        uint64_t level    : 8;
        uint64_t state    : 8;
        uint64_t reserved : 48;
    };
    uint64_t raw;
} sept_entry_arch_info_t;
tdx_static_assert(sizeof(sept_entry_arch_info_t) == 8, sept_entry_arch_info_t);

/**
 * @brief Check that EPT entry is a leaf - correct only for validly configured entries
 *
 * @param ept_entry Pointer to EPT entry
 * @param level The EPT entry level
 *
 * @return True if entry is a leaf, False otherwise
 */
_STATIC_INLINE_ bool_t is_ept_leaf_entry(ia32e_sept_t * ept_entry, ept_level_t level)
{
    return ((level == LVL_PT) || (ept_entry->fields_2m.leaf == 1));
}

/**
 * @brief Map a SEPT leaf entry
 *
 * @param ept_entry Pointer to EPT entry to map
 * @param page_pa Physical address to map in entry
 * @param leaf The EPT entry level
 * @param is_pending Is the entry pending or present
 */
_STATIC_INLINE_ void map_sept_leaf(ia32e_sept_t * ept_entry, pa_t page_pa, bool_t is_pending, bool_t supress_ve)
{
    ia32e_sept_t curr_entry = {.raw = 0};

    curr_entry.present.rwx = (is_pending ? 0: 0x7);
    curr_entry.fields_4k.mt = MT_WB; // 6
    curr_entry.fields_4k.ipat = 1;
    curr_entry.fields_4k.leaf = 1;
    curr_entry.fields_4k.tdp = is_pending;
    curr_entry.fields_4k.base = page_pa.page_4k_num;
    // When page is pending and not blocked, "supress_ve" is cleared to convert EPT violation into a #VE
    curr_entry.fields_4k.supp_ve = supress_ve;

    // One aligned assignment to make it atomic
    ept_entry->raw = curr_entry.raw;
}

/**
 * @brief Map a SEPT non-leaf entry
 *
 * @param ept_entry Pointer to EPT entry to map
 * @param page_pa Physical address to map in entry
 * @param leaf The EPT entry level
 * @param is_pending Is the entry pending or present
 */
_STATIC_INLINE_ void map_sept_non_leaf(ia32e_sept_t * ept_entry, pa_t page_pa)
{
    ia32e_sept_t curr_entry = {.raw = SEPTE_INIT_VALUE};

    curr_entry.present.rwx = 0x7;
    curr_entry.fields_4k.base = page_pa.page_4k_num;

    // One aligned assignment to make it atomic
    ept_entry->raw = curr_entry.raw;
}

typedef enum
{
    EPT_WALK_SUCCESS,
    EPT_WALK_VIOLATION,
    EPT_WALK_CONVERTIBLE_VIOLATION,
    EPT_WALK_MISCONFIGURATION
} ept_walk_result_t;

/**
 * @brief Private GPA-walk will walk over SEPT, and force assign private_hkid to each HPA at each level.
 *        Return a linear pointer to Secure-EPT entry corresponding to GPA and EPT level.
 *        EPT Misconfiguration during the walk will cause module halt (fatal error).
 *
 *
 * @param septp SEPT pointer that should be used in the walk
 * @param gpa Guest Physical Address that is translated
 * @param private_hkid HKID that can be assigned to HPA of each SEPT entry during the walk
 *
 * @param level Pointer to a level parameter that the walk should reach. On return contains the level
 *              that was actually reached in the walk.
 *
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 *               User should read the SEPT entry from the cached value only,
 *
 *
 * @return Linear pointer to last SEPT entry that was found during the walk.
 *         Always remember to free the linear pointer after the use.
 */
ia32e_sept_t* secure_ept_walk(ia32e_eptp_t septp, pa_t gpa, uint16_t private_hkid,
                              ept_level_t* level, ia32e_sept_t* cached_sept_entry);


/**
 * @brief Generic function used for all (private and shared) GPA translations, imitating the
 *        functionality of hardware PMH.
 *
 * @param eptp EPT pointer that should be used in the walk
 * @param gpa Guest Physical Address that is translated
 * @param private_gpa Indicated if input GPA is private or shared
 * @param private_hkid Used only if GPA is private, will be assigned on each HPA during the walk
 * @param access_rights Access rights asked for the walk (Read, Write, Execute)
 *
 * @param hpa Pointer to a HPA parameter. On return contains the translated HPA. Valid only on success.
 *
 * @param cached_ept_entry - Pointer to a EPT entry parameter. On return contains cached value
 *               of the last sampled EPT entry (even on failure).
 *               User should read the EPT entry from the cached value only,
 *
 * @param accumulated_rwx Pointer to a rwx parameter that will be accumulated during the walk
 *                        by ANDing all the rwx values of all the levels.
 *
 * @return Status of the walk, either full success, EPT violation, EPT convertible violation or EPT misconfiguration.
 *
 */
ept_walk_result_t gpa_translate(ia32e_eptp_t eptp, pa_t gpa, bool_t private_gpa,
                                uint16_t private_hkid, access_rights_t access_rights,
                                pa_t* hpa, ia32e_ept_t* cached_ept_entry, access_rights_t* accumulated_rwx);


#endif /* SRC_COMMON_MEMORY_HANDLERS_SEPT_MANAGER_H_ */
