// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file sept_manager.c
 * @brief SEPT manager implementaiton
 */


#include "tdx_basic_defs.h"
#include "tdx_basic_types.h"

#include "sept_manager.h"
#include "keyhole_manager.h"
#include "x86_defs/x86_defs.h"
#include "accessors/data_accessors.h"
#include "data_structures/tdx_local_data.h"
#include "helpers/helpers.h"


_STATIC_INLINE_ uint64_t get_ept_entry_idx(pa_t gpa, ept_level_t lvl)
{
    uint64_t idx = 0;

    switch (lvl)
    {
        case LVL_PML5:
            idx = gpa.fields_4k.pml5_index;
            break;
        case LVL_PML4:
            idx = gpa.fields_4k.pml4_index;
            break;
        case LVL_PDPT:
            idx = gpa.fields_4k.pdpt_index;
            break;
        case LVL_PD:
            idx = gpa.fields_4k.pd_index;
            break;
        case LVL_PT:
            idx = gpa.fields_4k.pt_index;
            break;
        default:
            tdx_sanity_check(0, SCEC_SEPT_MANAGER_SOURCE, 0);
            break;
    }

    return idx;
}

_STATIC_INLINE_ bool_t is_secure_ept_entry_misconfigured(ia32e_sept_t* pte, ept_level_t level)
{
    pa_t hpa;
    hpa.raw = pte->raw & IA32E_PAGING_STRUCT_ADDR_MASK;

    if ((pte->fields_ps.r == 0) && (pte->fields_ps.w == 1))
    {
        return true;
    }

    platform_common_config_t* msr_values = &get_global_data()->plt_common_config;

    if (!(msr_values->ia32_vmx_ept_vpid_cap & EPT_VPID_CAP_ALLOW_EXECUTE_ONLY))
    {
        if ((pte->fields_ps.r == 0) && (pte->fields_ps.x == 1))
        {
            return true;
        }
    }

    if (pte->present.rwx)
    {
        // A reserved bit is set. This includes the setting of a bit in the
        // range 51:12 that is beyond the logical processor’s physical-address width.

        // Bits beyond logical processor physical-address width will be checked
        // by the is_pa_smaller_than_max_pa() function call above

        // Paging structure case:
        if (((level > LVL_PDPT) || ((level > LVL_PT) && !pte->fields_1g.leaf))
                && pte->fields_ps.reserved_0)
        {
            return true;
        }
        // Leaf case
        if ( ((level == LVL_PDPT) && pte->fields_1g.leaf && pte->fields_1g.reserved_1) ||
             ((level == LVL_PD) && pte->fields_2m.leaf && pte->fields_2m.reserved_1)
           )
        {
            return true;
        }

        // The entry is the last one used to translate a guest physical address
        // (either an EPT PDE with bit 7 set to 1 or an EPT PTE) and the
        // value of bits 5:3 (EPT memory type) is 2, 3, or 7 (these values are reserved).
        if ( ((level == LVL_PDPT) && pte->fields_1g.leaf) ||
             ((level == LVL_PD) && pte->fields_2m.leaf) ||
              (level == LVL_PT) )
        {
            // Looking here at 4K struct because the MT bits location is the same in 1G and 2M
            if ((pte->fields_4k.mt == MT_RSVD0) || (pte->fields_4k.mt == MT_RSVD1) ||
                (pte->fields_4k.mt == MT_UCM))
            {
                return true;
            }
        }
    }

    return false;
}

_STATIC_INLINE_ bool_t is_shared_ept_entry_misconfigured(ia32e_ept_t* pte, ept_level_t level)
{
    pa_t hpa;
    hpa.raw = pte->raw & IA32E_PAGING_STRUCT_ADDR_MASK;

    // 28.2.3.1 EPT Misconfigurations from Intel SDM:
    // Bit 0 of the entry is clear (indicating that data reads are not allowed)
    // and bit 1 is set (indicating that data writes are allowed).
    if ((pte->fields_ps.r == 0) && (pte->fields_ps.w == 1))
    {
        return true;
    }

    platform_common_config_t* msr_values = &get_global_data()->plt_common_config;

    // Either of the following if the processor does not support execute-only translations:
    if (!(msr_values->ia32_vmx_ept_vpid_cap & EPT_VPID_CAP_ALLOW_EXECUTE_ONLY))
    {
        // Bit 0 of the entry is clear (indicating that data reads are not allowed)
        // and bit 2 is set (indicating that instruction fetches are allowed)
        if ((pte->fields_ps.r == 0) && (pte->fields_ps.x == 1))
        {
            return true;
        }

        // The "mode-based execute control for EPT" VM-execution control is 1,
        // bit 0 of the entry is clear (indicating that data reads are not allowed),
        // and bit 10 is set (indicating that instruction fetches are allowed from
        // usermode linear addresses).

        // No need to check, because "mode-based execute control for EPT" bit
        // is defined to be a constant 0 in TD VMCS.
    }

    // The entry is present (see Section 28.2.2) and one of the following holds:
    if (pte->present.rwx)
    {
        // A reserved bit is set. This includes the setting of a bit in the
        // range 51:12 that is beyond the logical processor’s physical-address width.

        // Bits beyond logical processor physical-address width will be checked
        // by the shared_hpa_check() function call above

        // Paging structure case:
        if (((level > LVL_PDPT) || ((level > LVL_PT) && !pte->fields_1g.leaf))
                && pte->fields_ps.reserved_0)
        {
            return true;
        }
        // Leaf case
        if ( ((level == LVL_PDPT) && pte->fields_1g.leaf && pte->fields_1g.reserved_0) ||
             ((level == LVL_PD) && pte->fields_2m.leaf && pte->fields_2m.reserved_0)
           )
        {
            return true;
        }

        // The entry is the last one used to translate a guest physical address
        // (either an EPT PDE with bit 7 set to 1 or an EPT PTE) and the
        // value of bits 5:3 (EPT memory type) is 2, 3, or 7 (these values are reserved).
        if ( ((level == LVL_PDPT) && pte->fields_1g.leaf) ||
             ((level == LVL_PD) && pte->fields_2m.leaf) ||
              (level == LVL_PT) )
        {
            // Looking here at 4K struct because the MT bits location is the same in 1G and 2M
            if ((pte->fields_4k.mt == MT_RSVD0) || (pte->fields_4k.mt == MT_RSVD1) ||
                (pte->fields_4k.mt == MT_UCM))
            {
                return true;
            }
        }
        else
        {
            // Shared 4KB HPA check is relevant only for present and non-leaf entries
            // Leaf entry HPA should be checked at the end of the final translation
            if (shared_hpa_check(hpa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS)
            {
                return true;
            }
        }
    }

    return false;
}

_STATIC_INLINE_ bool_t is_ept_violation_convertible(ia32e_ept_t* pte, ept_level_t level)
{
    // #VE is enabled unconditionally for TDX non-root operation.
    // The TDX-SEAM module sets the TD VMCS EPT-violation #VE VM-execution control to 1.

    // Checks are according to SDM (25.5.6.1) - Convertible EPT Violations

    // The values of certain EPT paging-structure entries determine which EPT violations are convertible. Specifically,
    // bit 63 of certain EPT paging-structure entries may be defined to mean suppress #VE:
    // - If bits 2:0 of an EPT paging-structure entry are all 0, the entry is not present.
    //      (If the “mode-based execute control for EPT” VM-execution control is 1,
    //       an EPT paging-structure entry is present if any of bits 2:0 or bit 10 is 1)
    //      If the processor encounters such an entry while translating a guest-physical address,
    //      it causes an EPT violation. The EPT violation is convertible if and only if bit 63 of the entry is 0.

    // - If an EPT paging-structure entry is present, the following cases apply:
    //      * If bit 7 of the entry is 1, or if the entry is an EPT PTE, the entry maps a page.
    //        If the processor uses such an entry to translate a guest-physical address, and if
    //        an access to that address causes an EPT violation, the EPT violation is convertible
    //        if and only if bit 63 of the entry is 0.
    //      * If bit 7 of the entry is 0 and the entry is not an EPT PTE, the entry references another EPT paging
    //        structure. The processor does not use the value of bit 63 of the entry to determine whether any
    //        subsequent EPT violation is convertible.

    // Note that Bit(22) - Mode-based execute control for EPT in TD exec controls is always 0
    // So no need to check bit 10 in EPT entry to determine whether the entry is present

    if ((!pte->present.rwx || pte->fields_2m.leaf || (level == LVL_PT)) && !pte->fields_4k.supp_ve)
    {
        return true;
    }

    return false;
}

ept_walk_result_t gpa_translate(ia32e_eptp_t eptp, pa_t gpa, bool_t private_gpa,
                                uint16_t private_hkid, access_rights_t access_rights,
                                pa_t* hpa, ia32e_ept_t* cached_ept_entry, access_rights_t* accumulated_rwx)
{
    ia32e_paging_table_t *pt;
    ia32e_ept_t *pte;
    pa_t pt_pa;
    ept_level_t current_lvl;

    // Get root PML EPT page address
    pt_pa.raw = eptp.raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    current_lvl = eptp.fields.ept_pwl;
    // No need to check the HPA of PML5 in Shared EPTP, it is checked during TDHVPWR

    accumulated_rwx->raw = (uint8_t)7;

    for (;current_lvl >= LVL_PT; current_lvl--)
    {
        if (private_gpa)
        {
            pt_pa = set_hkid_to_pa(pt_pa, private_hkid);
        }
        pt = map_pa((void*)(pt_pa.full_pa), TDX_RANGE_RO);
        pte = &(pt->ept[get_ept_entry_idx(gpa, current_lvl)]);

        // Update the output data - note the we read only from the cached entry
        cached_ept_entry->raw = pte->raw; // Atomic copy
        accumulated_rwx->rwx &= cached_ept_entry->present.rwx;

        free_la(pt); // Not needed at that point

        // Check misconfiguration conditions
        IF_RARE (!private_gpa && is_shared_ept_entry_misconfigured(cached_ept_entry, current_lvl))
        {
            return EPT_WALK_MISCONFIGURATION;
        }

        // Misconfigurations on Secure EPT are not expected and considered to be fatal errors
        IF_RARE (private_gpa && is_secure_ept_entry_misconfigured((ia32e_sept_t*)cached_ept_entry, current_lvl))
        {
            FATAL_ERROR();
        }

        // Check violation conditions
        IF_RARE ((cached_ept_entry->present.rwx == 0) ||
                 ((uint8_t)(access_rights.rwx & cached_ept_entry->present.rwx) != access_rights.rwx))
        {
            if (is_ept_violation_convertible(cached_ept_entry, current_lvl))
            {
                return EPT_WALK_CONVERTIBLE_VIOLATION;
            }
            else
            {
                return EPT_WALK_VIOLATION;
            }
        }

        // Check if leaf is reached - page walk done
        if (is_ept_leaf_entry((ia32e_sept_t*)cached_ept_entry, current_lvl))
        {
            // Calculate the final HPA
            hpa->raw = leaf_ept_entry_to_hpa((*(ia32e_sept_t*)cached_ept_entry), gpa.raw, current_lvl);
            break;
        }

        pt_pa.raw = cached_ept_entry->raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    }

    // Shared HPA check on the final translated 4KB page.
    // Since TDX module works only with 4KB operands, this check is sufficient,
    // and we don't need to check SEAMRR overlaps of whole area in case when bigger (1GB or 2MB)
    // leaf page is mapped by the TD.
    if (!private_gpa && (shared_hpa_check(*hpa, TDX_PAGE_SIZE_IN_BYTES) != TDX_SUCCESS))
    {
        return EPT_WALK_MISCONFIGURATION;
    }

    return EPT_WALK_SUCCESS;
}

ia32e_sept_t* secure_ept_walk(ia32e_eptp_t septp, pa_t gpa, uint16_t private_hkid,
                              ept_level_t* level, ia32e_sept_t* cached_sept_entry)
{
    ia32e_paging_table_t *pt;
    ia32e_sept_t *pte;
    pa_t pt_pa;

    ept_level_t requested_level = *level;
    ept_level_t current_lvl;

    tdx_sanity_check(requested_level <= LVL_PML5, SCEC_SEPT_MANAGER_SOURCE, 1);

    // Get root PML EPT page address
    pt_pa.raw = septp.raw & IA32E_PAGING_STRUCT_ADDR_MASK;
    current_lvl = septp.fields.ept_pwl;
    // No need to check the HPA of PML5 in Shared EPTP, it is checked during TDHVPWR

    for (;current_lvl >= LVL_PT; current_lvl--)
    {
        pt_pa = set_hkid_to_pa(pt_pa, private_hkid);
        pt = map_pa((void*)(pt_pa.full_pa), TDX_RANGE_RW);
        pte = &(pt->sept[get_ept_entry_idx(gpa, current_lvl)]);

        // Update the output data - note the we read only from the cached entry
        cached_sept_entry->raw = pte->raw; // Atomic copy
        *level = current_lvl;

        // Check if it is the requested level - success
        if (current_lvl == requested_level)
        {
            break;
        }

        IF_RARE (is_secure_ept_entry_misconfigured(cached_sept_entry, current_lvl))
        {
            FATAL_ERROR();
        }

        // Check if entry not present, or a leaf - so can't walk any further.
        IF_RARE (cached_sept_entry->present.rwx == 0 || is_ept_leaf_entry(cached_sept_entry, current_lvl))
        {
            break;
        }

        // Continue to next level in the walk
        pt_pa.raw = cached_sept_entry->raw & IA32E_PAGING_STRUCT_ADDR_MASK;
        free_la(pt); // Not needed at that point
    }

    // Note that the caller should remember to free the
    // PTE pointer after he finishes to use it!

    return pte;
}
