// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file pamt_manager.c
 * @brief PAMT manager implementation
 */

#include "pamt_manager.h"
#include "data_structures/tdx_global_data.h"
#include "keyhole_manager.h"
#include "accessors/data_accessors.h"
#include "helpers/helpers.h"

bool_t pamt_get_block(pa_t pa, pamt_block_t* pamt_block)
{
    tdmr_entry_t* covering_tdmr = NULL;
    tdx_module_global_t* global_data_ptr = get_global_data();

    uint64_t pa_addr = get_addr_from_pa(pa);

    // Assuming that TDMR table is sorted by base (ascending)
    for (uint32_t i = 0; i < global_data_ptr->num_of_tdmr_entries; i++)
    {
        if (global_data_ptr->tdmr_table[i].base <= pa_addr)
        {
            covering_tdmr = &global_data_ptr->tdmr_table[i];
        }
        else
        {
            break;
        }
    }

    if (covering_tdmr == NULL || pa_addr >= (covering_tdmr->base + covering_tdmr->size))
    {
        TDX_ERROR("Couldn't find covering TDMR for PA = 0x%llx\n", pa_addr);
        return false;
    }

    pa_t offset_pa;

    offset_pa.raw = pa_addr - covering_tdmr->base;
    uint32_t pamt_block_num = (uint32_t)offset_pa.page_1g_num;

    tdx_sanity_check(pamt_block_num < covering_tdmr->num_of_pamt_blocks, SCEC_PAMT_MANAGER_SOURCE, 0);

    if (pa_addr >= (covering_tdmr->last_initialized & ~(_1GB - 1)))
    {
        TDX_ERROR("PA = 0x%llx wasn't initialized yet for the covering TDMR (last init addr = 0x%llx)\n",
                pa_addr, covering_tdmr->last_initialized);
        return false;
    }

    pamt_block->pamt_1gb_p = (pamt_entry_t*) (covering_tdmr->pamt_1g_base
            + (uint64_t)(pamt_block_num * sizeof(pamt_entry_t)));
    pamt_block->pamt_2mb_p = (pamt_entry_t*) (covering_tdmr->pamt_2m_base
            + (uint64_t)(pamt_block_num * sizeof(pamt_entry_t) * PAMT_2MB_ENTRIES_IN_1GB));
    pamt_block->pamt_4kb_p = (pamt_entry_t*) (covering_tdmr->pamt_4k_base
            + (uint64_t)(pamt_block_num * sizeof(pamt_entry_t) * PAMT_4KB_ENTRIES_IN_1GB));

    return true;
}


#define PAMT_4K_ENTRIES_IN_2MB    (_2MB / _4KB)
#define PAMT_4K_ENTRIES_IN_1GB    (_1GB / _4KB)
#define PAMT_4K_ENTRIES_IN_CACHE  (MOVDIR64_CHUNK_SIZE / sizeof(pamt_entry_t))

_STATIC_INLINE_ bool_t is_page_reserved(uint64_t page_offset, tdmr_entry_t *tdmr_entry, uint32_t* last_rsdv_idx)
{
    uint64_t rsvd_offset, rsvd_offset_end;
    uint32_t i;

    for (i = *last_rsdv_idx; i < tdmr_entry->num_of_rsvd_areas; i++)
    {
        rsvd_offset = tdmr_entry->rsvd_areas[i].offset;
        rsvd_offset_end = rsvd_offset + tdmr_entry->rsvd_areas[i].size;

        if ((page_offset >= rsvd_offset) && (page_offset < rsvd_offset_end))
        {
            *last_rsdv_idx = i;
            return true;
        }
    }

    *last_rsdv_idx = i;
    return false;
}

_STATIC_INLINE_ void pamt_4kb_init(pamt_block_t* pamt_block, uint64_t num_4k_entries, tdmr_entry_t *tdmr_entry)
{
    pamt_entry_t* pamt_entry = NULL;
    uint64_t current_4k_page_idx = ((uint64_t)pamt_block->pamt_4kb_p - tdmr_entry->pamt_4k_base)
                                    / sizeof(pamt_entry_t);
    uint64_t page_offset;
    uint32_t last_rsdv_idx = 0;

    // PAMT_CHILD_ENTRIES pamt entries take more than 1 page size, this is why
    // we need to do a new map each time we reach new page in the entries array
    // Since we work with chunks of PAMT_CHILD_ENTRIES entries it time,
    // the start address is always aligned on 4K page
    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
    uint32_t pamt_pages = (uint32_t)(num_4k_entries / pamt_entries_in_page);

    pamt_entry_t* pamt_entry_start = pamt_block->pamt_4kb_p;
    tdx_sanity_check(((uint64_t)pamt_entry_start % TDX_PAGE_SIZE_IN_BYTES) == 0,
            SCEC_PAMT_MANAGER_SOURCE, 11);
    for (uint32_t i = 0; i < pamt_pages; i++)
    {
        pamt_entry = map_pa_with_global_hkid(
                &pamt_entry_start[pamt_entries_in_page * i], TDX_RANGE_RW);
        // create a cache aligned, cache sized chunk and fill it with 'val'
        ALIGN(MOVDIR64_CHUNK_SIZE) pamt_entry_t chunk[PAMT_4K_ENTRIES_IN_CACHE];
        basic_memset((uint64_t)chunk, PAMT_4K_ENTRIES_IN_CACHE*sizeof(pamt_entry_t), 0 , PAMT_4K_ENTRIES_IN_CACHE*sizeof(pamt_entry_t));
        for (uint32_t j = 0; j < pamt_entries_in_page; j++, current_4k_page_idx++)
        {
            page_offset = current_4k_page_idx * TDX_PAGE_SIZE_IN_BYTES;
            if (is_page_reserved(page_offset, tdmr_entry, &last_rsdv_idx))
            {
                chunk[j%PAMT_4K_ENTRIES_IN_CACHE].pt = PT_RSVD;
            }
            else
            {
                chunk[j%PAMT_4K_ENTRIES_IN_CACHE].pt = PT_NDA;
                last_rsdv_idx = 0;
            }
            if ((j+1)%PAMT_4K_ENTRIES_IN_CACHE == 0)
            {
                fill_cachelines_no_sfence((void*)&(pamt_entry[j-3]), (uint8_t*)chunk, 1);
            }
        }
        mfence();
        free_la(pamt_entry);
    }
}

_STATIC_INLINE_ void pamt_nodes_init(uint64_t start_pamt_4k_p, uint64_t end_pamt_4k_p,
        pamt_entry_t* nodes_array, uint64_t entries_in_node, tdmr_entry_t *tdmr_entry)
{
    pamt_entry_t* pamt_entry;

    uint64_t entries_start = (start_pamt_4k_p - tdmr_entry->pamt_4k_base) / (entries_in_node * (uint64_t)sizeof(pamt_entry_t));
    uint64_t entries_end   = (end_pamt_4k_p - tdmr_entry->pamt_4k_base) / (entries_in_node * (uint64_t)sizeof(pamt_entry_t));

    uint32_t i = 0;
    while ((entries_end - (uint64_t)i) > entries_start)
    {
        void* entry_p = &nodes_array[i];
        pamt_entry = map_pa_with_global_hkid(entry_p, TDX_RANGE_RW);
        if (is_cacheline_aligned(entry_p))
        {
            zero_cacheline(pamt_entry);
        }
        pamt_entry->pt = PT_NDA;

        free_la(pamt_entry);
        i++;
    }
}

void pamt_init(pamt_block_t* pamt_block, uint64_t num_4k_entries, tdmr_entry_t *tdmr_entry)
{
    uint64_t start_pamt_4k_p = (uint64_t)pamt_block->pamt_4kb_p;
    uint64_t end_pamt_4k_p = start_pamt_4k_p + (num_4k_entries * (uint64_t)sizeof(pamt_entry_t));

    pamt_4kb_init(pamt_block, num_4k_entries, tdmr_entry);
    pamt_nodes_init(start_pamt_4k_p, end_pamt_4k_p, pamt_block->pamt_2mb_p, PAMT_4K_ENTRIES_IN_2MB, tdmr_entry);
    pamt_nodes_init(start_pamt_4k_p, end_pamt_4k_p, pamt_block->pamt_1gb_p, PAMT_4K_ENTRIES_IN_1GB, tdmr_entry);
}

pamt_entry_t* pamt_walk(pa_t pa, pamt_block_t pamt_block, lock_type_t leaf_lock_type,
                        page_size_t* leaf_size, bool_t walk_to_leaf_size)
{
    pamt_entry_t* pamt_1gb = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);
    pamt_entry_t* pamt_2mb = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);
    pamt_entry_t* pamt_4kb = map_pa_with_global_hkid(&pamt_block.pamt_4kb_p[pa.pamt_4k.idx], TDX_RANGE_RW);

    pamt_entry_t* ret_entry_pp = NULL;
    pamt_entry_t* ret_entry_lp = NULL;

    page_size_t target_size = walk_to_leaf_size ? *leaf_size : PT_4KB;

    // Acquire PAMT 1GB entry lock as shared
    if (acquire_sharex_lock_sh(&pamt_1gb->entry_lock) != LOCK_RET_SUCCESS)
    {
        goto EXIT;
    }

    // Return pamt_1g entry if it is currently a leaf entry
    if ((pamt_1gb->pt == PT_REG) || (target_size == PT_1GB))
    {
        // Promote PAMT lock to exclusive if needed
        if ((leaf_lock_type == TDX_LOCK_EXCLUSIVE) && !promote_sharex_lock(&pamt_1gb->entry_lock))
        {
            goto EXIT_FAILURE_RELEASE_ROOT;
        }

        *leaf_size = PT_1GB;
        ret_entry_pp = pamt_block.pamt_1gb_p;

        goto EXIT;
    }

    // Acquire PAMT 2MB entry lock as shared
    if (acquire_sharex_lock_sh(&pamt_2mb->entry_lock) != LOCK_RET_SUCCESS)
    {
        goto EXIT_FAILURE_RELEASE_ROOT;
    }

    // Return pamt_2m entry if it is leaf
    if ((pamt_2mb->pt == PT_REG) || (target_size == PT_2MB))
    {
        // Promote PAMT lock to exclusive if needed
        if ((leaf_lock_type == TDX_LOCK_EXCLUSIVE) && !promote_sharex_lock(&pamt_2mb->entry_lock))
        {
            goto EXIT_FAILURE_RELEASE_ALL;
        }

        *leaf_size = PT_2MB;
        ret_entry_pp = &pamt_block.pamt_2mb_p[pa.pamt_2m.idx];

        goto EXIT;
    }

    // Acquire PAMT 4KB entry lock as shared/exclusive based on the lock flag
    if (acquire_sharex_lock(&pamt_4kb->entry_lock, leaf_lock_type) != LOCK_RET_SUCCESS)
    {
        goto EXIT_FAILURE_RELEASE_ALL;
    }

    *leaf_size = PT_4KB;
    ret_entry_pp = &pamt_block.pamt_4kb_p[pa.pamt_4k.idx];

    goto EXIT;

EXIT_FAILURE_RELEASE_ALL:
    // Release PAMT 2MB shared lock
    release_sharex_lock_sh(&pamt_2mb->entry_lock);
EXIT_FAILURE_RELEASE_ROOT:
    // Release PAMT 1GB shared lock
    release_sharex_lock_sh(&pamt_1gb->entry_lock);

EXIT:
    free_la(pamt_1gb);
    free_la(pamt_2mb);
    free_la(pamt_4kb);

    if (ret_entry_pp != NULL)
    {
        ret_entry_lp = map_pa_with_global_hkid(ret_entry_pp,
                (leaf_lock_type == TDX_LOCK_EXCLUSIVE) ? TDX_RANGE_RW : TDX_RANGE_RO);
    }

    return ret_entry_lp;
}

void pamt_unwalk(pa_t pa, pamt_block_t pamt_block, pamt_entry_t* pamt_entry_p,
                 lock_type_t leaf_lock_type, page_size_t leaf_size)
{
    pamt_entry_t* pamt_1gb = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);
    pamt_entry_t* pamt_2mb = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);
    pamt_entry_t* pamt_4kb = map_pa_with_global_hkid(&pamt_block.pamt_4kb_p[pa.pamt_4k.idx], TDX_RANGE_RW);

    switch (leaf_size)
    {
        case PT_4KB:
            release_sharex_lock(&pamt_4kb->entry_lock, leaf_lock_type);
            release_sharex_lock_sh(&pamt_2mb->entry_lock);
            release_sharex_lock_sh(&pamt_1gb->entry_lock);

            break;

        case PT_2MB:
            release_sharex_lock(&pamt_2mb->entry_lock, leaf_lock_type);
            release_sharex_lock_sh(&pamt_1gb->entry_lock);

            break;

        case PT_1GB:
            release_sharex_lock(&pamt_1gb->entry_lock, leaf_lock_type);

            break;

        default:
            tdx_sanity_check(0, SCEC_PAMT_MANAGER_SOURCE, 2);
    }

    free_la(pamt_1gb);
    free_la(pamt_2mb);
    free_la(pamt_4kb);

    free_la(pamt_entry_p);

    return;

}

bool_t pamt_promote(pa_t pa, page_size_t new_leaf_size, pamt_block_t pamt_block)
{
    pamt_entry_t* promoted_pamt_entry = NULL;
    pamt_entry_t* pamt_entry_children_pa = NULL;
    pamt_entry_t* pamt_entry_children_la = NULL;
    bool_t status = false;

    tdx_sanity_check((new_leaf_size == PT_2MB) || (new_leaf_size == PT_1GB), SCEC_PAMT_MANAGER_SOURCE, 3);

    if (new_leaf_size == PT_2MB)
    {
        promoted_pamt_entry = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);
        pamt_entry_children_pa = &pamt_block.pamt_4kb_p[pa.pamt_4k.idx];
    }
    else if (new_leaf_size == PT_1GB)
    {
        promoted_pamt_entry = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);
        pamt_entry_children_pa = &pamt_block.pamt_2mb_p[pa.pamt_2m.idx];
    }

    tdx_sanity_check(promoted_pamt_entry->pt == PT_NDA, SCEC_PAMT_MANAGER_SOURCE, 4);

    // Acquire exclusive lock on the promoted entry
    if (acquire_sharex_lock_ex(&promoted_pamt_entry->entry_lock) != LOCK_RET_SUCCESS)
    {
        goto EXIT;
    }

    // PAMT_CHILD_ENTRIES pamt entries take more than 1 page size, this is why
    // we need to do a new map each time we reach new page in the entries array
    // Since we work with chunks of PAMT_CHILD_ENTRIES entries it time,
    // the start address is always aligned on 4K page
    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
    uint32_t pamt_pages = PAMT_CHILD_ENTRIES / pamt_entries_in_page;

    tdx_sanity_check(((uint64_t)pamt_entry_children_pa % TDX_PAGE_SIZE_IN_BYTES) == 0,
            SCEC_PAMT_MANAGER_SOURCE, 5);

    for (uint32_t i = 0; i < pamt_pages; i++)
    {
        pamt_entry_children_la = map_pa_with_global_hkid(
                &pamt_entry_children_pa[pamt_entries_in_page * i], TDX_RANGE_RW);

        for (uint32_t j = 0; j < pamt_entries_in_page; j++)
        {
            if (i == 0 && j == 0)
            {
                // Copy the first child leaf metadata to the merged new leaf entry
                // making its page type PT_REG and inheriting its owner
                promoted_pamt_entry->pt = pamt_entry_children_la[0].pt;
                promoted_pamt_entry->owner = pamt_entry_children_la[0].owner;
            }

            tdx_sanity_check((promoted_pamt_entry->pt == pamt_entry_children_la[j].pt) &&
                       (promoted_pamt_entry->owner == pamt_entry_children_la[j].owner),
                       SCEC_PAMT_MANAGER_SOURCE, 6);

            pamt_entry_children_la[j].pt = PT_NDA;
        }

        free_la(pamt_entry_children_la);
    }

    // Release previously acquired exclusive lock
    release_sharex_lock_ex(&promoted_pamt_entry->entry_lock);

    status = true;

EXIT:
    free_la(promoted_pamt_entry);

    return status;
}

bool_t pamt_demote(pa_t pa, page_size_t leaf_size, pamt_block_t pamt_block)
{
    pamt_entry_t* demoted_pamt_entry = NULL;
    pamt_entry_t* pamt_entry_children_pa = NULL;
    pamt_entry_t* pamt_entry_children_la = NULL;
    bool_t status = false;

    tdx_sanity_check((leaf_size == PT_2MB) || (leaf_size == PT_1GB), SCEC_PAMT_MANAGER_SOURCE, 7);

    if (leaf_size == PT_2MB)
    {
        demoted_pamt_entry = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);
        pamt_entry_children_pa = &pamt_block.pamt_4kb_p[pa.pamt_4k.idx];
    }
    else if (leaf_size == PT_1GB)
    {
        demoted_pamt_entry = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);
        pamt_entry_children_pa = &pamt_block.pamt_2mb_p[pa.pamt_2m.idx];
    }

    tdx_sanity_check(demoted_pamt_entry->pt == PT_REG, SCEC_PAMT_MANAGER_SOURCE, 8);

    // Acquire exclusive lock on the demoted entry
    if (acquire_sharex_lock_ex(&demoted_pamt_entry->entry_lock) != LOCK_RET_SUCCESS)
    {
        goto EXIT;
    }

    // PAMT_CHILD_ENTRIES pamt entries take more than 1 page size, this is why
    // we need to do a new map each time we reach new page in the entries array
    // Since we work with chunks of PAMT_CHILD_ENTRIES entries it time,
    // the start address is always aligned on 4K page
    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
    uint32_t pamt_pages = PAMT_CHILD_ENTRIES / pamt_entries_in_page;

    tdx_sanity_check(((uint64_t)pamt_entry_children_pa % TDX_PAGE_SIZE_IN_BYTES) == 0,
            SCEC_PAMT_MANAGER_SOURCE, 9);

    for (uint32_t i = 0; i < pamt_pages; i++)
    {
        pamt_entry_children_la = map_pa_with_global_hkid(
                &pamt_entry_children_pa[pamt_entries_in_page * i], TDX_RANGE_RW);

        for (uint32_t j = 0; j < pamt_entries_in_page; j++)
        {
            // Copy the leaf entry metadata to its 512 child entries
            pamt_entry_children_la[j].pt = demoted_pamt_entry->pt;
            pamt_entry_children_la[j].owner = demoted_pamt_entry->owner;
        }

        free_la(pamt_entry_children_la);
    }

    // Convert parent entry type from regular to NDA
    demoted_pamt_entry->pt = PT_NDA;

    // Release previously acquired exclusive lock
    release_sharex_lock_ex(&demoted_pamt_entry->entry_lock);

    status = true;

EXIT:

    free_la(demoted_pamt_entry);
    return status;

}

pamt_entry_t* pamt_implicit_get(pa_t pa, page_size_t leaf_size)
{
    pamt_block_t pamt_block;

    if (!pamt_get_block(pa, &pamt_block))
    {
        FATAL_ERROR(); // PAMT block not found or not initialized
    }

    pamt_entry_t* pamt_entry_p = NULL;

    switch (leaf_size)
    {
        case PT_1GB:
            pamt_entry_p = map_pa_with_global_hkid(pamt_block.pamt_1gb_p, TDX_RANGE_RW);
            break;
        case PT_2MB:
            pamt_entry_p = map_pa_with_global_hkid(&pamt_block.pamt_2mb_p[pa.pamt_2m.idx], TDX_RANGE_RW);
            break;
        case PT_4KB:
            pamt_entry_p = map_pa_with_global_hkid(&pamt_block.pamt_4kb_p[pa.pamt_4k.idx], TDX_RANGE_RW);
            break;
        default:
            FATAL_ERROR();
            break;
    }

    tdx_sanity_check((pamt_entry_p->pt != PT_NDA) && (pamt_entry_p->pt != PT_RSVD), SCEC_PAMT_MANAGER_SOURCE, 10);

    return pamt_entry_p;
}

pamt_entry_t* pamt_implicit_get_and_lock(pa_t pa, page_size_t leaf_size, lock_type_t leaf_lock_type)
{
    pamt_entry_t* pamt_entry = pamt_implicit_get(pa, leaf_size);

    if (acquire_sharex_lock(&pamt_entry->entry_lock, leaf_lock_type) != LOCK_RET_SUCCESS)
    {
        free_la(pamt_entry);
        return NULL;
    }

    return pamt_entry;
}

void pamt_implicit_release_lock(pamt_entry_t* pamt_entry, lock_type_t leaf_lock_type)
{
    release_sharex_lock(&pamt_entry->entry_lock, leaf_lock_type);

    free_la(pamt_entry);
}

bool_t pamt_is_2mb_range_free(pa_t hpa, pamt_block_t* pamt_block)
{
    pamt_entry_t* pamt_entry_children_la;
    pamt_entry_t* pamt_entry_children_pa = &pamt_block->pamt_4kb_p[hpa.pamt_4k.idx];
    uint32_t pamt_entries_in_page = TDX_PAGE_SIZE_IN_BYTES / sizeof(pamt_entry_t);
    uint32_t pamt_pages = PAMT_CHILD_ENTRIES / pamt_entries_in_page;

    tdx_sanity_check(((uint64_t)pamt_entry_children_pa % TDX_PAGE_SIZE_IN_BYTES) == 0,
                     SCEC_HELPERS_SOURCE, 3);

    for (uint32_t i = 0; i < pamt_pages; i++)
    {
        pamt_entry_children_la = map_pa_with_global_hkid(&pamt_entry_children_pa[pamt_entries_in_page * i], TDX_RANGE_RO);

        for (uint32_t j = 0; j < pamt_entries_in_page; j++)
        {
            // Check the leaf entry is not directly assigned
            if (pamt_entry_children_la[j].pt != PT_NDA)
            {
                TDX_ERROR("Page %d in range is not NDA!\n", (i * pamt_entries_in_page) + j);
                free_la(pamt_entry_children_la);
                return false;
            }
        }
        free_la(pamt_entry_children_la);
    }

    return true;
}
