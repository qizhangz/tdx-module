// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file tdx_locks.h
 * @brief TDX Locks Definitions
 */

#ifndef SRC_COMMON_HELPERS_TDX_LOCKS_H_
#define SRC_COMMON_HELPERS_TDX_LOCKS_H_

#include "tdx_basic_types.h"
#include "tdx_basic_defs.h"

#include "accessors/ia32_accessors.h"
#include "debug/tdx_debug.h"
#include "helpers/error_reporting.h"

typedef enum
{
    TDX_LOCK_SHARED = 0,
    TDX_LOCK_EXCLUSIVE = 1
} lock_type_t;

typedef enum
{
    LOCK_RET_FAIL, LOCK_RET_SUCCESS
} lock_return_t;

typedef uint8_t mutex_lock_t;

typedef enum
{
    MUTEX_FREE = 0, MUTEX_LOCK = 1
} mutex_state_t;


_STATIC_INLINE_ lock_return_t acquire_mutex_lock(mutex_lock_t * lock_ptr)
{
    mutex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval = _lock_cmpxchg_8bit(MUTEX_FREE, MUTEX_LOCK, lock_ptr);

    return (retval == MUTEX_FREE) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

#if defined(DEBUGFEATURE_TDX_DBG_TRACE)
_STATIC_INLINE_ lock_return_t acquire_mutex_lock_or_wait(mutex_lock_t * lock_ptr)
{
    mutex_lock_t retval = MUTEX_LOCK;

    tdx_debug_assert(lock_ptr != NULL);

    while (retval != MUTEX_FREE)
    {
        retval = _lock_cmpxchg_8bit(MUTEX_FREE, MUTEX_LOCK, lock_ptr);

        if (retval != MUTEX_FREE)
        {
            ia32_pause();
        }
    }

    return LOCK_RET_SUCCESS;
}
#endif

_STATIC_INLINE_ void release_mutex_lock(mutex_lock_t * lock_ptr)
{
    mutex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval = _lock_cmpxchg_8bit(MUTEX_LOCK, MUTEX_FREE, lock_ptr);

    // Check that the previous lock was actually taken
    tdx_sanity_check((retval == MUTEX_LOCK), SCEC_LOCK_SOURCE, 0);
}

//Sharex lock layout:  [ Readers count [14:1] |  Exclusive lock [0] ]
typedef enum
{
    SHAREX_FREE = 0, SHAREX_SINGLE_READER = BIT(1), SHAREX_EXCLUSIVE_LOCK = BIT(0)
} sharex_state_t;


typedef union ALIGN(2)
{
    struct
    {
        uint16_t exclusive :1;
        uint16_t counter   :15;
    };
    uint16_t raw;
} sharex_lock_t;

#define SHAREX_FULL_COUNTER_NO_WRITER  0xFFFE

_STATIC_INLINE_ lock_return_t acquire_sharex_lock_sh(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_xadd_16b(&lock_ptr->raw, 2);

    // Check that we don't overflow the counter when only readers are on the lock
    tdx_sanity_check((retval.raw != SHAREX_FULL_COUNTER_NO_WRITER), SCEC_LOCK_SOURCE, 1);

    return (retval.exclusive == 0) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

_STATIC_INLINE_ lock_return_t acquire_sharex_lock_ex(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_cmpxchg_16b(SHAREX_FREE, SHAREX_EXCLUSIVE_LOCK, &lock_ptr->raw);

    return (retval.raw == SHAREX_FREE) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

_STATIC_INLINE_ lock_return_t acquire_sharex_lock(sharex_lock_t * lock_ptr, lock_type_t lock_type)
{
    if (lock_type == TDX_LOCK_EXCLUSIVE)
    {
        return acquire_sharex_lock_ex(lock_ptr);
    }
    else if (lock_type == TDX_LOCK_SHARED)
    {
        return acquire_sharex_lock_sh(lock_ptr);
    }

    tdx_sanity_check(0, SCEC_LOCK_SOURCE, 2);

    // Not supposed to return this after sanity check
    return LOCK_RET_FAIL;
}

_STATIC_INLINE_ void release_sharex_lock_sh(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_xadd_16b(&lock_ptr->raw, (uint16_t)-2);

    // Check that the previous lock wasn't exclusively taken, or wasn't taken at all
    tdx_sanity_check(!(retval.exclusive == 1 || retval.counter == 0), SCEC_LOCK_SOURCE, 3);
}

_STATIC_INLINE_ void release_sharex_lock_ex(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _xchg_16b(&lock_ptr->raw, SHAREX_FREE);

    //Check if lock wasn't free, or shared
    tdx_sanity_check(retval.exclusive == 1, SCEC_LOCK_SOURCE, 4);
}

_STATIC_INLINE_ void release_sharex_lock(sharex_lock_t * lock_ptr, lock_type_t lock_type)
{
    if (lock_type == TDX_LOCK_EXCLUSIVE)
    {
        release_sharex_lock_ex(lock_ptr);
    }
    else if (lock_type == TDX_LOCK_SHARED)
    {
        release_sharex_lock_sh(lock_ptr);
    }
    else
    {
        tdx_sanity_check(0, SCEC_LOCK_SOURCE, 5);
    }
}

_STATIC_INLINE_ lock_return_t promote_sharex_lock(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _lock_cmpxchg_16b(SHAREX_SINGLE_READER, SHAREX_EXCLUSIVE_LOCK, &lock_ptr->raw);

    //Check if lock was already exclusive or free
    tdx_sanity_check(!(retval.exclusive == 1 || retval.raw == SHAREX_FREE), SCEC_LOCK_SOURCE, 6);

    return (retval.counter == 1) ? LOCK_RET_SUCCESS : LOCK_RET_FAIL;
}

_STATIC_INLINE_ lock_return_t demote_sharex_lock(sharex_lock_t * lock_ptr)
{
    sharex_lock_t retval;

    tdx_debug_assert(lock_ptr != NULL);

    retval.raw = _xchg_16b(&lock_ptr->raw, SHAREX_SINGLE_READER);

    //Check if lock wasn't free, or shared
    tdx_sanity_check(retval.exclusive == 1, SCEC_LOCK_SOURCE, 7);

    return LOCK_RET_SUCCESS;
}

#endif /* SRC_COMMON_HELPERS_TDX_LOCKS_H_ */
