// Intel Proprietary 
// 
// Copyright 2021 Intel Corporation All Rights Reserved.
// 
// Your use of this software is governed by the TDX Source Code LIMITED USE LICENSE.
// 
// The Materials are provided “as is,” without any express or implied warranty of any kind including warranties
// of merchantability, non-infringement, title, or fitness for a particular purpose.

/**
 * @file sha384.c
 * @brief Crypto implementation of SHA384
 */

#include "crypto/sha384.h"
#include "helpers/helpers.h"
#include "ippcp.h"

static IppsHashMethod* sha384_get_global_method(void)
{
    int32_t method_buffer_size;
    IppStatus ret_val = ippStsErr;

    hash_method_t* sha384_method = &get_global_data()->sha384_method;
    IppsHashMethod* hash_method_ptr = (IppsHashMethod*)sha384_method->hash_method_buffer;

    if (sha384_method->is_initialized)
    {
        return hash_method_ptr;
    }

    ret_val = ippsHashMethodGetSize(&method_buffer_size);

    if (ret_val != ippStsNoErr || method_buffer_size > (int32_t)HASH_METHOD_BUFFER_SIZE)
    {
        TDX_ERROR("Required method buffer size is %d\n", method_buffer_size);
        return NULL;
    }

    ret_val = ippsHashMethodSet_SHA384(hash_method_ptr);
    if (ret_val != ippStsNoErr)
    {
        TDX_ERROR("SHA384 Method setting failed\n");
        return NULL;
    }

    sha384_method->is_initialized = true;

    return hash_method_ptr;
}

crypto_api_error sha384_init(sha384_ctx_t * ctx)
{
    sha384_ctx_t local_ctx;
    int32_t ctx_size = 0;
    IppStatus ret_val = ippStsErr;

    IppsHashMethod* hash_method = sha384_get_global_method();
    if (hash_method == NULL)
    {
        goto EXIT;
    }

    // Zero initial local context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    ret_val = ippsHashGetSize_rmf(&ctx_size);

    if ((ret_val != ippStsNoErr) || (ctx_size <= 0) || ((uint32_t)ctx_size > sizeof(sha384_ctx_t)))
    {
        goto EXIT_NO_COPY;
    }

    IppsHashState_rmf* ipp_hash_state = (IppsHashState_rmf*)(local_ctx.buffer);

    // Init the sha context
    ret_val = ippsHashInit_rmf(ipp_hash_state, hash_method);

    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

EXIT:

    // Copy context from stack
    if (ret_val == ippStsNoErr)
    {
        ret_val = ippsHashPack_rmf(ipp_hash_state, (Ipp8u*)ctx->buffer, sizeof(sha384_ctx_t));
    }

EXIT_NO_COPY:

    // Clear context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    return ret_val;
}


crypto_api_error sha384_update_128B(sha384_ctx_t * ctx,
                                    const sha384_128B_block_t * blocks,
                                    uint32_t num_of_blocks)
{
    sha384_ctx_t local_ctx;
    int32_t ctx_size = 0;
    IppStatus ret_val = ippStsErr;

    ret_val = ippsHashGetSize_rmf(&ctx_size);

    if ((ret_val != ippStsNoErr) || (ctx_size <= 0) || ((uint32_t)ctx_size > sizeof(sha384_ctx_t)))
    {
        goto EXIT_NO_COPY;
    }

    // Copy context to stack
    IppsHashState_rmf* ipp_hash_state = (IppsHashState_rmf*)(local_ctx.buffer);

    ret_val = ippsHashUnpack_rmf(ctx->buffer, ipp_hash_state);
    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

    for (uint32_t i = 0; i < num_of_blocks; i++)
    {
        ret_val = ippsHashUpdate_rmf((const Ipp8u*)blocks[i].block_byte_buffer,
                                     (int)SIZE_OF_SHA384_BLOCK_IN_BYTES,
                                     ipp_hash_state);
        if (ret_val != ippStsNoErr)
        {
            goto EXIT;
        }
    }

EXIT:

    // Copy context from stack
    if (ret_val == ippStsNoErr)
    {
        ret_val = ippsHashPack_rmf(ipp_hash_state, (Ipp8u*)ctx->buffer, sizeof(sha384_ctx_t));
    }

EXIT_NO_COPY:

    // Clear context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    return ret_val;
}


crypto_api_error sha384_finalize(sha384_ctx_t * ctx, uint64_t * hash)
{
    sha384_ctx_t local_ctx;
    int32_t ctx_size = 0;
    IppStatus ret_val = ippStsErr;

    ret_val = ippsHashGetSize_rmf(&ctx_size);

    if ((ret_val != ippStsNoErr) || (ctx_size <= 0) || ((uint32_t)ctx_size > sizeof(sha384_ctx_t)))
    {
        goto EXIT_NO_COPY;
    }

    // Copy context to stack
    IppsHashState_rmf* ipp_hash_state = (IppsHashState_rmf*)(local_ctx.buffer);

    ret_val = ippsHashUnpack_rmf(ctx->buffer, ipp_hash_state);
    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

    ret_val = ippsHashFinal_rmf((Ipp8u*)hash, ipp_hash_state);
    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

EXIT:

    // Copy context from stack
    if (ret_val == ippStsNoErr)
    {
        ret_val = ippsHashPack_rmf(ipp_hash_state, (Ipp8u*)ctx->buffer, sizeof(sha384_ctx_t));
    }

EXIT_NO_COPY:

    // Clear context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    return ret_val;
}


crypto_api_error sha384_generate_hash_128B(const sha384_128B_block_t * blocks,
                                           uint32_t num_of_blocks,
                                           uint64_t * hash)
{
    IppStatus ret_val = ippStsErr;
    int32_t ctx_size = 0;
    sha384_ctx_t local_ctx;

    IppsHashMethod* hash_method = sha384_get_global_method();
    if (hash_method == NULL)
    {
        goto EXIT;
    }

    ret_val = ippsHashGetSize_rmf(&ctx_size);

    if ((ret_val != ippStsNoErr) || (ctx_size <= 0) || ((uint32_t)ctx_size > sizeof(sha384_ctx_t)))
    {
        goto EXIT;
    }

    IppsHashState_rmf* ipp_hash_state = (IppsHashState_rmf*)(local_ctx.buffer);

    // Init the sha context
    ret_val = ippsHashInit_rmf(ipp_hash_state, hash_method);
    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

    for (uint32_t i = 0; i < num_of_blocks; i++)
    {
        ret_val = ippsHashUpdate_rmf((const Ipp8u*)blocks[i].block_byte_buffer,
                                     (int)SIZE_OF_SHA384_BLOCK_IN_BYTES,
                                     ipp_hash_state);
        if (ret_val != ippStsNoErr)
        {
            goto EXIT;
        }
    }

    ret_val = ippsHashFinal_rmf((Ipp8u*)hash, ipp_hash_state);
    if (ret_val != ippStsNoErr)
    {
        goto EXIT;
    }

EXIT:

    // Clear context
    basic_memset_to_zero(local_ctx.buffer, SIZE_OF_SHA384_CTX_BUFFER);

    return ret_val;
}


crypto_api_error sha384_generate_hash(const uint8_t * block,
                                      uint32_t block_size,
                                      uint64_t * hash)
{
    IppsHashMethod* hash_method = sha384_get_global_method();
    if (hash_method == NULL)
    {
        return ippStsErr;
    }

    return ippsHashMessage_rmf(block, (int)block_size, (Ipp8u*)hash, hash_method);
}

