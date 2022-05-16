// ChaCha20 implementation, based on https://github.com/Ginurx/chacha20-c, unlicense license
//
// How to use:
//
// inplace encryption:
//    struct chacha20_context ctx;
//    chacha20_init_context(&ctx, key, nonce, counter);
//    chacha20_xor(&ctx, buffer, size_of_buffer);
//
/////////////
//
// raw block processing (NOT an encryption):
//    chacha20_process_block(block_of_16_uint32);
//    chacha20_xor_block(source_buffer_16_uint32, block_of_16_uint32); // xor ChaCha20 block with userdata buffer
//


#pragma once


#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>


struct chacha20_context
{
    uint32_t keystream32[16];
    size_t position;

    uint8_t key[32];
    uint8_t nonce[12];
    uint64_t counter;

    uint32_t state[16];
};


static uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t pack4(const uint8_t *a)
{
    uint32_t res = 0;
    res |= (uint32_t)a[0] << 0 * 8;
    res |= (uint32_t)a[1] << 1 * 8;
    res |= (uint32_t)a[2] << 2 * 8;
    res |= (uint32_t)a[3] << 3 * 8;
    return res;
}

static void unpack4(uint32_t src, uint8_t *dst) {
    dst[0] = (src >> 0 * 8) & 0xff;
    dst[1] = (src >> 1 * 8) & 0xff;
    dst[2] = (src >> 2 * 8) & 0xff;
    dst[3] = (src >> 3 * 8) & 0xff;
}

static void chacha20_init_block(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[])
{
    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

    const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
    ctx->state[0] = pack4(magic_constant + 0 * 4);
    ctx->state[1] = pack4(magic_constant + 1 * 4);
    ctx->state[2] = pack4(magic_constant + 2 * 4);
    ctx->state[3] = pack4(magic_constant + 3 * 4);
    ctx->state[4] = pack4(key + 0 * 4);
    ctx->state[5] = pack4(key + 1 * 4);
    ctx->state[6] = pack4(key + 2 * 4);
    ctx->state[7] = pack4(key + 3 * 4);
    ctx->state[8] = pack4(key + 4 * 4);
    ctx->state[9] = pack4(key + 5 * 4);
    ctx->state[10] = pack4(key + 6 * 4);
    ctx->state[11] = pack4(key + 7 * 4);
    // 64 bit counter initialized to zero by default.
    ctx->state[12] = 0;
    ctx->state[13] = pack4(nonce + 0 * 4);
    ctx->state[14] = pack4(nonce + 1 * 4);
    ctx->state[15] = pack4(nonce + 2 * 4);

    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

static void chacha20_block_set_counter(struct chacha20_context *ctx, uint64_t counter)
{
    ctx->state[12] = (uint32_t)counter;
    ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

static void chacha20_process_block(uint32_t block[16])
{
#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

    for (int i = 0; i < 10; i++)
    {
        CHACHA20_QUARTERROUND(block, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(block, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(block, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(block, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(block, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(block, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(block, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(block, 3, 4, 9, 14)
    }
#undef CHACHA20_QUARTERROUND
}

static void chacha20_xor_block(uint32_t dst_block[16], uint32_t src_block[16])
{
    for (int i = 0; i < 16; i++)
        dst_block[i] ^= src_block[i];
}

static void chacha20_block_next(struct chacha20_context *ctx)
{
    // This is where the crazy voodoo magic happens.
    // Mix the bytes a lot and hope that nobody finds out how to undo it.
    for (int i = 0; i < 16; i++) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

    for (int i = 0; i < 10; i++)
    {
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(ctx->keystream32, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(ctx->keystream32, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(ctx->keystream32, 3, 4, 9, 14)
    }
#undef CHACHA20_QUARTERROUND

    for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

    uint32_t *counter = ctx->state + 12;
    // increment counter
    counter[0]++;
    if (0 == counter[0])
    {
        // wrap around occured, increment higher 32 bits of counter
        counter[1]++;
        // Limited to 2^64 blocks of 64 bytes each.
        // If you want to process more than 1180591620717411303424 bytes
        // you have other problems.
        // We could keep counting with counter[2] and counter[3] (nonce),
        // but then we risk reusing the nonce which is very bad.
        assert(0 != counter[1]);
    }
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[], uint64_t counter)
{
    memset(ctx, 0, sizeof(struct chacha20_context));

    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->counter = counter;
    ctx->position = 64;
}

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes)
{
    uint8_t *keystream8 = (uint8_t*)ctx->keystream32;
    for (size_t i = 0; i < n_bytes; i++)
    {
        if (ctx->position >= 64)
        {
            chacha20_block_next(ctx);
            ctx->position = 0;
        }
        bytes[i] ^= keystream8[ctx->position];
        ctx->position++;
    }
}
