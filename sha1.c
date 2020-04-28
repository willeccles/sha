// Compiled with -O3 -W -Wall -pedantic

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

// number of bytes per chunk
#define CHUNK_SIZE (512/CHAR_BIT)

// left rotate function
// Source: https://en.wikipedia.org/wiki/Circular_shift
uint32_t rotl32 (uint32_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
    count &= mask;
    return (value << count) | (value >> (-count & mask));
}

// gets the k_t for a given value t
static inline uint32_t k_t(int t) {
    if (t >= 0 && t <= 19) {
        return 0x5A827999;
    } else if (t >= 20 && t <= 39) {
        return 0x6ED9EBA1;
    } else if (t >= 40 && t <= 59) {
        return 0x8F1BBCDC;
    } else if (t >= 60 && t <= 79) {
        return 0xCA62C1D6;
    }

    // make the compiler happy, but t should never be >79
    return 0;
}

// computes f_t for the values B, C, and D given a value for t
static inline uint32_t f_t(uint32_t B, uint32_t C, uint32_t D, int t) {
    if (t >= 0 && t <= 19) {
        return (B & C) | (~B & D);
    } else if ((t >= 20 && t <= 39) || (t >= 60 && t <= 79)) {
        return B ^ C ^ D;
    } else if (t >= 40 && t <= 59) {
        return (B & C) | (B & D) | (C & D);
    }

    // keep compiler happy, but t should be in [0, 80)
    return 0;
}

static uint32_t H0 = 0x67452301;
static uint32_t H1 = 0xEFCDAB89;
static uint32_t H2 = 0x98BADCFE;
static uint32_t H3 = 0x10325476;
static uint32_t H4 = 0xC3D2E1F0;

// chunk = 512 bits of data
static void processchunk(const unsigned char* chunk) {
    // 80x 32-bit words
    uint32_t w[80] = {0};
    for (int i = 0; i < 16; i++) {
        w[i] =  ((uint32_t)chunk[i*4]) << 24;
        w[i] |= ((uint32_t)chunk[i*4+1]) << 16;
        w[i] |= ((uint32_t)chunk[i*4+2]) << 8;
        w[i] |= ((uint32_t)chunk[i*4+3]);
    }

    for (int i = 16; i < 80; i++) {
        w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    uint32_t a = H0;
    uint32_t b = H1;
    uint32_t c = H2;
    uint32_t d = H3;
    uint32_t e = H4;

    uint32_t k, f, tmp;
    for (int t = 0; t < 80; t++) {
        k = k_t(t);
        f = f_t(b, c, d, t);
        tmp = rotl32(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = tmp;
    }

    H0 += a;
    H1 += b;
    H2 += c;
    H3 += d;
    H4 += e;
}

int main(int argc, char** argv) {
    if (argc == 1) {
        fprintf(stderr, "usage: %s [message]\n"
                "     message: the message to compute the SHA1 hash of\n",
                argv[0]);
        return 1;
    }

    /* This program does not load the entire message into memory at any
     * point (except for wherever it's located in argv). Instead, we will
     * effectively consider this a stream of chunks to operate on. This
     * has the side effect of significantly complicating the process of
     * appending the data, as we need to deal with it one chunk at a time.
     */

    // alias m -> argv
    char* m = argv[1];

    // length of m as appended to m
    uint64_t m_bits = strlen(m) * CHAR_BIT;
    
    size_t m_rem = strlen(m);
    unsigned char chunk[CHUNK_SIZE] = {0};

    while (m_rem >= CHUNK_SIZE) {
        m_rem -= CHUNK_SIZE;
        strncpy((char*)chunk, m, CHUNK_SIZE);
        processchunk(chunk);
        m += CHUNK_SIZE;
    }

    // copy the remaining bit of data into the last chunk
    // doing 512 will fill with 0 if none left
    strncpy((char*)chunk, m, CHUNK_SIZE);

    // we don't need to explicitly zero-pad because the strncpy fills
    // the zeroes after the end of the remaining data
    // we can just add the 1
    chunk[m_rem] = 0x80;

    // if there is no space for the 8 bytes of size data, we need to
    // process this as-is and then make another chunk of data for the
    // message length, unfortunately
    if (m_rem+1 > CHUNK_SIZE-8) {
        processchunk(chunk);
        memset(chunk, 0, CHUNK_SIZE);
    }

    // m_bits needs to be converted to big-endian, but since
    // we are putting it into an array of bytes this is super easy
    for (int i = 7; i >= 0; i--) {
        chunk[(CHUNK_SIZE - 8) + (7 - i)] = (m_bits >> (8 * i)) & 0xFF;
    }

    processchunk(chunk);

    printf("%08x%08x%08x%08x%08x\n", H0, H1, H2, H3, H4);

    return 0;
}
