// Compiled with -O3 -W -Wall -pedantic

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// number of bytes per chunk
#define CHUNK_SIZE (512/CHAR_BIT)

// round constants:
// first 32 bits of the fractional parts of the cube roots of the first
// 64 primes 2..311
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// these are the first 32 bits of the fractional parts of the
// square roots of the first 8 primes 2..19
static uint32_t H0 = 0x6a09e667;
static uint32_t H1 = 0xbb67ae85;
static uint32_t H2 = 0x3c6ef372;
static uint32_t H3 = 0xa54ff53a;
static uint32_t H4 = 0x510e527f;
static uint32_t H5 = 0x9b05688c;
static uint32_t H6 = 0x1f83d9ab;
static uint32_t H7 = 0x5be0cd19;

// right rotate function
// Source: https://en.wikipedia.org/wiki/Circular_shift
uint32_t rotr32 (uint32_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
    count &= mask;
    return (value >> count) | (value << (-count & mask));
}

// chunk = 512 bits of data
static void processchunk(const unsigned char* chunk) {
    // 64x 32-bit words
    uint32_t w[64] = {0};
    for (int i = 0; i < 16; i++) {
        w[i] =  ((uint32_t)chunk[i*4]) << 24;
        w[i] |= ((uint32_t)chunk[i*4+1]) << 16;
        w[i] |= ((uint32_t)chunk[i*4+2]) << 8;
        w[i] |= ((uint32_t)chunk[i*4+3]);
    }

    uint32_t s0, s1;
    for (int i = 16; i < 64; i++) {
        s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a = H0;
    uint32_t b = H1;
    uint32_t c = H2;
    uint32_t d = H3;
    uint32_t e = H4;
    uint32_t f = H5;
    uint32_t g = H6;
    uint32_t h = H7;

    uint32_t ch, tmp1, tmp2, maj;
    for (int t = 0; t < 64; t++) {
        s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        ch = (e & f) ^ (~e & g);
        tmp1 = h + s1 + ch + k[t] + w[t];
        s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        tmp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
    }

    H0 += a;
    H1 += b;
    H2 += c;
    H3 += d;
    H4 += e;
    H5 += f;
    H6 += g;
    H7 += h;
}

int main(int argc, char** argv) {
    if (argc == 1) {
        fprintf(stderr, "usage: %s [message]\n"
                "     message: the message to compute the SHA-256 hash of\n",
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

    printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", H0, H1, H2, H3, H4, H5, H6, H7);

    return 0;
}
