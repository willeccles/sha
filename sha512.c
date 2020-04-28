// Compiled with -O3 -W -Wall -pedantic
// The differences between SHA-256 and 512 are as follows:
//  - Messages are broken into 1024 bit chunks instead of 512
//  - Hash values and constants are 64 bits
//  - 80 rounds as opposed to 64
//  - w[] has 80x 64-bit words instead of 64x 32-bit
//  - 80 primes instead of 64 (because 80 rounds)
//  - 64 bit words everywhere
//  - Length of the message is a 128-bit integer (we will use 64 bits
//    and pad with zeroes because I'm too lazy to do the real math here)
//  - rotates and shifts are different lengths

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// number of bytes per chunk
#define CHUNK_SIZE (1024/CHAR_BIT)

// round constants:
// first 64 bits of the fractional parts of the cube roots of the first
// 80 primes 2..409
static const uint64_t k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

// these are the first 32 bits of the fractional parts of the
// square roots of the first 8 primes 2..19
static uint64_t H0 = 0x6a09e667f3bcc908;
static uint64_t H1 = 0xbb67ae8584caa73b;
static uint64_t H2 = 0x3c6ef372fe94f82b;
static uint64_t H3 = 0xa54ff53a5f1d36f1;
static uint64_t H4 = 0x510e527fade682d1;
static uint64_t H5 = 0x9b05688c2b3e6c1f;
static uint64_t H6 = 0x1f83d9abfb41bd6b;
static uint64_t H7 = 0x5be0cd19137e2179;

// right rotate function
// Source: https://en.wikipedia.org/wiki/Circular_shift
uint64_t rotr64 (uint64_t value, unsigned int count) {
    const unsigned int mask = CHAR_BIT * sizeof(value) - 1;
    count &= mask;
    return (value >> count) | (value << (-count & mask));
}

// chunk = 1024 bits of data (SHA-512 uses bigger chunks)
static void processchunk(const unsigned char* chunk) {
    // 80x 64-bit words
    uint64_t w[80] = {0};
    for (int i = 0; i < 16; i++) {
        w[i]  = ((uint64_t)chunk[i*8]) << 56;
        w[i] |= ((uint64_t)chunk[i*8+1]) << 48;
        w[i] |= ((uint64_t)chunk[i*8+2]) << 40;
        w[i] |= ((uint64_t)chunk[i*8+3]) << 32;
        w[i] |= ((uint64_t)chunk[i*8+4]) << 24;
        w[i] |= ((uint64_t)chunk[i*8+5]) << 16;
        w[i] |= ((uint64_t)chunk[i*8+6]) << 8;
        w[i] |= ((uint64_t)chunk[i*8+7]);
    }

    uint64_t s0, s1;
    for (int i = 16; i < 80; i++) {
        s0 = rotr64(w[i-15], 1) ^ rotr64(w[i-15], 8) ^ (w[i-15] >> 7);
        s1 = rotr64(w[i-2], 19) ^ rotr64(w[i-2], 61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint64_t a = H0;
    uint64_t b = H1;
    uint64_t c = H2;
    uint64_t d = H3;
    uint64_t e = H4;
    uint64_t f = H5;
    uint64_t g = H6;
    uint64_t h = H7;

    uint64_t ch, tmp1, tmp2, maj;
    for (int t = 0; t < 80; t++) {
        s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        ch = (e & f) ^ (~e & g);
        tmp1 = h + s1 + ch + k[t] + w[t];
        s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
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
                "     message: the message to compute the SHA-512 hash of\n",
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
    // doing CHUNK_SIZE will fill with 0 if none left
    strncpy((char*)chunk, m, CHUNK_SIZE);

    // we don't need to explicitly zero-pad because the strncpy fills
    // the zeroes after the end of the remaining data
    // we can just add the 1
    chunk[m_rem] = 0x80;

    // if there is no space for the 16 bytes of size data, we need to
    // process this as-is and then make another chunk of data for the
    // message length, unfortunately
    if (m_rem+1 > CHUNK_SIZE-16) {
        processchunk(chunk);
        memset(chunk, 0, CHUNK_SIZE);
    }

    // m_bits needs to be converted to big-endian, but since
    // we are putting it into an array of bytes this is super easy
    // we are using 64 bits here assuming a padding of zeros to the left
    // this way I don't have to deal with a 128-bit integer
    for (int i = 7; i >= 0; i--) {
        chunk[(CHUNK_SIZE - 8) + (7 - i)] = (m_bits >> (8 * i)) & 0xFF;
    }

    processchunk(chunk);

    printf("%016llx%016llx%016llx%016llx%016llx%016llx%016llx%016llx\n",
            H0, H1, H2, H3, H4, H5, H6, H7);

    return 0;
}
