/*
 * sha256.h
 *
 *  Created on: 27 Apr 2023
 *      Author: LiorBenjamin
 *
 *  Source: https://csrc.nist.gov/csrc/media/publications/fips/180/4/final/documents/fips180-4-draft-aug2014.pdf
 */

#ifndef _SHA256_H_
#define _SHA256_H_

#include <stdint.h>

#if 0
#ifndef __likely
#define __likely(x)		(__builtin_expect((x),1))
#endif
#ifndef __unlikely
#define __unlikely(x)	(__builtin_expect((x),0))
#endif
#else
#define __likely
#define __unlikely
#endif

#define SHA256_BYTE						unsigned char
#define SHA256_WORD						unsigned int
#define SHA256_MESSAEG_DIGEST_BITS		256
#define SHA256_MESSAEG_DIGEST_WORDS		(SHA256_MESSAEG_DIGEST_BITS / (8*sizeof(SHA256_WORD))) /* 8 */

typedef struct {
	SHA256_WORD				hash[SHA256_MESSAEG_DIGEST_WORDS];
	unsigned long long		bit_len;
} SHA256_ctx;

/* initialize sha256 value */
void sha256_init(SHA256_ctx *ctx);
int sha256_cumulative_calc(SHA256_ctx *ctx, SHA256_BYTE *blk_data, uint32_t chunk_size_bytes);
int sha256_self_test();

int sha256_file(char *path, char *sha);

#endif /* _SHA256_H_ */
