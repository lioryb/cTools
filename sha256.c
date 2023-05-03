#define _CRT_SECURE_NO_WARNINGS 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

#define MAX_ADDITIVE_CONSTANTS	64
#define SHA_MAX_INT 			0xffffffff

/* word manipulations */
/**********************/

/* Shift RIGHT and LEFT */
#define _SHR(_x_, _n_)		(((_x_) >> (_n_)) & SHA_MAX_INT)
#define _SHL(_x_, _n_)   	(((_x_) << (_n_)) & SHA_MAX_INT)
/* Rotational _SHR and _SHL */
#define _ROTR(_x_, _n_)		( _SHR((_x_), (_n_)) | _SHL((_x_), (32 - (_n_))) )
#define _ROTL(_x_, _n_)		( _SHL((_x_), (_n_)) | _SHR((_x_), (32 - (_n_))) )
/* logical functions */
#define _CH(_x_, _y_, _z_)	(((_x_) & (_y_)) ^ (~(_x_) & (_z_)))
#define _MAJ(_x_, _y_, _z_)	(((_x_) & (_y_)) ^ ((_x_) & (_z_)) ^ ((_y_) & (_z_)))
/* capital letter sigma */
#define _CAPCSIG0(_x_)		(_ROTR((_x_), 2) ^ _ROTR((_x_), 13) ^ _ROTR((_x_), 22))
#define _CAPCSIG1(_x_)		(_ROTR((_x_), 6) ^ _ROTR((_x_), 11) ^ _ROTR((_x_), 25))
/* lowercase letter sigma */
#define _LOWCSIG0(_x_)		(_ROTR((_x_), 7) ^ _ROTR((_x_), 18) ^ _SHR((_x_), 3))
#define _LOWCSIG1(_x_)		(_ROTR((_x_), 17) ^ _ROTR((_x_), 19) ^ _SHR((_x_), 10))

static const uint32_t K_CONST[MAX_ADDITIVE_CONSTANTS] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define BYTE_SIZE							8
#define BYTE_TO_BIT(_x_)					((_x_) * BYTE_SIZE)
#define BIT_TO_BYTE(_x_)					(((_x_) + (BYTE_SIZE - 1)) / BYTE_SIZE)
#define BYTE_MASK							((1 << BYTE_SIZE) - 1)

#define SHA256_BLOCK_SIZE_BITS				512
#define SHA256_BLOCKS_SIZE_WORDS			(SHA256_BLOCK_SIZE_BITS / 32) /* 16 */
#define SHA256_BLOCKS_SIZE_BYTES			BIT_TO_BYTE(SHA256_BLOCK_SIZE_BITS) /* 64 */
#define SHA256_SCHEDULE_WORDS				64
#define SHA256_MSG_LENGTH_FLD_BITS			(64)
#define SHA256_MSG_LENGTH_FLD_BYTES			BIT_TO_BYTE(SHA256_MSG_LENGTH_FLD_BITS) /* 8 */
#define SHA256_MAX_LAST_BLOCK_SIZE_BITS		(SHA256_BLOCK_SIZE_BITS - SHA256_MSG_LENGTH_FLD_BITS) /* 448 */
#define SHA256_MAX_LAST_BLOCK_SIZE_BYTES	BIT_TO_BYTE(SHA256_MAX_LAST_BLOCK_SIZE_BITS) /* 56 */

enum {
	SHA256_VAR_a	= 0,
	SHA256_VAR_b	= 1,
	SHA256_VAR_c	= 2,
	SHA256_VAR_d	= 3,
	SHA256_VAR_e	= 4,
	SHA256_VAR_f	= 5,
	SHA256_VAR_g	= 6,
	SHA256_VAR_h	= 7,

	SHA256_VAR_TOTAL
};

void sha256_init(SHA256_ctx *ctx)
{
	memset(ctx, 0, sizeof(SHA256_ctx));

	ctx->hash[0] = 0x6a09e667;
	ctx->hash[1] = 0xbb67ae85;
	ctx->hash[2] = 0x3c6ef372;
	ctx->hash[3] = 0xa54ff53a;
	ctx->hash[4] = 0x510e527f;
	ctx->hash[5] = 0x9b05688c;
	ctx->hash[6] = 0x1f83d9ab;
	ctx->hash[7] = 0x5be0cd19;
}

uint32_t little_to_big_endian(uint32_t val) {
    return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
           ((val & 0xFF0000) >> 8) | ((val & 0xFF000000) >> 24);
}

void sha256_blk_calc(SHA256_ctx *ctx, SHA256_BYTE *blk_data)
{
	/* working variables */
	SHA256_WORD 	sha256_var[SHA256_VAR_TOTAL];
	/* schedule words */
	SHA256_WORD		Wt[SHA256_SCHEDULE_WORDS];
	SHA256_WORD		T1;
	SHA256_WORD		T2;
	int idx;
	int var_idx;

	/* This section implements the HASH computation per message block, as described in the above
	 * mentioned link, section 6.2.2
	 *
	 * using a context in order to allow parallel calculations (can init several context in parallel)
	 */

	/* step 1 */
	/* here, idx refers to 't' in the algorithm */
	for (idx = 0 ; idx < 16 ; idx++){
		Wt[idx] = (blk_data[idx*4+0] << 24) | (blk_data[idx*4+1] << 16) | (blk_data[idx*4+2] << 8) | (blk_data[idx*4+3]);
		//Wt[idx] = little_to_big_endian(Wt[idx]);
	}

	for ( ; idx < SHA256_SCHEDULE_WORDS ; idx++) {

		Wt[idx] = (_LOWCSIG1(Wt[idx-2]) + Wt[idx-7] +
				_LOWCSIG0(Wt[idx-15]) + Wt[idx-16]) & 0xFFFFFFFF;
	}

	/* step 2 */
	/* here, idx refers to the corresponding working variable, where
	 * 0 = a ; 1 = b ; 2 = c ; 3 = d ; 4 = e ; 5 = f ; 6 = g ; 7 = h
	 * ctx->hash is the cumulative hash, till that point */
	for (var_idx = 0 ; var_idx < SHA256_VAR_TOTAL ; var_idx++)
		sha256_var[var_idx] = ctx->hash[var_idx];

	/* step 3 */
	/* here, idx refers to 't' in the algorithm */
	for (idx = 0 ; idx < SHA256_SCHEDULE_WORDS ; idx++) {
		T1 = sha256_var[SHA256_VAR_h] + _CAPCSIG1(sha256_var[SHA256_VAR_e]) + _CH(sha256_var[SHA256_VAR_e], sha256_var[SHA256_VAR_f], sha256_var[SHA256_VAR_g]) + K_CONST[idx] + Wt[idx];
		T2 = _CAPCSIG0(sha256_var[SHA256_VAR_a]) + _MAJ(sha256_var[SHA256_VAR_a], sha256_var[SHA256_VAR_b], sha256_var[SHA256_VAR_c]);
		for (var_idx = SHA256_VAR_h ; var_idx > SHA256_VAR_a ; var_idx--)
			sha256_var[var_idx] = sha256_var[var_idx-1];
		sha256_var[SHA256_VAR_e] += T1;
		sha256_var[SHA256_VAR_a] = T1 + T2;
	}

	/* step 4 */
	for (var_idx = 0 ; var_idx < SHA256_VAR_TOTAL ; var_idx++)
		ctx->hash[var_idx] += sha256_var[var_idx];
}

int sha256_cumulative_calc(SHA256_ctx *ctx, SHA256_BYTE *blk_data, uint32_t chunk_size_bytes)
{
	uint32_t chunk_size_bits = BYTE_TO_BIT(chunk_size_bytes);
	uint32_t data_size_bits_h;
	uint32_t data_size_bits_l;
	int byte_offset;
	SHA256_BYTE* data_ptr;

	if __unlikely(chunk_size_bytes > SHA256_BLOCKS_SIZE_BYTES)
		return -1;

	if __likely(SHA256_BLOCKS_SIZE_BYTES == chunk_size_bytes) {
		sha256_blk_calc(ctx, blk_data);
		ctx->bit_len += SHA256_BLOCK_SIZE_BITS;
	}
	else {
		/* last chunk */
		union {
			SHA256_BYTE		single_access[2*SHA256_BLOCKS_SIZE_BYTES];
			SHA256_BYTE		double_access[2][SHA256_BLOCKS_SIZE_BYTES];
		} data_trailer;
		memset(data_trailer.single_access, 0, sizeof(data_trailer));
		data_ptr = &data_trailer.single_access[chunk_size_bytes];
		ctx->bit_len += chunk_size_bits;

		memcpy(data_trailer.single_access, blk_data, chunk_size_bytes);
		*data_ptr++ = 0x80;
		while ((chunk_size_bytes % SHA256_BLOCKS_SIZE_BYTES) != (SHA256_MAX_LAST_BLOCK_SIZE_BYTES-1)) {
			chunk_size_bytes++;
			*data_ptr++ = 0;
		}

		data_size_bits_h = (uint32_t)(ctx->bit_len >> 32);
		data_size_bits_l = (uint32_t)(ctx->bit_len & (unsigned int)(-1));
		for (byte_offset = 24 ; byte_offset >= 0 ; byte_offset -= 8)
			*data_ptr++ = (data_size_bits_h >> byte_offset) & BYTE_MASK;
		for (byte_offset = 24 ; byte_offset >= 0 ; byte_offset -= 8)
			*data_ptr++ = (data_size_bits_l >> byte_offset) & BYTE_MASK;

		sha256_blk_calc(ctx, data_trailer.double_access[0]);
		if (SHA256_BLOCKS_SIZE_BYTES < chunk_size_bytes)
			sha256_blk_calc(ctx, data_trailer.double_access[1]);
	}

	return 0;
}

int sha256_self_test()
{
	unsigned char expected_result[65];
	unsigned char calc_result[65];
	unsigned char test_string[512];
	SHA256_ctx sha256;

	/* case #1 - simple string, using less then a single block (up to 55 bytes) */
	sprintf((char *)test_string, "%s", "1234567890123456789012345678901234567890"); /* 40 characters */
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 40);
	sprintf((char *)expected_result, "a4ebdd541454b84cc670c9f1f5508baf67ffd3fe59b883267808781f992a0b1d");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	/* corner case is 55-56 bytes, where addition of 0x80 at the end, requires adding additional buffer */
	/* case #2 - 55 bytes - won't add another buffer */
	sprintf((char *)test_string, "%s", "1234567890123456789012345678901234567890123456789012345");
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 55);
	sprintf((char *)expected_result, "03c3a70e99ed5eeccd80f73771fcf1ece643d939d9ecc76f25544b0233f708e9");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	/* case #3 - 56 bytes - would add a second buffer */
	sprintf((char *)test_string, "%s", "12345678901234567890123456789012345678901234567890123456");
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 56);
	sprintf((char *)expected_result, "0be66ce72c2467e793202906000672306661791622e0ca9adf4a8955b2ed189c");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	/* case #3 - 60 bytes - would internally add a second buffer */
	sprintf((char *)test_string, "%s", "123456789012345678901234567890123456789012345678901234567890");
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 60);
	sprintf((char *)expected_result, "decc538c077786966ac863b5532c4027b8587ff40f6e3103379af62b44eae44d");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	/* case #4 - 100 bytes - should use 2 iterations */
	sprintf((char *)test_string, "%s", "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 64);
	sha256_cumulative_calc(&sha256, &test_string[64], (100-64));
	sprintf((char *)expected_result, "b20e12a7bcf7a0bcc5150265aab9c40b1d673781c143a73be76232d81e6038ec");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	/* case #5 - 119 bytes - should use 2 iterations, without adding 3rd buffer */
	sprintf((char *)test_string, "%s", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 64);
	sha256_cumulative_calc(&sha256, &test_string[64], (119-64));
	sprintf((char *)expected_result, "1631895cb6d8252481dfe45655eb7c4498b9c933fe0f449b5e3cac632faf0f59");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	/* case #6 - 120 bytes - should use 2 iterations, internally a 3rd buffer would be required  */
	sprintf((char *)test_string, "%s", "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 64);
	sha256_cumulative_calc(&sha256, &test_string[64], (120-64));
	sprintf((char *)expected_result, "3f1d5c569700bb14477510ccfb716fe629fd07b13dc4b1c7ce73a5fa97770bc8");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	/* case #7 - 140 bytes - should use 3 iterations, without adding 4th buffer */
	sprintf((char *)test_string, "%s", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
	sha256_init(&sha256);
	sha256_cumulative_calc(&sha256, test_string, 64);
	sha256_cumulative_calc(&sha256, &test_string[64], 64);
	sha256_cumulative_calc(&sha256, &test_string[2*64], (140-2*64));
	sprintf((char *)expected_result, "2b3f88f443a0e3b55c929eebdf6a71a2c15dcf6f4fad06410d4dd5d2dd3e620e");
	sprintf((char *)calc_result, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);
	if (strncmp((char *)calc_result, (char *)expected_result, 64))
		return -1;

	return 0;
}

int sha256_file(char *path, char *sha)
{
	FILE *fptr;
	unsigned char read_buffer[SHA256_BLOCKS_SIZE_BYTES*2];
	unsigned char temp[SHA256_BLOCKS_SIZE_BYTES*4];
	size_t read_elements;
	size_t element_size_in_bytes = 1;
	SHA256_ctx sha256;

	sha256_init(&sha256);
	memset(read_buffer, 0, sizeof(read_buffer));

	if (!(fptr = fopen(path, "rb")))
		return -1;

	int counter=0;
	while ((read_elements = fread(read_buffer, element_size_in_bytes, (SHA256_BLOCKS_SIZE_BYTES/element_size_in_bytes), fptr))) {
		memset(temp, 0, sizeof(temp));
		sha256_cumulative_calc(&sha256, read_buffer, (int)(read_elements*element_size_in_bytes));
	}

	sprintf(sha, "%08x%08x%08x%08x%08x%08x%08x%08x",
			sha256.hash[0], sha256.hash[1], sha256.hash[2], sha256.hash[3],
			sha256.hash[4], sha256.hash[5], sha256.hash[6], sha256.hash[7]);

	fclose(fptr);

	return 0;
}
