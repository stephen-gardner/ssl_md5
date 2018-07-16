/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/13 18:33:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/16 09:17:34 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

static uint32_t const	g_primecr[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void					sha256_init(t_sha256ctx *ctx)
{
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

#define CH(e, f, g)		(((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a, b, c)	(((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define BSIG0(a)		(ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22))
#define BSIG1(e)		(ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25))

static uint32_t			*process_chunk(t_sha256ctx *ctx)
{
	static uint32_t	state[8];
	uint32_t		tmp1;
	uint32_t		tmp2;
	int				i;

	i = 0;
	ft_memcpy(state, ctx->state, sizeof(state));
	while (i < 64)
	{
		tmp1 = state[7] + BSIG1(state[4]) + CH(state[4], state[5], state[6])
			+ g_primecr[i] + ((uint32_t *)ctx->buff)[i];
		tmp2 = BSIG0(state[0]) + MAJ(state[0], state[1], state[2]);
		state[7] = state[6];
		state[6] = state[5];
		state[5] = state[4];
		state[4] = state[3] + tmp1;
		state[3] = state[2];
		state[2] = state[1];
		state[1] = state[0];
		state[0] = tmp1 + tmp2;
		++i;
	}
	return (state);
}

#define SSIG0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define SSIG1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

static void				update(t_sha256ctx *ctx)
{
	uint32_t	*chunk_res;
	uint32_t	*buff;
	int			i;

	i = 16;
	buff = (uint32_t *)ctx->buff;
	rev_endian32(buff, 16);
	while (i < 64)
	{
		buff[i] = buff[i - 16] + SSIG0(buff[i - 15]) + buff[i - 7]
			+ SSIG1(buff[i - 2]);
		++i;
	}
	chunk_res = process_chunk(ctx);
	ctx->state[0] += chunk_res[0];
	ctx->state[1] += chunk_res[1];
	ctx->state[2] += chunk_res[2];
	ctx->state[3] += chunk_res[3];
	ctx->state[4] += chunk_res[4];
	ctx->state[5] += chunk_res[5];
	ctx->state[6] += chunk_res[6];
	ctx->state[7] += chunk_res[7];
	ft_memset(ctx->buff, 0, 64);
}

void					sha256_update(t_sha256ctx *ctx, t_byte const *msg,
							size_t len)
{
	uint32_t	bytes;

	while (len)
	{
		bytes = ctx->count[0] >> 3;
		if (bytes + len < 64)
		{
			ft_memcpy(ctx->buff + bytes, msg, len);
			ctx->count[0] += len << 3;
			return ;
		}
		ft_memcpy(ctx->buff + bytes, msg, 64 - bytes);
		ctx->count[0] = 0;
		++ctx->count[1];
		update(ctx);
		msg += 64 - bytes;
		len -= 64 - bytes;
	}
}

void					sha256_final(t_byte *digest, t_sha256ctx *ctx)
{
	uint32_t	bytes;
	uint64_t	total_size;
	int			i;

	bytes = ctx->count[0] >> 3;
	ctx->buff[bytes] = 0x80;
	if (bytes + sizeof(uint64_t) > 64)
		update(ctx);
	total_size = ((size_t)ctx->count[1] << 9) + ctx->count[0];
	rev_endian64(&total_size, 1);
	ft_memcpy(ctx->buff + (64 - sizeof(uint64_t)), &total_size,
		sizeof(uint64_t));
	update(ctx);
	i = 0;
	while (i < 32)
	{
		digest[i] = ((t_byte *)ctx->state)[i];
		++i;
	}
	rev_endian32((uint32_t *)digest, 8);
}
