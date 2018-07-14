/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/11 00:29:32 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/13 17:54:59 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_printf.h"
#include <stdlib.h>

static t_uint const	g_radians[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#define S1			7, 12, 17, 22
#define S2			5, 9, 14, 20
#define S3			4, 11, 16, 23
#define S4			6, 10, 15, 21

static t_uint const	g_shifts[64] = {
	S1, S1, S1, S1,
	S2, S2, S2, S2,
	S3, S3, S3, S3,
	S4, S4, S4, S4
};

static t_uint const	g_bindex[64] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
	5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
	0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
};

char const			*md5tostr(t_md5ctx *ctx)
{
	static char	str[32];
	t_byte		*data;
	int			i;

	i = 0;
	data = (t_byte *)ctx->state;
	while (i < 16)
	{
		ft_sprintf(&str[(i << 1)], "%.2x", data[i]);
		++i;
	}
	return (str);
}

static t_byte		*pad_msg(t_md5ctx *ctx, t_byte *msg, size_t len)
{
	t_byte		*padded;
	uint64_t	nsize;

	nsize = len + sizeof(uint64_t) + 1;
	nsize += 64 - (nsize & 63);
	padded = ft_memalloc(nsize);
	ft_memcpy(padded, msg, len);
	padded[len] = 0x80;
	len <<= 3;
	ft_memcpy(padded + nsize - sizeof(uint64_t), &len, sizeof(uint64_t));
	ctx->count[1] = nsize >> 6;
	return (padded);
}

#define F1(b, c, d)	(((b) & (c)) | (~(b) & (d)))
#define F2(b, c, d)	(((b) & (d)) | ((c) & ~(d)))
#define F3(b, c, d)	((b) ^ (c) ^ (d))
#define F4(b, c, d)	((c) ^ ((b) | ~(d)))
#define ROTL(x, c)	(((x) << (c)) | ((x) >> (32 - c)))

static t_uint		*process_chunk(t_md5ctx *ctx)
{
	static t_uint	state[4];
	t_uint			f;
	int				i;

	i = 0;
	ft_memcpy(state, ctx->state, sizeof(state));
	while (i < 64)
	{
		if (i < 16)
			f = F1(state[1], state[2], state[3]);
		else if (i < 32)
			f = F2(state[1], state[2], state[3]);
		else if (i < 48)
			f = F3(state[1], state[2], state[3]);
		else
			f = F4(state[1], state[2], state[3]);
		f += state[0] + g_radians[i] + ctx->buff[g_bindex[i]];
		state[0] = state[3];
		state[3] = state[2];
		state[2] = state[1];
		state[1] += ROTL(f, g_shifts[i]);
		++i;
	}
	return (state);
}

t_md5ctx			*md5(t_byte *msg, size_t len)
{
	static t_md5ctx	ctx;
	t_byte const	*padded;
	t_uint			*chunk_res;
	uint32_t		i;

	i = 0;
	ctx.state[0] = 0x67452301;
	ctx.state[1] = 0xefcdab89;
	ctx.state[2] = 0x98badcfe;
	ctx.state[3] = 0x10325476;
	ctx.count[0] = len;
	padded = pad_msg(&ctx, msg, len);
	while (i < ctx.count[1])
	{
		ft_memcpy(ctx.buff, padded + (i++ << 6), 64);
		chunk_res = process_chunk(&ctx);
		ctx.state[0] += chunk_res[0];
		ctx.state[1] += chunk_res[1];
		ctx.state[2] += chunk_res[2];
		ctx.state[3] += chunk_res[3];
	}
	ft_memset(ctx.buff, 0, 64);
	free((void *)padded);
	return (&ctx);
}
