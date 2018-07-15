/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:33:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/15 04:38:01 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H
# include "libft.h"
# include <stdint.h>

# define ROTL(x, c)	(((x) << (c)) | ((x) >> (32 - (c))))
# define ROTR(x, c)	(((x) >> (c)) | ((x) << (32 - (c))))

typedef struct	s_md5ctx
{
	uint32_t	state[4];
	uint32_t	count[2];
	t_byte		buff[64];
}				t_md5ctx;

typedef struct	s_sha256ctx
{
	uint32_t	state[8];
	uint32_t	count[2];
	t_byte		buff[256];
}				t_sha256ctx;

/*
** md5.c
*/

void			md5_init(t_md5ctx *ctx);
void			md5_update(t_md5ctx *ctx, t_byte *msg, size_t len);
void			md5_final(t_byte *digest, t_md5ctx *ctx);

/*
** sha256.c
*/

void			sha256_init(t_sha256ctx *ctx);
void			sha256_update(t_sha256ctx *ctx, t_byte *msg, size_t len);
void			sha256_final(t_byte *digest, t_sha256ctx *ctx);

/*
** util.c
*/

void			rev_endian32(uint32_t *tab, int len);
void			rev_endian64(uint64_t *tab, int len);
#endif
