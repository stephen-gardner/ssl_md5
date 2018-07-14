/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:33:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/14 12:06:00 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H
# include "libft.h"
# include <stdint.h>

typedef struct	s_md5ctx
{
	uint32_t	state[4];
	uint32_t	count[2];
	uint32_t	buff[16];
}				t_md5ctx;

/*
** md5.c
*/

void			md5_init(t_md5ctx *ctx);
void			md5_update(t_md5ctx *ctx, t_byte *msg, size_t len);
void			md5_final(t_byte *digest, t_md5ctx *ctx);
#endif
