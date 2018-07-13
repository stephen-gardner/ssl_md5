/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:33:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/13 08:22:18 by sgardner         ###   ########.fr       */
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

char const		*md5tostr(t_md5ctx *ctx);
t_md5ctx		*md5(t_byte *msg, size_t len);
#endif
