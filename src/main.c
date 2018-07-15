/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:17:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/15 04:41:40 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_printf.h"

#include <fcntl.h>
#include <unistd.h>
/*
int	main(int ac, char *av[])
{
	t_md5ctx	ctx;
	t_byte		digest[16];
	char		hash[32];

	if (ac < 2)
		return (1);
	md5_init(&ctx);
	md5_update(&ctx, (t_byte *)av[1], LEN(av[1]));
	md5_final(digest, &ctx);
int fd = open(av[1], O_RDONLY);
t_byte	buff[4097];
int bytes = 0;
while ((bytes = read(fd, buff, 4096)) > 0)
{
	buff[bytes] = 0;
	md5_update(&ctx, buff, bytes);
}
close(fd);
md5_final(digest, &ctx);
	for (int i = 0; i < 16; i++)
		ft_sprintf(hash + (i << 1), "%.2x", digest[i]);
	ft_printf("%s\n", hash);
	return (0);
}*/


int	main(int ac, char *av[])
{
	t_sha256ctx	ctx;
	t_byte		digest[32];
	char		hash[64];

	if (ac < 2)
		return (1);
	sha256_init(&ctx);
/*	md5_update(&ctx, (t_byte *)av[1], LEN(av[1]));
	md5_final(digest, &ctx);*/
int fd = open(av[1], O_RDONLY);
t_byte	buff[4097];
int bytes = 0;
while ((bytes = read(fd, buff, 4096)) > 0)
{
	buff[bytes] = 0;
	sha256_update(&ctx, buff, bytes);
}
close(fd);
sha256_final(digest, &ctx);
	for (int i = 0; i < 32; i++)
		ft_sprintf(hash + (i << 1), "%.2x", digest[i]);
	ft_printf("%s\n", hash);
	return (0);
}
