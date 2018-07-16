/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:17:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/15 23:37:03 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_getopt.h"
#include "ft_printf.h"
#include <unistd.h>

static void	print_result(t_ssl *ssl, t_byte const *digest)
{
	char	hash[64];
	int		len;
	int		i;

	i = 0;
	len = (ssl->hash_type == MD5) ? 16 : 32;
	while (i < len)
	{
		ft_sprintf(hash + (i << 1), "%.2x", digest[i]);
		++i;
	}
	ft_printf("%s\n", hash);
}

static void	hash_stdin(t_ssl *ssl)
{
	static t_byte	buff[4096];
	t_byte			digest[32];
	int				bytes;

	if (ssl->hash_type == MD5)
		md5_init(&ssl->ctx.md5);
	else
		sha256_init(&ssl->ctx.sha256);
	while ((bytes = read(STDIN_FILENO, buff, 4096)) > 0)
	{
		if (ssl->hash_type == MD5)
			md5_update(&ssl->ctx.md5, buff, bytes);
		else
			sha256_update(&ssl->ctx.sha256, buff, bytes);
	}
	if (ssl->hash_type == MD5)
		md5_final(digest, &ssl->ctx.md5);
	else
		sha256_final(digest, &ssl->ctx.sha256);
	print_result(ssl, digest);
}

int			main(int ac, char *av[])
{
	static t_ssl	ssl;
	char			f;

	if (ac < 2)
		return (usage());
	ft_strlowcase(av[1]);
	if (!strcmp("md5", av[1]))
		ssl.hash_type = MD5;
	else if (!strcmp("sha256", av[1]))
		ssl.hash_type = SHA256;
	else
		return (usage());
	ft_memcpy(&av[1], &av[ac - 1], sizeof(char *) * (ac - 1));
	--ac;
	while ((f = ft_getopt(ac, av, "pqrs:")) != -1)
	{
		if (f == 'q')
			ssl.quiet = TRUE;
		else if (f == 'r')
			ssl.reverse = TRUE;
		else if (f == 'p')
			hash_stdin(&ssl);
		else if (f == 's')
			;
	}
	return (0);
}
