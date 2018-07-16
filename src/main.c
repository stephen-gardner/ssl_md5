/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:17:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/16 06:05:35 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_getopt.h"
#include "ft_printf.h"

char const		*g_pname;

void			print_hash(t_ssl *ssl, t_byte const *digest)
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
	if (ssl->arg && !ssl->quiet)
	{
		if (ssl->reverse)
			ft_printf("%s %s\n", hash, ssl->arg);
		else
		{
			ft_printf((ssl->hash_type == MD5) ? "MD5" : "SHA256");
			ft_printf(" (%s) = %s\n", ssl->arg, hash);
		}
	}
	else
		ft_printf("%s\n", hash);
}

static t_bool	set_mode(int ac, char *av[], t_ssl *ssl)
{
	if (ac < 2)
		return (FALSE);
	ft_strlowcase(av[1]);
	if (!strcmp("md5", av[1]))
		ssl->hash_type = MD5;
	else if (!strcmp("sha256", av[1]))
		ssl->hash_type = SHA256;
	else
		return (FALSE);
	ft_memcpy(&av[1], &av[2], sizeof(char *) * (ac));
	return (TRUE);
}

int				main(int ac, char *av[])
{
	static t_ssl	ssl;
	char			f;

	g_pname = av[0];
	if (!set_mode(ac--, av, &ssl))
		return (usage());
	while ((f = ft_getopt(ac, av, "pqrs:")) != -1)
	{
		if (f == 'q')
			ssl.quiet = TRUE;
		else if (f == 'r')
			ssl.reverse = TRUE;
		else if (f == 'p')
			hash_file(&ssl, NULL);
		else if (f == 's')
			hash_string(&ssl, g_optarg);
		else
			return (usage());
	}
	return (0);
}
