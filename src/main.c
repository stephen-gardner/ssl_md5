/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:17:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/16 08:49:44 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_getopt.h"
#include "ft_printf.h"

char const		*g_pname;

static char const	*get_hash(t_ssl *ssl, t_byte const *digest)
{
	static char	hash[65];
	int			size;
	int			i;

	i = 0;
	size = 0;
	if (ssl->hash_type == MD5)
		size = 16;
	else if (ssl->hash_type == SHA256)
		size = 32;
	while (i < size)
	{
		ft_sprintf(hash + (i << 1), "%.2x", digest[i]);
		++i;
	}
	return (hash);
}

void				print_hash(t_ssl *ssl, t_byte const *digest, t_bool quote)
{
	char const	*hash;

	hash = get_hash(ssl, digest);
	if (ssl->arg && !ssl->quiet)
	{
		if (ssl->reverse)
		{
			ft_printf((quote) ? "%s \"%s\"\n" : "%s %s\n",
				hash, ssl->arg);
		}
		else
		{
			if (ssl->hash_type == MD5)
				ft_printf("MD5 ");
			else if (ssl->hash_type == SHA256)
				ft_printf("SHA256 ");
			ft_printf((quote) ? "(\"%s\") = %s\n" : "(%s) = %s\n",
				ssl->arg, hash);
		}
	}
	else
		ft_printf("%s\n", hash);
}

static t_bool		process_flags(int ac, char *const av[], t_ssl *ssl)
{
	char	f;
	t_bool	hashed;

	hashed = FALSE;
	while ((f = ft_getopt(ac, av, "pqrs:")) != -1)
	{
		if (f == 'q')
			ssl->quiet = TRUE;
		else if (f == 'r')
			ssl->reverse = TRUE;
		else if (f == 'p')
		{
			hash_file(ssl, NULL);
			hashed = TRUE;
		}
		else if (f == 's')
		{
			hash_string(ssl, g_optarg);
			hashed = TRUE;
		}
		else
			usage();
	}
	return (hashed);
}

static t_bool		set_mode(int ac, char *av[], t_ssl *ssl)
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

int					main(int ac, char *av[])
{
	static t_ssl	ssl;
	t_bool			hashed;

	g_pname = av[0];
	if (!set_mode(ac--, av, &ssl))
		usage();
	hashed = process_flags(ac, av, &ssl);
	if (!hashed && g_optind == ac)
		hash_file(&ssl, NULL);
	while (g_optind < ac)
		hash_file(&ssl, av[g_optind++]);
	return (0);
}
