/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:17:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/17 19:26:33 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_getopt.h"
#include "ft_printf.h"

char const		*g_pname;

static t_bool	process_flags(int ac, char *const av[], t_ssl *ssl)
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

static t_bool	set_mode(int ac, char *av[], t_ssl *ssl)
{
	t_digest const	*alg;
	int				i;

	if (ac < 2)
		return (FALSE);
	i = 0;
	ft_strupcase(av[1]);
	while (i < g_digests_size)
	{
		alg = &g_digests[i++];
		if (!strcmp(alg->name, av[1]))
		{
			ssl->hash_type = alg->type;
			break ;
		}
	}
	if (!ssl->hash_type)
		return (FALSE);
	ft_memcpy(&av[1], &av[2], sizeof(char *) * (ac));
	return (TRUE);
}

int				main(int ac, char *av[])
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
