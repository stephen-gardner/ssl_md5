/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/09 18:17:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/13 08:34:03 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include <unistd.h>

int	main(int ac, char *av[])
{
	t_md5ctx	*ctx;

	if (ac < 2)
		return (1);
	ctx = md5((t_byte *)av[1], LEN(av[1]));
	write(1, md5tostr(ctx), 32);
	write(1, "\n", 1);
	return (0);
}
