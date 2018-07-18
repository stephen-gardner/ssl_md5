/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/16 04:29:26 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/17 19:47:00 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_printf.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

t_digest const	g_digests[] = {
	{ MD5, md5_init, md5_update, md5_final, "MD5", 16 },
	{ SHA256, sha256_init, sha256_update, sha256_final, "SHA256", 32 }
};

int const		g_digests_size = sizeof(g_digests) / sizeof(t_digest);

static void		print_hash(t_ssl *ssl, t_byte const *digest, t_bool quote)
{
	t_digest const	*alg;
	char			hash[65];
	int				i;

	i = 0;
	alg = &g_digests[ssl->hash_type - 1];
	while (i < alg->bsize)
	{
		ft_sprintf(hash + (i << 1), "%.2x", digest[i]);
		++i;
	}
	if (ssl->arg && !ssl->quiet)
	{
		if (ssl->reverse)
			ft_printf((quote) ? "%s \"%s\"\n" : "%s %s\n", hash, ssl->arg);
		else if (quote)
			ft_printf("%s (\"%s\") = %s\n", alg->name, ssl->arg, hash);
		else
			ft_printf("%s (%s) = %s\n", alg->name, ssl->arg, hash);
	}
	else
		ft_printf("%s\n", hash);
}

void			hash_file(t_ssl *ssl, char const *filename)
{
	t_digest const	*alg;
	t_byte			buff[4096];
	t_byte			digest[32];
	int				bytes;
	int				fd;

	if (!(ssl->arg = filename))
		fd = 0;
	else if ((fd = open(filename, O_RDONLY)) == -1)
	{
		ft_printf("%s: %s: %s\n", g_pname, filename, strerror(errno));
		return ;
	}
	alg = &g_digests[ssl->hash_type - 1];
	alg->init(ssl);
	while ((bytes = read(fd, buff, 4096)) > 0)
	{
		alg->update(ssl, buff, bytes);
		if (fd == STDIN_FILENO)
			write(STDOUT_FILENO, buff, bytes);
	}
	if (fd)
		close(fd);
	alg->final(ssl, digest);
	print_hash(ssl, digest, FALSE);
}

void			hash_string(t_ssl *ssl, char const *arg)
{
	t_digest const	*alg;
	t_byte			digest[32];

	alg = &g_digests[ssl->hash_type - 1];
	ssl->arg = arg;
	alg->init(ssl);
	alg->update(ssl, (t_byte const *)arg, LEN(arg));
	alg->final(ssl, digest);
	print_hash(ssl, digest, TRUE);
}
