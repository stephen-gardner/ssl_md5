/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   hash.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/16 04:29:26 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/16 05:58:39 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"
#include "ft_printf.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void	init(t_ssl *ssl)
{
	if (ssl->hash_type == MD5)
		md5_init(&ssl->ctx.md5);
	else if (ssl->hash_type == SHA256)
		sha256_init(&ssl->ctx.sha256);
}

static void	update(t_ssl *ssl, t_byte const *buff, size_t len)
{
	if (ssl->hash_type == MD5)
		md5_update(&ssl->ctx.md5, buff, len);
	else if (ssl->hash_type == SHA256)
		sha256_update(&ssl->ctx.sha256, buff, len);
}

static void	final(t_ssl *ssl, t_byte *digest)
{
	if (ssl->hash_type == MD5)
		md5_final(digest, &ssl->ctx.md5);
	else if (ssl->hash_type == SHA256)
		sha256_final(digest, &ssl->ctx.sha256);
}

void		hash_file(t_ssl *ssl, char const *filename)
{
	t_byte	buff[4096];
	t_byte	digest[32];
	int		bytes;
	int		fd;

	if (!(ssl->arg = filename))
		fd = 0;
	else if ((fd = open(filename, O_RDONLY)) == -1)
	{
		ft_printf("%s: %s: %s\n", g_pname, filename, strerror(errno));
		return ;
	}
	init(ssl);
	while ((bytes = read(fd, buff, 4096)) > 0)
	{
		update(ssl, buff, bytes);
		if (fd == STDIN_FILENO)
			write(STDOUT_FILENO, buff, bytes);
	}
	if (fd)
		close(fd);
	final(ssl, digest);
	print_hash(ssl, digest);
}

void		hash_string(t_ssl *ssl, char const *arg)
{
	t_byte	digest[32];

	ssl->arg = arg;
	init(ssl);
	update(ssl, (t_byte const *)arg, LEN(arg));
	final(ssl, digest);
	print_hash(ssl, digest);
}
