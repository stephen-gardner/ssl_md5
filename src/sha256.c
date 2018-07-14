/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: sgardner <stephenbgardner@gmail.com>       +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/07/13 18:33:28 by sgardner          #+#    #+#             */
/*   Updated: 2018/07/13 19:15:28 by sgardner         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ssl.h"

#define CH(e, f, g)		(((e) & (f)) ^ (~(e) & (g)))
#define MAJ(a, b, c)	(((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))
#define ROTR(x, c)		(((x) >> (c)) | ((x) << (32 - (c))))
#define BSIG0(x)		(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x)		(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define SSIG1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))
