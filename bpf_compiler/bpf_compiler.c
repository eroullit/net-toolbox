/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009-2011	Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 */

 /* __LICENSE_HEADER_END__ */

#include <stdlib.h>
#include <stdio.h>

#include "bpf_compiler.h"
#include "bpf_expr.h"

int main (int argc, char ** argv)
{
	struct bpf_expr expr;

	if (argc != 2)
	{
		fprintf(stderr, "Please write your BPF expression into double quotes\n");
		return (EXIT_FAILURE);
	}

	lex_init((argc == 2 && argv[1]) ? argv[1] : "");

	bpf_expr_parse(&expr);

	bpf_print_expr(&expr);

	bpf_expr_free(&expr);

	lex_cleanup();

	return (0);
}
