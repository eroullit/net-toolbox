/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2009, 2011  Daniel Borkmann <daniel@netsniff-ng.org> and
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
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
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include "bpf_compiler.h"

int bpf_strtoll(const char const * str, uint64_t * val)
{
	char * endptr = NULL;

	assert(str);
	assert(val);

	errno = 0;

	*val = strtoull(str, &endptr, 0);

	if ((errno == ERANGE && *val == ULLONG_MAX) || (errno != 0 && *val == 0)) 
	{
		return(errno);
	}

	if (endptr == str) 
	{
		return(EINVAL);
	}

	return (0);
}

int main (int argc, char ** argv)
{
	lex_init(argv[1] ? argv[1] : "");
	bpf_expr_parse();
	lex_cleanup();
	return (0);
}
