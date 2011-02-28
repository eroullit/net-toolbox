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
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include "bpf_compiler.h"

int bpf_strtoull(const char const * str, uint64_t * val)
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

void bpf_expr_init(struct bpf_expr * expr)
{
	assert(expr);

	memset(expr, 0, sizeof(*expr));

	TAILQ_INIT(&expr->head);
}

void bpf_expr_free(struct bpf_expr * expr)
{
	struct bpf_step * step;
	assert(expr);

	/* Same behaviour as free(3) */
	if (!expr)
		return;

	while(!TAILQ_EMPTY(&expr->head))
	{
		step = TAILQ_FIRST(&expr->head);
		TAILQ_REMOVE(&expr->head, step, entry);
		free(step);
	}

	memset(expr, 0, sizeof(*expr));
}

struct bpf_step * bpf_step_alloc(void)
{
	struct bpf_step * step;

	step = malloc(sizeof(*step));

	if (!step)
		return NULL;

	memset(step, 0, sizeof(*step));

	return step;
}

static int bpf_step_add(struct bpf_expr * expr, const union token token)
{
	struct bpf_step * step;

	assert(expr);

	step = bpf_step_alloc();

	if (!step)
		return ENOMEM;

	step->token = token;
	step->nr = expr->len;

	TAILQ_INSERT_TAIL(&expr->head, step, entry);
	expr->len++;
}

int bpf_step_add_code(struct bpf_expr * expr, const enum bpf_compiler_code code)
{
	union token token = {0};

	token.code = code;

	return bpf_step_add(expr, token);
}

int bpf_step_add_value(struct bpf_expr * expr, const uint64_t val)
{
	union token token = {0};

	token.val = val;

	return bpf_step_add(expr, token);
}

int bpf_step_add_eth(struct bpf_expr * expr, const struct ether_addr eth)
{
	union token token = {0};

	token.eth = eth;

	return bpf_step_add(expr, token);
}

int bpf_step_add_in(struct bpf_expr * expr, const struct in_addr in)
{
	union token token = {0};

	token.in = in;

	return bpf_step_add(expr, token);
}

int bpf_step_add_in6(struct bpf_expr * expr, const struct in6_addr in6)
{
	union token token = {0};

	token.in6 = in6;

	return bpf_step_add(expr, token);
}

int bpf_print_expr(const struct bpf_expr * const expr)
{
	struct bpf_step * step;

	assert(expr);

	TAILQ_FOREACH(step, &expr->head, entry)
	{
		/* TODO */
	}
}

int main (int argc, char ** argv)
{
	struct bpf_expr expr;

	lex_init(argv[1] ? argv[1] : "");

	bpf_expr_parse(&expr);

	bpf_expr_free(&expr);

	lex_cleanup();

	return (0);
}
