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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include "bpf_compiler.h"

int bpf_strtoull(const char * const str, uint64_t * val)
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

	/* Same behaviour as free(3) */
	if (!expr)
		return;

	while((step = TAILQ_FIRST(&expr->head)) != NULL)
	{
		TAILQ_REMOVE(&expr->head, step, entry);
		free(step);
		step = NULL;
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

static int bpf_step_add_value(struct bpf_expr * expr, const union value value)
{
	struct bpf_step * step;

	assert(expr);

	/* 
	 * As a value must go with the previous code
	 * we fetch the last added step and attach the value to it
	 */

	step = TAILQ_LAST(&expr->head, bpf_expr_head);

	assert(step);

	switch(step->code)
	{
		case PORT:
		case LEN:
			step->value.nr = value.nr;
		break;

		case IP:
			step->value.in = value.in;
		break;

		case IP6:
			step->value.in6 = value.in6;
		break;

		case MAC:
			step->value.eth = value.eth;
		break;

		default:
			return EINVAL;
		break;
	}

	return 0;
}

int bpf_step_add_code(struct bpf_expr * expr, const enum bpf_compiler_code code)
{
	struct bpf_step * step;
 
        assert(expr);
 
	step = bpf_step_alloc();

	if (!step)
		return ENOMEM;

	step->code = code;
	step->nr = expr->len;

	TAILQ_INSERT_TAIL(&expr->head, step, entry);
	expr->len++;

	return 0;
}

int bpf_step_add_number(struct bpf_expr * expr, const uint64_t nr)
{
	union value value = {0};

	value.nr = nr;

	return bpf_step_add_value(expr, value);
}

int bpf_step_add_eth(struct bpf_expr * expr, const struct ether_addr eth)
{
	union value value = {0};

	value.eth = eth;

	return bpf_step_add_value(expr, value);
}

int bpf_step_add_in(struct bpf_expr * expr, const struct in_addr in)
{
	union value value = {0};

	value.in = in;

	return bpf_step_add_value(expr, value);
}

int bpf_step_add_in6(struct bpf_expr * expr, const struct in6_addr in6)
{
	union value value = {0};

	value.in6 = in6;

	return bpf_step_add_value(expr, value);
}

int bpf_print_expr(const struct bpf_expr * const expr)
{
	union
	{
		char in_str[INET_ADDRSTRLEN];
		char in6_str[INET6_ADDRSTRLEN];
	} addr;

	struct bpf_step * step;

	assert(expr);

	TAILQ_FOREACH(step, &expr->head, entry)
	{
		switch(step->code)
		{
			case SRC:
				printf("%s\n", stringify(SRC));
			break;

			case DST:
				printf("%s\n", stringify(DST));
			break;

			case IP:
				inet_ntop(AF_INET, &step->value.in, addr.in_str, sizeof(addr.in_str));
				printf("%s : %s\n", stringify(IP), addr.in_str);
			break;

			case IP6:
				inet_ntop(AF_INET6, &step->value.in6, addr.in6_str, sizeof(addr.in6_str));
				printf("%s : %s\n", stringify(IP6),  addr.in6_str);
			break;
	
			case MAC:
				printf("%s : %s\n", stringify(MAC), ether_ntoa(&step->value.eth));
			break;
	
			case LEN:
				printf("%s : %"PRIu64"\n", stringify(LEN), step->value.nr);
			break;
	
			case PORT:
				printf("%s : %"PRIu64"\n", stringify(PORT), step->value.nr);
			break;
			
			case NOT:
				printf("%s\n", stringify(NOT));
			break;

			case AND:
				printf("%s\n", stringify(AND));
			break;

			case OR:
				printf("%s\n", stringify(OR));
			break;

			case XOR:
				printf("%s\n", stringify(XOR));
			break;

			default:
				return EINVAL;
			break;
		}
	}

	return 0;
}

int main (int argc, char ** argv)
{
	struct bpf_expr expr;

	if (argc != 2)
	{
		printf("Please write your BPF expression into double quotes\n");
		return (EXIT_FAILURE);
	}

	lex_init((argc == 2 && argv[1]) ? argv[1] : "");

	bpf_expr_parse(&expr);

	bpf_print_expr(&expr);

	bpf_expr_free(&expr);

	lex_cleanup();

	return (0);
}
