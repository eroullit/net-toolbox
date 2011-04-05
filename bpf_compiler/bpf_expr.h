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

#ifndef	__BPF_EXPR_H__
#define	__BPF_EXPR_H__

#include <stdint.h>
#include <sys/queue.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define	stringify(x)	#x

enum bpf_arith_ops
{
	UNKNOWN_ARITH_OP = 0,
	EQUAL,
	NOT_EQUAL,
	GREATER,
	LESS,
	GREATER_EQUAL,
	LESS_EQUAL
};

enum bpf_bit_ops
{
	UNKNOWN_BIT_OP = 0,
	NOT,
	AND,
	OR,
	XOR
};

enum bpf_direction
{
	DIRECTION_UNKNOWN = 0,
	ANY_DIRECTION,
	SRC,
	DST,
};

enum bpf_compiler_obj
{
	UNKNOWN_OBJ = 0,
	IP,
	IP6,
	MAC,
	LEN,
	PORT,
	BIT_OP,
	MAC_ID,
	POS_NUMBER,
	IPv4_ID
};

struct bpf_step
{
	union value
	{
		uint64_t nr;
		struct in_addr in;
		struct in6_addr in6;
		struct ether_addr eth;
		enum bpf_bit_ops bit_op;
	} value;

	enum bpf_direction direction;
	enum bpf_arith_ops arith_op;
	enum bpf_compiler_obj obj;
	size_t nr;
	TAILQ_ENTRY(bpf_step) entry;
};

struct bpf_expr
{
	size_t					len;
	TAILQ_HEAD(bpf_expr_head, bpf_step)	head;
};

struct bpf_step * bpf_step_alloc(void);
void bpf_expr_free(struct bpf_expr * expr);
void bpf_expr_init(struct bpf_expr * expr);
int bpf_expr_parse(struct bpf_expr * expr);

int bpf_strtoull(const char * const str, uint64_t * val);

int bpf_step_is_value_set(const struct bpf_step * const step);
int bpf_step_set_obj(struct bpf_step * step, const enum bpf_compiler_obj obj);
int bpf_step_set_direction(struct bpf_step * step, const enum bpf_direction dir);
int bpf_step_set_arith_op(struct bpf_step * step, const enum bpf_arith_ops op);
int bpf_step_set_bit_op(struct bpf_step * step, const enum bpf_bit_ops op);
int bpf_expr_set_step(struct bpf_expr * expr, struct bpf_step * step);
int bpf_step_set_number(struct bpf_step * step, const uint64_t nr);
int bpf_step_set_eth(struct bpf_step * step, const struct ether_addr eth);
int bpf_step_set_in(struct bpf_step * step, const struct in_addr in);
int bpf_step_set_in6(struct bpf_step * step, const struct in6_addr in6);

int bpf_print_step(const struct bpf_step * const step);
int bpf_print_expr(const struct bpf_expr * const expr);

#endif	/* __BPF_EXPR_H__ */
