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

%{
// bpf.l -- a simple BPF parser

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include "bpf_compiler.h"
#include "bpf_expr.h"

#ifdef	FLEX_SCANNER
#define YY_NO_INPUT
#define YY_NO_UNPUT
static YY_BUFFER_STATE in_buffer;
#else	/* FLEX_SCANNER */
static const char *in_buffer;
#endif	/* FLEX_SCANNER */

static struct bpf_step * cur_step;
%}

digit	[0-9]
pos_int	{digit}+
neg_int	-{digit}+
letter	[a-zA-Z]
word    {letter}+
hex	([0-9A-Fa-f][0-9A-Fa-f]?)
hex_val	0x({hex}+)
MAC	({hex}:{hex}:{hex}:{hex}:{hex}:{hex})
IPv4	{pos_int}.{pos_int}.{pos_int}.{pos_int}

%%

dst		{bpf_step_set_direction(cur_step, DST); return DST;}
src		{bpf_step_set_direction(cur_step, SRC); return SRC;}
port		{bpf_step_set_obj(cur_step, PORT); return PORT;}
ip		{bpf_step_set_obj(cur_step, IP); return IP;}
mac		{bpf_step_set_obj(cur_step, MAC); return MAC;}

{MAC}		{struct ether_addr * eth = ether_aton(yytext);
		 
		 bpf_step_set_eth(cur_step, *eth);
		 
		 return MAC_ID;
		}

{IPv4}		{struct in_addr addr;

		 inet_pton(AF_INET, yytext, &addr);
		 
		 bpf_step_set_in(cur_step, addr);

		 return IPv4_ID;
		}

and|"&&"	{bpf_step_set_bit_op(cur_step, AND);return AND;}
or|"||"		{bpf_step_set_bit_op(cur_step, OR);return OR;}
xor|"^"		{bpf_step_set_bit_op(cur_step, XOR);return XOR;}
not|"!"		{bpf_step_set_bit_op(cur_step, NOT);return NOT;} /* XXX NOT support might cause problem */

"=="		{bpf_step_set_arith_op(cur_step, EQUAL);return EQUAL;}
"!="		{bpf_step_set_arith_op(cur_step, NOT_EQUAL);return NOT_EQUAL;}
">"		{bpf_step_set_arith_op(cur_step, GREATER);return GREATER;}
"<"		{bpf_step_set_arith_op(cur_step, LESS);return LESS;}
">="		{bpf_step_set_arith_op(cur_step, GREATER_EQUAL);return GREATER_EQUAL;}
"<="		{bpf_step_set_arith_op(cur_step, LESS_EQUAL);return LESS_EQUAL;}

{pos_int}|{hex_val}	{uint64_t val;
			 int rc;

			 rc = bpf_strtoull(yytext, &val);

			 if (rc)
		 	 {
		 		 printf("%s\n", stringify(UNKNOWN_OBJ));
		 	 	 return UNKNOWN_OBJ;
		 	 }

		 	 bpf_step_set_number(cur_step, val);

		 	 return POS_NUMBER;
			}

{neg_int}|{word}	{return UNKNOWN_OBJ;}	/* No support for negative number yet and forbid unsupported words. */

[ \t\n\r]	;

%%

void lex_init(const char * const buf)
{
#ifdef	FLEX_SCANNER
	in_buffer = yy_scan_string(buf);
#else	/* FLEX_SCANNER */
	in_buffer = buf;
#endif	/* FLEX_SCANNER */
}

void lex_cleanup()
{
#ifdef FLEX_SCANNER
	if (in_buffer != NULL)
		yy_delete_buffer(in_buffer);
	in_buffer = NULL;
#endif
}

int bpf_expr_parse(struct bpf_expr * expr)
{
	int rc;

	assert(expr);

	bpf_expr_init(expr);

	cur_step = bpf_step_alloc();

	if (!cur_step)
	{
		return ENOMEM;
	}

	do
	{
		rc = yylex();

		/* When a BPF step is a valid object with a value, it is added to the BPF expression */
		/* XXX Is valid here */
		if (cur_step->obj != UNKNOWN_OBJ && bpf_step_is_value_set(cur_step) != 0)
		{
			bpf_expr_set_step(expr, cur_step);

			cur_step = bpf_step_alloc();

			if (!cur_step)
			{
				bpf_expr_free(expr);
				return ENOMEM;
			}
		}
	}while (rc != '\0');

	if (cur_step)
		free(cur_step);

	return (0);
}

int yywrap(void){return 1;}
