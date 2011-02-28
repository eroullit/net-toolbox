%{
// bpf.l -- a simple BPF parser

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include "bpf_compiler.h"

#ifdef	FLEX_SCANNER
#define YY_NO_INPUT
#define YY_NO_UNPUT
static YY_BUFFER_STATE in_buffer;
#else	/* FLEX_SCANNER */
static const char *in_buffer;
#endif	/* FLEX_SCANNER */

static struct bpf_expr cur_expr;
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

dst		{bpf_step_add_code(&cur_expr, DST); return DST;}
src		{bpf_step_add_code(&cur_expr, SRC); return SRC;}
port		{bpf_step_add_code(&cur_expr, PORT); return PORT;}
ip		{bpf_step_add_code(&cur_expr, IP); return IP;}
mac		{bpf_step_add_code(&cur_expr, MAC); return MAC;}
{MAC}		{struct ether_addr * eth = ether_aton(yytext);
		 
		 bpf_step_add_eth(&cur_expr, *eth);
		 
		 return MAC_ID;
		}

{IPv4}		{struct in_addr addr;

		 inet_pton(AF_INET, yytext, &addr);
		 
		 bpf_step_add_in(&cur_expr, addr);

		 return IPv4_ID;
		}

and		{bpf_step_add_code(&cur_expr, AND);return AND;}
or		{bpf_step_add_code(&cur_expr, OR);return OR;}
xor		{bpf_step_add_code(&cur_expr, XOR);return XOR;}
not		{bpf_step_add_code(&cur_expr, NOT);return NOT;}

{hex_val}	{uint64_t val;
		 int rc;

		 rc = bpf_strtoull(yytext, &val);

		 if (rc)
		 {
		 	 printf("%s\n", stringify(UNKNOWN));
		 	 return UNKNOWN;
		 }

		 bpf_step_add_number(&cur_expr, val);

		 return POS_NUMBER;
		}

{pos_int}	{uint64_t val;
		 int rc;

		 rc = bpf_strtoull(yytext, &val);

		 if (rc)
		 {
		 	 printf("%s\n", stringify(UNKNOWN));
		 	 return UNKNOWN;
		 }

		 bpf_step_add_number(&cur_expr, val);

		 return POS_NUMBER;
		}

{neg_int}	{return UNKNOWN;}	/* No support for negative number yet */
{word}		{return UNKNOWN;}	/* Forbin unsupported words. */
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
	struct bpf_step * step = NULL;

	assert(expr);

	bpf_expr_init(expr);
	bpf_expr_init(&cur_expr);

	do
	{
		rc = yylex();
	}while (rc != '\0');

	while ((step = TAILQ_FIRST(&cur_expr.head)) != NULL)
	{
		TAILQ_REMOVE(&cur_expr.head, step, entry);
		TAILQ_INSERT_TAIL(&expr->head, step, entry);
	}

	return (0);
}

int yywrap(void){return 1;}
