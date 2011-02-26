%{
// bpf.l -- a simple BPF parser
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
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
%}

digit	[0-9]
pos_int	{digit}+
neg_int	-{digit}+
letter	[a-zA-Z]
word    {letter}+
hex	([0-9A-Fa-f][0-9A-Fa-f]?)
MAC	({hex}:{hex}:{hex}:{hex}:{hex}:{hex})
IPv4	{pos_int}.{pos_int}.{pos_int}.{pos_int}

%%

dst		{printf("%s\n", stringify(DST)); return DST;}
src		{printf("%s\n", stringify(SRC)); return SRC;}
port		{printf("%s\n", stringify(PORT)); return PORT;}
{MAC}		{printf("%s : %s\n", stringify(MAC_ID), ether_ntoa(ether_aton(yytext))); return MAC_ID;}

{IPv4}		{char addrstr[INET_ADDRSTRLEN];
		 struct in_addr addr;

		 inet_pton(AF_INET, yytext, &addr);
		 inet_ntop(AF_INET, &addr, addrstr, INET_ADDRSTRLEN);
		 printf("%s : %s\n", stringify(IPv4_ID), addrstr);
		 return IPv4_ID;
		}

and		{printf("%s\n", stringify(AND));return AND;}
or		{printf("%s\n", stringify(OR));return OR;}
xor		{printf("%s\n", stringify(XOR));return XOR;}
not		{printf("%c\n", '!');return '!';}

{pos_int}	{uint64_t val;
		 int rc;

		 rc = bpf_strtoll(yytext, &val);

		 if (rc)
		 {
		 	 printf("%s\n", stringify(UNKNOWN));
		 	 return UNKNOWN;
		 }

		 printf("%s: %"PRIu64"\n", stringify(NUMBER), val);

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

int bpf_expr_parse(void)
{
	int rc;

	do
	{
		rc = yylex();
	}while (rc != '\0');

	return (0);
}

int yywrap(void){return 1;}
