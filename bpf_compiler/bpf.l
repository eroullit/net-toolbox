%{
// bpf.l -- a simple BPF parser
#include <stdio.h>
#include <string.h>
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
number	{digit}+
letter	[a-zA-Z]
word    {letter}+
hex	([0-9A-Fa-f][0-9A-Fa-f]?)
MAC	({hex}:{hex}:{hex}:{hex}:{hex}:{hex})
IPv4	{number}.{number}.{number}.{number}

%%

dst		{printf("dst\n"); return DST;}
src		{printf("src\n"); return SRC;}
{MAC}		{printf("mac : %s\n", ether_ntoa(ether_aton(yytext))); return MAC_ID;}
{IPv4}		{char addrstr[INET_ADDRSTRLEN];
		 struct in_addr addr;

		 inet_pton(AF_INET, yytext, &addr);
		 inet_ntop(AF_INET, &addr, addrstr, INET_ADDRSTRLEN);
		 printf("ipv4 : %s\n", addrstr);
		 return IPv4_ID;
		}
and		{printf("and\n");return AND;}
or		{printf("or\n");return OR;}
not		{printf("not\n");return '!';}
{word}		;
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
