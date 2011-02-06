#include "bpf_compiler.h"

int main (int argc, char ** argv)
{
	lex_init(argv[1] ? argv[1] : "");
	bpf_expr_parse();
	lex_cleanup();
	return (0);
}
