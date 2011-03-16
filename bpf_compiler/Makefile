default:
	flex --nounput bpf.l
	gcc -g -Wall -Werror -W -pedantic -std=gnu99 bpf_compiler.c bpf_expr.c lex.yy.c -o bpf_compiler
