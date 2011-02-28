default:
	flex --nounput bpf.l
	gcc -g -Wall -Werror -W -pedantic -std=gnu99 bpf_compiler.c lex.yy.c -o bpf_compiler
