#ifndef	__BPF_COMPILER_H__
#define	__BPF_COMPILER_H__

enum bpf_compiler_code
{
	SRC = 1,
	DST,
	LEN,
	AND,
	OR,
	MAC_ID,
	IPv4_ID,
};

void lex_init(const char * const buf);
void lex_cleanup();
int bpf_expr_parse(void);

#endif	/* __BPF_COMPILER_H__ */
