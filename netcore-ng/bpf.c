/**
 * \file bpf.c
 * \author written by Emmanuel Roullit emmanuel@netsniff-ng.org (c) 2009-2011
 * \date 2011
 */

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


/*
 * Copyright (c) 1990, 1991, 1992, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include <linux/filter.h>

#include <arpa/inet.h>

#include <netcore-ng/bpf.h>
#include <netcore-ng/macros.h>

/*
 * The instruction encodings.
 */

/* instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC	0x07

/* ld/ldx fields */
#define BPF_SIZE(code)	((code) & 0x18)
#define		BPF_W		0x00
#define		BPF_H		0x08
#define		BPF_B		0x10
#define BPF_MODE(code)	((code) & 0xe0)
#define		BPF_IMM 	0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)	((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET	0x40
#define BPF_SRC(code)	((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)	((code) & 0x18)
#define		BPF_A		0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define		BPF_TAX		0x00
#define		BPF_TXA		0x80

#define EXTRACT_SHORT(packet)	((unsigned short) ntohs(*(unsigned short *) packet))
#define EXTRACT_LONG(packet)		(ntohl(*(unsigned long *) packet))

/*
 * Number of scratch memory words for: BPF_ST and BPF_STX
 */
#ifndef BPF_MEMWORDS
# define BPF_MEMWORDS 16
#endif				/* BPF_MEMWORDS */

/**
 *      \brief	Print a human readable format of a BPF block
 *      \param	bpf[in]	Pointer to the BPF block to print
 *      \param	n[in]	Index of the BPF expression in the whole BPF expression
 *      \return	Pointer to human readable string of the input BPF block
 *      \note 	The code contained within the switch-case statement is taken from BSD licensed code.
 */

static char *bpf_dump(const struct sock_filter * bpf, int n)
{
	int v;
	const char *fmt, *op;

	static char image[256];
	char operand[64];

	v = bpf->k;

	switch (bpf->code) {
	default:
		op = "unimp";
		fmt = "0x%x";
		v = bpf->code;
		break;

	case BPF_RET | BPF_K:
		op = "ret";
		fmt = "#%d";
		break;

	case BPF_RET | BPF_A:
		op = "ret";
		fmt = "";
		break;

	case BPF_LD | BPF_W | BPF_ABS:
		op = "ld";
		fmt = "[%d]";
		break;

	case BPF_LD | BPF_H | BPF_ABS:
		op = "ldh";
		fmt = "[%d]";
		break;

	case BPF_LD | BPF_B | BPF_ABS:
		op = "ldb";
		fmt = "[%d]";
		break;

	case BPF_LD | BPF_W | BPF_LEN:
		op = "ld";
		fmt = "#pktlen";
		break;

	case BPF_LD | BPF_W | BPF_IND:
		op = "ld";
		fmt = "[x + %d]";
		break;

	case BPF_LD | BPF_H | BPF_IND:
		op = "ldh";
		fmt = "[x + %d]";
		break;

	case BPF_LD | BPF_B | BPF_IND:
		op = "ldb";
		fmt = "[x + %d]";
		break;

	case BPF_LD | BPF_IMM:
		op = "ld";
		fmt = "#0x%x";
		break;

	case BPF_LDX | BPF_IMM:
		op = "ldx";
		fmt = "#0x%x";
		break;

	case BPF_LDX | BPF_MSH | BPF_B:
		op = "ldxb";
		fmt = "4*([%d]&0xf)";
		break;

	case BPF_LD | BPF_MEM:
		op = "ld";
		fmt = "M[%d]";
		break;

	case BPF_LDX | BPF_MEM:
		op = "ldx";
		fmt = "M[%d]";
		break;

	case BPF_ST:
		op = "st";
		fmt = "M[%d]";
		break;

	case BPF_STX:
		op = "stx";
		fmt = "M[%d]";
		break;

	case BPF_JMP | BPF_JA:
		op = "ja";
		fmt = "%d";
		v = n + 1 + bpf->k;
		break;

	case BPF_JMP | BPF_JGT | BPF_K:
		op = "jgt";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JGE | BPF_K:
		op = "jge";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
		op = "jeq";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JSET | BPF_K:
		op = "jset";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JGT | BPF_X:
		op = "jgt";
		fmt = "x";
		break;

	case BPF_JMP | BPF_JGE | BPF_X:
		op = "jge";
		fmt = "x";
		break;

	case BPF_JMP | BPF_JEQ | BPF_X:
		op = "jeq";
		fmt = "x";
		break;

	case BPF_JMP | BPF_JSET | BPF_X:
		op = "jset";
		fmt = "x";
		break;

	case BPF_ALU | BPF_ADD | BPF_X:
		op = "add";
		fmt = "x";
		break;

	case BPF_ALU | BPF_SUB | BPF_X:
		op = "sub";
		fmt = "x";
		break;

	case BPF_ALU | BPF_MUL | BPF_X:
		op = "mul";
		fmt = "x";
		break;

	case BPF_ALU | BPF_DIV | BPF_X:
		op = "div";
		fmt = "x";
		break;

	case BPF_ALU | BPF_AND | BPF_X:
		op = "and";
		fmt = "x";
		break;

	case BPF_ALU | BPF_OR | BPF_X:
		op = "or";
		fmt = "x";
		break;

	case BPF_ALU | BPF_LSH | BPF_X:
		op = "lsh";
		fmt = "x";
		break;

	case BPF_ALU | BPF_RSH | BPF_X:
		op = "rsh";
		fmt = "x";
		break;

	case BPF_ALU | BPF_ADD | BPF_K:
		op = "add";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_SUB | BPF_K:
		op = "sub";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_MUL | BPF_K:
		op = "mul";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_DIV | BPF_K:
		op = "div";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_AND | BPF_K:
		op = "and";
		fmt = "#0x%x";
		break;

	case BPF_ALU | BPF_OR | BPF_K:
		op = "or";
		fmt = "#0x%x";
		break;

	case BPF_ALU | BPF_LSH | BPF_K:
		op = "lsh";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_RSH | BPF_K:
		op = "rsh";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_NEG:
		op = "neg";
		fmt = "";
		break;

	case BPF_MISC | BPF_TAX:
		op = "tax";
		fmt = "";
		break;

	case BPF_MISC | BPF_TXA:
		op = "txa";
		fmt = "";
		break;
	}

	snprintf(operand, sizeof(operand), fmt, v);
	snprintf(image, sizeof(image),
		 (BPF_CLASS(bpf->code) == BPF_JMP &&
		  BPF_OP(bpf->code) != BPF_JA) ?
		 "(%03d) %-8s %-16s jt %d\tjf %d" : "(%03d) %-8s %s", n, op, operand, n + 1 + bpf->jt, n + 1 + bpf->jf);
	return image;
}

/**
 *      \brief	Print a human readable format of a whole BPF expression
 *      \param	bpf[in]	Pointer to the BPF expression to print
 */

void bpf_dump_all(const struct sock_fprog * const bpf)
{
	int i;

	assert(bpf);

	for (i = 0; i < bpf->len; ++i) {
		info(" %s\n", bpf_dump(&bpf->filter[i], i));
	}

	info("\n");
}

/**
 *      \brief	Checks the input BPF expression validity
 *      \param	bpf[in]	Pointer to the BPF expression to check
 *      \return	0 is BPF is not valid, 1 when valid
 */

int bpf_is_valid(const struct sock_fprog * const bpf)
{
	uint32_t i, from;
	const struct sock_filter *p;

	/* File parsing got nothing usefull  */
	if (!bpf)
		return 0;

	if (bpf->len < 1)
		return 0;

	for (i = 0; i < bpf->len; ++i) {
		p = &bpf->filter[i];
		switch (BPF_CLASS(p->code)) {
			/*
			 * Check that memory operations use valid addresses.
			 */
		case BPF_LD:
		case BPF_LDX:
			switch (BPF_MODE(p->code)) {
			case BPF_IMM:
				break;
			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/*
				 * There's no maximum packet data size
				 * in userland.  The runtime packet length
				 * check suffices.
				 */
				break;
			case BPF_MEM:
				if (p->k >= BPF_MEMWORDS)
					return 0;
				break;
			case BPF_LEN:
				break;
			default:
				return 0;
			}
			break;
		case BPF_ST:
		case BPF_STX:
			if (p->k >= BPF_MEMWORDS)
				return 0;
			break;
		case BPF_ALU:
			switch (BPF_OP(p->code)) {
			case BPF_ADD:
			case BPF_SUB:
			case BPF_MUL:
			case BPF_OR:
			case BPF_AND:
			case BPF_LSH:
			case BPF_RSH:
			case BPF_NEG:
				break;
			case BPF_DIV:
				/*
				 * Check for constant division by 0.
				 */
				if (BPF_RVAL(p->code) == BPF_K && p->k == 0)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_JMP:
			/*
			 * Check that jumps are within the code block,
			 * and that unconditional branches don't go
			 * backwards as a result of an overflow.
			 * Unconditional branches have a 32-bit offset,
			 * so they could overflow; we check to make
			 * sure they don't.  Conditional branches have
			 * an 8-bit offset, and the from address is <=
			 * BPF_MAXINSNS, and we assume that BPF_MAXINSNS
			 * is sufficiently small that adding 255 to it
			 * won't overflow.
			 *
			 * We know that len is <= BPF_MAXINSNS, and we
			 * assume that BPF_MAXINSNS is < the maximum size
			 * of a u_int, so that i + 1 doesn't overflow.
			 *
			 * For userland, we don't know that the from
			 * or len are <= BPF_MAXINSNS, but we know that
			 * from <= len, and, except on a 64-bit system,
			 * it's unlikely that len, if it truly reflects
			 * the size of the program we've been handed,
			 * will be anywhere near the maximum size of
			 * a u_int.  We also don't check for backward
			 * branches, as we currently support them in
			 * userland for the protochain operation.
			 */
			from = i + 1;
			switch (BPF_OP(p->code)) {
			case BPF_JA:
				if (from + p->k >= bpf->len)
					return 0;
				break;
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
				if (from + p->jt >= bpf->len || from + p->jf >= bpf->len)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_RET:
			break;
		case BPF_MISC:
			break;
		default:
			return 0;
		}
	}

	return BPF_CLASS(bpf->filter[bpf->len - 1].code) == BPF_RET;
}

/**
 *      \brief	Checks the input packet matches the BPF expression
 *      \param	fcode[in]	Pointer to the BPF expression to use against the input packet
 *      \param	packet[in]	Pointer to the packet to match
 *      \param	plen[in]	Valid packet length
 *      \return	0 if the packet does not match the BPF expression
 *      	1 if it does or if the input BPF is an empty expression
 */

uint32_t bpf_filter(const struct sock_fprog * const fcode, uint8_t * packet, size_t plen)
{
	/* XXX: caplen == len */
	uint32_t A, X;
	uint32_t k;
	struct sock_filter *bpf;
	int32_t mem[BPF_MEMWORDS];

	if (fcode == NULL || fcode->filter == NULL || fcode->len == 0)
		return 0xFFFFFFFF;

	A = 0;
	X = 0;

	bpf = fcode->filter;

	--bpf;

	while (1) {

		++bpf;

		switch (bpf->code) {
		default:
			return 0;
		case BPF_RET | BPF_K:
			return (uint32_t) bpf->k;

		case BPF_RET | BPF_A:
			return (uint32_t) A;

		case BPF_LD | BPF_W | BPF_ABS:
			k = bpf->k;
			if (k + sizeof(int32_t) > plen)
				return 0;
			A = EXTRACT_LONG(&packet[k]);
			continue;

		case BPF_LD | BPF_H | BPF_ABS:
			k = bpf->k;
			if (k + sizeof(short) > plen)
				return 0;
			A = EXTRACT_SHORT(&packet[k]);
			continue;

		case BPF_LD | BPF_B | BPF_ABS:
			k = bpf->k;
			if (k >= plen)
				return 0;
			A = packet[k];
			continue;

		case BPF_LD | BPF_W | BPF_LEN:
			A = plen;
			continue;

		case BPF_LDX | BPF_W | BPF_LEN:
			X = plen;
			continue;

		case BPF_LD | BPF_W | BPF_IND:
			k = X + bpf->k;
			if (k + sizeof(int32_t) > plen)
				return 0;
			A = EXTRACT_LONG(&packet[k]);
			continue;

		case BPF_LD | BPF_H | BPF_IND:
			k = X + bpf->k;
			if (k + sizeof(short) > plen)
				return 0;
			A = EXTRACT_SHORT(&packet[k]);
			continue;

		case BPF_LD | BPF_B | BPF_IND:
			k = X + bpf->k;
			if (k >= plen)
				return 0;
			A = packet[k];
			continue;

		case BPF_LDX | BPF_MSH | BPF_B:
			k = bpf->k;
			if (k >= plen)
				return 0;
			X = (packet[bpf->k] & 0xf) << 2;
			continue;

		case BPF_LD | BPF_IMM:
			A = bpf->k;
			continue;

		case BPF_LDX | BPF_IMM:
			X = bpf->k;
			continue;

		case BPF_LD | BPF_MEM:
			A = mem[bpf->k];
			continue;

		case BPF_LDX | BPF_MEM:
			X = mem[bpf->k];
			continue;

		case BPF_ST:
			mem[bpf->k] = A;
			continue;

		case BPF_STX:
			mem[bpf->k] = X;
			continue;

		case BPF_JMP | BPF_JA:
			bpf += bpf->k;
			continue;

		case BPF_JMP | BPF_JGT | BPF_K:
			bpf += (A > bpf->k) ? bpf->jt : bpf->jf;
			continue;

		case BPF_JMP | BPF_JGE | BPF_K:
			bpf += (A >= bpf->k) ? bpf->jt : bpf->jf;
			continue;

		case BPF_JMP | BPF_JEQ | BPF_K:
			bpf += (A == bpf->k) ? bpf->jt : bpf->jf;
			continue;

		case BPF_JMP | BPF_JSET | BPF_K:
			bpf += (A & bpf->k) ? bpf->jt : bpf->jf;
			continue;

		case BPF_JMP | BPF_JGT | BPF_X:
			bpf += (A > X) ? bpf->jt : bpf->jf;
			continue;

		case BPF_JMP | BPF_JGE | BPF_X:
			bpf += (A >= X) ? bpf->jt : bpf->jf;
			continue;

		case BPF_JMP | BPF_JEQ | BPF_X:
			bpf += (A == X) ? bpf->jt : bpf->jf;
			continue;

		case BPF_JMP | BPF_JSET | BPF_X:
			bpf += (A & X) ? bpf->jt : bpf->jf;
			continue;

		case BPF_ALU | BPF_ADD | BPF_X:
			A += X;
			continue;

		case BPF_ALU | BPF_SUB | BPF_X:
			A -= X;
			continue;

		case BPF_ALU | BPF_MUL | BPF_X:
			A *= X;
			continue;

		case BPF_ALU | BPF_DIV | BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;

		case BPF_ALU | BPF_AND | BPF_X:
			A &= X;
			continue;

		case BPF_ALU | BPF_OR | BPF_X:
			A |= X;
			continue;

		case BPF_ALU | BPF_LSH | BPF_X:
			A <<= X;
			continue;

		case BPF_ALU | BPF_RSH | BPF_X:
			A >>= X;
			continue;

		case BPF_ALU | BPF_ADD | BPF_K:
			A += bpf->k;
			continue;

		case BPF_ALU | BPF_SUB | BPF_K:
			A -= bpf->k;
			continue;

		case BPF_ALU | BPF_MUL | BPF_K:
			A *= bpf->k;
			continue;

		case BPF_ALU | BPF_DIV | BPF_K:
			A /= bpf->k;
			continue;

		case BPF_ALU | BPF_AND | BPF_K:
			A &= bpf->k;
			continue;

		case BPF_ALU | BPF_OR | BPF_K:
			A |= bpf->k;
			continue;

		case BPF_ALU | BPF_LSH | BPF_K:
			A <<= bpf->k;
			continue;

		case BPF_ALU | BPF_RSH | BPF_K:
			A >>= bpf->k;
			continue;

		case BPF_ALU | BPF_NEG:
			A = -A;
			continue;

		case BPF_MISC | BPF_TAX:
			X = A;
			continue;

		case BPF_MISC | BPF_TXA:
			A = X;
			continue;
		}

	}
}

/**
 *      \brief	Parse a BPF file representing a BPF expression
 *      \param	bpf_path[in]	BPF file path
 *      \param	bpf[out]	Pointer the parse BPF expression
 *      \return	-1 if the BPF file could not be read-only opened
 *      	or the same return value as bpf_is_valid
 *      \see	bpf_is_valid
 *      \note	a BPF block contained in a BPF file should look like
 *      	{ 0xNN, (0|1), (0|1), 0xNNNNNNNN },
 *      	(e.g { 0x15, 0, 1, 0x00000806 },)
 *      	Lines which does not respect this convention are counted
 *      	as comments
 */

int bpf_parse(const char * const bpf_path, struct sock_fprog *bpf)
{
	int ret;
	char buff[128] = { 0 };

	struct sock_filter sf_single;

	assert(bpf);
	assert(bpf_path);

	FILE *fp = fopen(bpf_path, "r");
	if (!fp) {
		err("Cannot read rulefile");
		return (-1);
	}

	memset(buff, 0, sizeof(buff));

	info("Parsing BPF %s\n", bpf_path);

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		/* We're using evil sscanf, so we have to assure
		   that we don't get into a buffer overflow ... */
		buff[sizeof(buff) - 1] = 0;

		/* A comment. Skip this line */
		if (buff[0] != '{') {
			continue;
		}

		memset(&sf_single, 0, sizeof(sf_single));

		ret = sscanf(buff, "{ 0x%x, %d, %d, 0x%08x },",
			     (unsigned int *)((void *)&(sf_single.code)),
			     (int *)((void *)&(sf_single.jt)), (int *)((void *)&(sf_single.jf)), &(sf_single.k));
		if (ret != 4) {
			/* No valid bpf opcode format or a syntax error */
			return 0;
		}

		bpf->len++;
		bpf->filter = (struct sock_filter *)realloc(bpf->filter, bpf->len * sizeof(sf_single));

		memcpy(&bpf->filter[bpf->len - 1], &sf_single, sizeof(sf_single));

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);

	return (bpf_is_valid(bpf));
}
