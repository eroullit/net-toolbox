#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

#include "bpf_expr.h"

const char * bpf_arith_ops_to_string(const enum bpf_arith_ops op)
{
	static const char * const bpf_arith_ops_string[] = 
	{
		[UNKNOWN_ARITH_OP] = stringify(UNKNOWN_ARITH_OP),
		[EQUAL] = stringify(EQUAL),
		[NOT_EQUAL] = stringify(NOT_EQUAL),
		[LESS] = stringify(LESS),
		[GREATER] = stringify(GREATER),
		[GREATER_EQUAL] = stringify(GREATER_EQUAL),
		[LESS_EQUAL]= stringify(LESS_EQUAL)
	};

	assert(op <= sizeof(bpf_arith_ops_string));

	return (bpf_arith_ops_string[op]);
}

const char * bpf_bit_ops_to_string(const enum bpf_bit_ops op)
{
	static const char * const bpf_bit_ops_string[] = 
	{
		[UNKNOWN_BIT_OP] = stringify(UNKNOWN_BIT_OP),
		[NOT] = stringify(NOT),
		[AND] = stringify(AND),
		[OR] = stringify(OR),
		[XOR] = stringify(XOR)
	};

	assert(op <= sizeof(bpf_bit_ops_string));

	return (bpf_bit_ops_string[op]);
}

const char * bpf_direction_to_string(const enum bpf_direction dir)
{
	static const char * const bpf_direction_string[] = 
	{
		[DIRECTION_UNKNOWN] = stringify(DIRECTION_UNKNOWN),
		[ANY_DIRECTION] = stringify(ANY_DIRECTION),
		[SRC] = stringify(SRC),
		[DST] = stringify(DST)
	};

	assert(dir <= sizeof(bpf_direction_string));

	return (bpf_direction_string[dir]);
}

const char * bpf_code_to_string(const enum bpf_compiler_obj obj)
{
	static const char * const bpf_code_string[] = 
	{
		[UNKNOWN_OBJ] = stringify(UNKNOWN_OBJ),
		[IP] = stringify(IP),
		[IP6] = stringify(IP6),
		[MAC] = stringify(MAC),
		[PORT] = stringify(PORT),
		[BIT_OP] = stringify(BIT_OP),
		[POS_NUMBER] = stringify(POS_NUMBER),
		[MAC_ID] = stringify(MAC_ID)
	};
	
	assert(obj <= sizeof(bpf_code_string));

	return (bpf_code_string[obj]);
}

int bpf_strtoull(const char * const str, uint64_t * val)
{
	char * endptr = NULL;

	assert(str);
	assert(val);

	errno = 0;

	*val = strtoull(str, &endptr, 0);

	if ((errno == ERANGE && *val == ULLONG_MAX) || (errno != 0 && *val == 0)) 
	{
		return(errno);
	}

	if (endptr == str) 
	{
		return(EINVAL);
	}

	return (0);
}

void bpf_expr_init(struct bpf_expr * expr)
{
	assert(expr);

	memset(expr, 0, sizeof(*expr));

	TAILQ_INIT(&expr->head);
}

void bpf_expr_free(struct bpf_expr * expr)
{
	struct bpf_step * step;

	/* Same behaviour as free(3) */
	if (!expr)
		return;

	while((step = TAILQ_FIRST(&expr->head)) != NULL)
	{
		TAILQ_REMOVE(&expr->head, step, entry);
		free(step);
		step = NULL;
	}

	memset(expr, 0, sizeof(*expr));
}

struct bpf_step * bpf_step_alloc(void)
{
	struct bpf_step * step;

	step = malloc(sizeof(*step));

	if (!step)
		return NULL;

	memset(step, 0, sizeof(*step));

	step->obj = UNKNOWN_OBJ;
	step->arith_op = EQUAL;
	step->direction = ANY_DIRECTION;

	return step;
}

int bpf_step_is_value_set(const struct bpf_step * const step)
{
	union value value = {0};

	assert(step);

	return (memcmp(&value, &step->value, sizeof(value)));
}

int bpf_step_set_value(struct bpf_step * step, const union value value)
{
	assert(step);

	switch(step->obj)
	{
		case PORT:
		case LEN:
			step->value.nr = value.nr;
		break;

		case IP:
			step->value.in = value.in;
		break;

		case IP6:
			step->value.in6 = value.in6;
		break;

		case MAC:
			step->value.eth = value.eth;
		break;

		case BIT_OP:
			step->value.bit_op = value.bit_op;
		break;

		default:
			return EINVAL;
		break;
	}

	return 0;
}

int bpf_step_set_direction(struct bpf_step * step, const enum bpf_direction dir)
{
	assert(step);

	step->direction = dir;

	return 0;
}

int bpf_step_set_obj(struct bpf_step * step, const enum bpf_compiler_obj obj)
{
	assert(step);

	step->obj = obj;

	return 0;
}

int bpf_step_set_arith_op(struct bpf_step * step, const enum bpf_arith_ops op)
{
	assert(step);

	step->arith_op = op;

	return 0;
}

int bpf_step_set_bit_op(struct bpf_step * step, const enum bpf_bit_ops op)
{
	assert(step);

	step->obj = BIT_OP;
	step->arith_op = EQUAL;
	step->value.bit_op = op;

	return 0;
}

int bpf_expr_set_step(struct bpf_expr * expr, struct bpf_step * step)
{
        assert(expr);
        assert(step);

	step->nr = expr->len;

	TAILQ_INSERT_TAIL(&expr->head, step, entry);
	expr->len++;

	return 0;
}

int bpf_step_set_number(struct bpf_step * step, const uint64_t nr)
{
	union value value = {0};

	value.nr = nr;

	return bpf_step_set_value(step, value);
}

int bpf_step_set_eth(struct bpf_step * step, const struct ether_addr eth)
{
	union value value = {0};

	value.eth = eth;

	return bpf_step_set_value(step, value);
}

int bpf_step_set_in(struct bpf_step * step, const struct in_addr in)
{
	union value value = {0};

	value.in = in;

	return bpf_step_set_value(step, value);
}

int bpf_step_add_in6(struct bpf_step * step, const struct in6_addr in6)
{
	union value value = {0};

	value.in6 = in6;

	return bpf_step_set_value(step, value);
}

int bpf_print_step(const struct bpf_step * const step)
{
	union
	{
		char in_str[INET_ADDRSTRLEN];
		char in6_str[INET6_ADDRSTRLEN];
	} addr;

	assert(step);

	printf("%s %s %s ", bpf_direction_to_string(step->direction), bpf_code_to_string(step->obj), bpf_arith_ops_to_string(step->arith_op));

	switch(step->obj)
	{
		case IP:
			inet_ntop(AF_INET, &step->value.in, addr.in_str, sizeof(addr.in_str));
			printf("%s", addr.in_str);
		break;

		case IP6:
			inet_ntop(AF_INET6, &step->value.in6, addr.in6_str, sizeof(addr.in6_str));
			printf("%s", addr.in6_str);
		break;

		case MAC:
			printf("%s", ether_ntoa(&step->value.eth));
		break;

		case LEN:
			printf("%"PRIu64"", step->value.nr);
		break;

		case PORT:
			printf("%"PRIu64"", step->value.nr);
		break;

		case BIT_OP:
			printf("%s", bpf_bit_ops_to_string(step->value.bit_op));
		break;
		
		default:
			printf("\n");

			return EINVAL;
		break;
	}

	printf("\n");

	return (0);
}

int bpf_print_expr(const struct bpf_expr * const expr)
{
	int rc = 0;
	struct bpf_step * step;

	assert(expr);

	TAILQ_FOREACH(step, &expr->head, entry)
	{
		rc = bpf_print_step(step);

		if (rc)
			break;
	}

	return rc;
}
