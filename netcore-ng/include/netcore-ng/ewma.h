/**
 * \file ewma.h
 * \author written by Bruno Randolf <br1@einfach.org> (c)
 * \date 2011
 */

/* __LICENSE_HEADER_BEGIN__ */

/*
 * Copyright (C) 2010-2011	Emmanuel Roullit <emmanuel@netsniff-ng.org>
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

#ifndef EWMA_H
#define	EWMA_H

#include <stdint.h>

#define DEFAULT_EWMA_WEIGHT 8
#define DEFAULT_EWMA_FACTOR 1024

struct ewma {
	uint64_t internal;
	uint64_t factor;
	uint64_t weight;
};

int ewma_init(struct ewma * const avg, const uint64_t factor, const uint64_t weight);
struct ewma * ewma_add(struct ewma * const avg, const uint64_t val);

/**
 * \brief Read average struct
 * \param[in] avg Average structure
 * \return average value
 * \note The maximum value of averages can be \f$\frac{UINT64\_MAX}{factor*weight}\f$.
 */

static inline uint64_t ewma_read(const struct ewma * const avg)
{
	return avg->internal >> avg->factor;
}

#endif	/* EWMA_H */

