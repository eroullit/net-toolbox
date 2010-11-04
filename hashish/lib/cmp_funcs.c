/*
** $Id: cmp_funcs.c 6 2007-08-20 07:52:21Z hgndgtl $
**
** Copyright (C) 2006 - Hagen Paul Pfeifer <hagen@jauu.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <string.h>

#include "privlibhashish.h"

int hi_cmp_str(const uintptr_t key1, const uintptr_t key2)
{
	return strcmp((char *)key1, (char *)key2);
}

int hi_cmp_int(const uintptr_t key1, const uintptr_t key2)
{
	intptr_t a, b;

	a = (intptr_t) key1;
	b = (intptr_t) key2;

	return a - b;
}

int hi_cmp_uint(const uintptr_t key1, const uintptr_t key2)
{
	return key1 - key2;
}

/* vim:set ts=4 sw=4 tw=78 noet: */
