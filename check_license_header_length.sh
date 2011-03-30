#!/bin/sh

LICENSE_BEGIN="__LICENSE_HEADER_BEGIN__"
LICENSE_END="__LICENSE_HEADER_END__"
license_length=0

while read line;
do
	if [ "${start_count}" = "1" ]; then
		echo "${line}" | grep -q ${LICENSE_BEGIN}
		if [ "${?}" = "0" ]; then
			start_count=1
		fi
	else
		license_length=$((${license_length} + 1))

		echo "${line}" | grep -q ${LICENSE_END}

		if [ "${?}" = "0" ]; then
			break;
		fi
	fi
done < ${1}

echo "Length of license header is ${license_length}"
