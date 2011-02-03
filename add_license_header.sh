#!/bin/sh

#
# nettoolbox-ng Project
# 
# Add license header to file given as argument

licenselen=`wc -l license_header | sed 's/[^0-9]//g'`

for x in `find ${@} -type f -iname *.c -or -iname *.h`; do
  head -${licenselen} ${x} | diff license_header - || ( ( cat license_header; echo; cat ${x}) > tmp_file; mv tmp_file ${x} )
done

rm -f tmp_file
