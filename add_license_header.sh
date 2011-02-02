#!/bin/sh

#
# nettoolbox-ng Project
# 
# Add license header to file given as argument

for file in ${@}
do
	cat license_header ${file} > tmpfile
	mv tmpfile ${file}
done
