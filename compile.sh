#!/bin/sh

sed -i 's/[ \t]*$//' "./allocators/a2alloc/a2alloc.c"
export TOPDIR=`pwd`
make clean
make 
make debug
