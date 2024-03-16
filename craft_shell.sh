#!/usr/bin/env bash
#echo -n $2 | xxd -p
nasm -f bin $1 -o /dev/stdout | xxd -p |  sed 's/.\{2\}/&\\x/g' | tr -d '\n' | sed 's/^/\\x/' ; echo ""
