#!/bin/bash
gcc -c -o memscan.o memscan.c
gcc -shared -o libmemscan.so memscan.o
