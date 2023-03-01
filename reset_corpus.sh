#!/bin/bash
rm /home/root/corpus/*

# replace path strings with literals, removing ""

#find "<path-to-dataset>" -size -5 -exec cp -v "{}" "<path-to-corpus>"/corpus/ \;
#cp -v /-/data/BLQYONKYGPSK7RW76LOAUDZGQXB634CT.pdf /-/corpus/
#cp -v /-/data/CS4O7BCLPRK6J5MKIK7BPBFC2UURCM7X.pdf /-/corpus/
#cp -v /-/data/HPXULDFI3DAZ3V2NZOHYUGUY5SLS4AHU.pdf /-/corpus/

find "<path-to-dataset>" -size -6 -exec cp "{}" "<path-to-corpus>"/corpus \;
#1.7K    /-/corpus/BLQYONKYGPSK7RW76LOAUDZGQXB634CT.pdf
#1.6K    /-/corpus/CS4O7BCLPRK6J5MKIK7BPBFC2UURCM7X.pdf
#1.7K    /-/corpus/HPXULDFI3DAZ3V2NZOHYUGUY5SLS4AHU.pdf
#1.4K    /-/corpus/J5ZSV4CEZDUKODXRBOAVGJVB5XTR5QMA.pdf
#1.8K    /-/corpus/JQTLTBNFMLOTJNAZWAJGUYXUWJ42X5WM.pdf
#2.0K    /-/corpus/W5VHS6JXL2IZQKOADSVN6J2JWZPNWVC6.pdf
#1.8K    /-/corpus/WT4PUCQSO7JLM6FV4HZDJ6DN4ZGWFL7U.pdf
#12K     total
