# Author: Martin Pech <xpechm00@stud.fit.vutbr.cz>
PROJECT = ipk_1

CC = g++
#CFLAGS = -std=c99 -Werror -Wall -Wextra -pedantic

default: 
	$(CC) ipk-sniffer.cpp -o ipk-sniffer -lpcap

clear:
	rm *.cpp

clearAll:
	rm *.cpp
	rm ipk-sniffer
	rm makefile

run:
	./ipk-sniffer -i