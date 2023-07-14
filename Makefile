#
# Student makefile for Cache Lab
# Note: requires a 64-bit x86-64 system 
#
CC = gcc
CFLAGS = -g -std=gnu99 -m64

UNAME := $(shell uname)

#ifeq ($(UNAME), Linux)
#	CFLAGS += -static
#endif

all: cache

cache: cache.c cache.h main.c dogfault.h
	$(CC) $(CFLAGS) -o $@ cache.c main.c -lm 

#
# Clean the src dirctory
#
clean:
	rm -rf *.o *~ cache
deepclean: clean
	rm -f traces/out/*
