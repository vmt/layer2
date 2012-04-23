# Makefile - layer2 Makefile.
#
# Copyright (c) 2005 Vivek Mohan <vivek@sig9.com>
# All rights reserved.
# See (LICENSE)
#
CC		= gcc
CFLAGS		= -Wall -g -DL2_VERBOSE
LIBS		= -lnet -lpcap -lpthread
RM		= rm

.SUFFIXES: .c .o
.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

OBJS	 = layer2.o conf.o
MAINOBJ	 = main.o

all: layer2

layer2: $(OBJS) $(MAINOBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o layer2 $(MAINOBJ) $(OBJS) $(LIBS)

main.o:	main.c layer2.h conf.h
layer2.o: layer2.c layer2.h
conf.o: conf.c conf.h

clean:
	$(RM) -f *.core *.o *~ layer2
