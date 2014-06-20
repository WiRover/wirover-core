CC = gcc
CFLAGS = -Wall -g
LIBS = 
LIBFLAGS = 
OBJECTS = policy.o

all: vpolicy

vpolicy: policy.c policyFunctions.c policyFunctions.h policyTypes.h
	$(CC) $(CFLAGS) policyFunctions.c policy.c -o vpolicy -lm

clean:
	rm -f *.o *~ core* vpolicy
