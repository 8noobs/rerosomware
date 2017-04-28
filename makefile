CC := gcc
SRCS := rsa.c main.c

debug: $(SRCS)
	$(CC) -Wall -g $^ -o ransom

release: $(SRCS)
	$(CC) -Wall -O3 -DNDEBUG -mwindows $^ -o ransom
