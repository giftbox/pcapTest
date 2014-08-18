all: test.c
	arm-linux-gcc -o test test.c -lpcap

clean:
	rm -rf *.o test
