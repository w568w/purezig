// Example shared library for foreign dlopen demo

#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

void greet(const char *name) {
    printf("Hello, %s! (from example.so)\n", name);
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
