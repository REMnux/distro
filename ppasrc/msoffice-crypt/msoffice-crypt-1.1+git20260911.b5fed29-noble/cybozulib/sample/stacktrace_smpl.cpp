/*
	sample how to use stacktrace
	g++ -I ../include/ stacktrace_smpl.cpp -g -rdynamic && ./a.out
*/
#include <stdio.h>
#include <iostream>
#define CYBOZU_EXCEPTION_WITH_STACKTRACE
#include <cybozu/exception.hpp>

void putStackTrace()
{
	throw cybozu::Exception("throw test");
}

struct A {
	void f() {
		putStackTrace();
	}
};

struct B {
	A a;
	void g() {
		a.f();
	}
};

void func()
{
	puts("func");
	B b;
	b.g();
}

void g()
{
	func();
}

void h()
{
	g();
}

int main()
	try
{
	h();
} catch (std::exception& e) {
	printf("e=%s\n", e.what());
}

