#include <cybozu/exception.hpp>
#include <cybozu/string.hpp>
#include <cybozu/atoi.hpp>
#include <iostream>
#include <assert.h>
#include <cybozu/stacktrace.hpp>

struct MailException : cybozu::Exception {
	MailException() : cybozu::Exception("mail") { }
};

void f2()
{
	const char *msg = "HTTP/...";
	std::string abc = "abc";
	char c = 'x';
	int port = 80;
	unsigned int s = 90;
	MailException e;
	e << "can't send" << msg << abc << c << port << s << '\n';
	cybozu::StackTrace st;
	e << st;
	throw e;
}

void f1()
{
	f2();
}

void f0()
{
	f1();
}

int main()
{
	try {
		f0();
	} catch (cybozu::Exception &e) {
		std::cout << "for user" << std::endl;
		std::cout << e.toString() << std::endl;
	} catch (...) {
		std::cout << "Error!" << std::endl;
	}
}
