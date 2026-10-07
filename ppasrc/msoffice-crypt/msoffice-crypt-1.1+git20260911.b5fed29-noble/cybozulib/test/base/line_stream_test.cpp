#include <cybozu/test.hpp>
#include <cybozu/line_stream.hpp>
#include <queue>

const size_t maxLineSize = 20;

struct Socket : public std::queue<std::string> {
	size_t readSome(char *buf, size_t size)
	{
		if (empty()) {
			return 0;
		} else {
			std::string& s = front();
			size_t dataSize = std::min(s.size(), size);
			memcpy(buf, s.data(), dataSize);
			s.erase(0, dataSize);
			if (s.empty()) pop();
			return dataSize;
		}
	}
};

typedef cybozu::LineStreamT<Socket> LineStream;

CYBOZU_TEST_AUTO(test0)
{
	Socket socket;
	LineStream ls(socket, maxLineSize);
	std::string line;
	CYBOZU_TEST_ASSERT(!ls.next(line));
	CYBOZU_TEST_ASSERT(line.empty());
	std::string remain;
	ls.getRemain(remain);
	CYBOZU_TEST_ASSERT(remain.empty());
}

CYBOZU_TEST_AUTO(test1)
{
	Socket socket;
	socket.push("0123456789012345678\n");
	socket.push("abcdefghijklmnopqrst\n");
	socket.push("ABCEF5678901234567890\n");
	LineStream ls(socket, maxLineSize);
	std::string line;
	CYBOZU_TEST_ASSERT(ls.next(line));
	CYBOZU_TEST_EQUAL(line, "0123456789012345678");

	CYBOZU_TEST_ASSERT(ls.next(line));
	CYBOZU_TEST_EQUAL(line, "abcdefghijklmnopqrst");

	CYBOZU_TEST_EXCEPTION_MESSAGE(ls.next(line), cybozu::Exception, "line is too long");
}

CYBOZU_TEST_AUTO(test2)
{
	Socket socket;
	socket.push("01234567890\n0123456789");
	socket.push("01234");
	socket.push("567");
	socket.push("8");
	socket.push("9");
	socket.push("\n");

	socket.push("01234567890\n0123456789");
	socket.push("01234");
	socket.push("567890");

	LineStream ls(socket, maxLineSize);
	std::string line;
	CYBOZU_TEST_ASSERT(ls.next(line));
	CYBOZU_TEST_EQUAL(line, "01234567890");

	CYBOZU_TEST_ASSERT(ls.next(line));
	CYBOZU_TEST_EQUAL(line, "01234567890123456789");

	CYBOZU_TEST_ASSERT(ls.next(line));
	CYBOZU_TEST_EQUAL(line, "01234567890");

	CYBOZU_TEST_EXCEPTION_MESSAGE(ls.next(line), cybozu::Exception, "no CRLF");
}

CYBOZU_TEST_AUTO(test3)
{
	const char tbl[][64] = {
		"abc\r\ndef\nghi",
		"jk\r\n123\n\r\nxyz",
		"A012\n3456\n789\n",
	};
	const char out[][64] = {
		"abc",
		"def",
		"ghijk",
		"123",
		"",
		"xyzA012",
		"3456",
		"789",
	};
	Socket socket;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		socket.push(tbl[i]);
	}
	LineStream ls(socket, maxLineSize);
	size_t outPos = 0;
	for (;;) {
		std::string line;
		if (!ls.next(line)) break;
		CYBOZU_TEST_EQUAL(line, out[outPos]);
		outPos++;
	}
	CYBOZU_TEST_EQUAL(outPos, CYBOZU_NUM_OF_ARRAY(out));
}

CYBOZU_TEST_AUTO(test4)
{
	const char tbl[][64] = {
		"\r\n\r\n",
		"\n\n",
		"\r\r\n",
	};
	const char out[][64] = {
		"",
		"",
		"",
		"",
		"\r",
	};
	Socket socket;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		socket.push(tbl[i]);
	}
	LineStream ls(socket, maxLineSize);
	size_t outPos = 0;
	for (;;) {
		std::string line;
		if (!ls.next(line)) break;
		CYBOZU_TEST_EQUAL(line, out[outPos]);
		outPos++;
	}
	CYBOZU_TEST_EQUAL(outPos, CYBOZU_NUM_OF_ARRAY(out));
}

CYBOZU_TEST_AUTO(lastDataWithoutCRLF)
{
	const char tbl[][64] = {
		"abc\r\ndef\nghi",
		"jk\r\n123\n\r\nxyz",
		"A012\n3456\n789",
	};
	const char out[][64] = {
		"abc",
		"def",
		"ghijk",
		"123",
		"",
		"xyzA012",
		"3456",
		"789",
	};
	Socket socket;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		socket.push(tbl[i]);
	}
	LineStream ls(socket, maxLineSize);
	size_t outPos = 0;
	for (;;) {
		std::string line;
		if (!ls.next(line)) break;
		CYBOZU_TEST_EQUAL(line, out[outPos]);
		outPos++;
	}
	CYBOZU_TEST_EQUAL(outPos, CYBOZU_NUM_OF_ARRAY(out));
}

CYBOZU_TEST_AUTO(remain)
{
	Socket s;
	s.push("123456789\r\nabcdefg\r\n\r\neee\r\n");
	LineStream ls(s);
	const struct {
		const char *line;
		const char *remain;
	} tbl[] = {
		{ "123456789", "abcdefg\r\n\r\neee\r\n" },
		{ "abcdefg", "\r\neee\r\n" },
		{ "", "eee\r\n" },
		{ "eee", "" },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		std::string line;
		CYBOZU_TEST_ASSERT(ls.next(line));
		CYBOZU_TEST_EQUAL(line, tbl[i].line);
		CYBOZU_TEST_EQUAL(ls.getRemain(), tbl[i].remain);
	}
}

CYBOZU_TEST_AUTO(remain2)
{
	Socket s;
	//      0123 4 56789 ; read 10byte(=5 * 2)
	s.push("qwer\r\n123456789a");
	LineStream ls(s, 5);
	std::string line;
	CYBOZU_TEST_ASSERT(ls.next(line));
	CYBOZU_TEST_EQUAL(line, "qwer");
	CYBOZU_TEST_EQUAL(ls.getRemain(), "1234");
	CYBOZU_TEST_EXCEPTION_MESSAGE(ls.next(line), cybozu::Exception, "no CRLF");
}
