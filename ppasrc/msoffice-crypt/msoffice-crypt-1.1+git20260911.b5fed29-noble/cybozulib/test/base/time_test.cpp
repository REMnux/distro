#include <stdio.h>
#include <memory.h>
#include <cybozu/time.hpp>
#include <cybozu/test.hpp>

#ifdef _WIN32
	#define MK_GMT_TIME(x) _mkgmtime64(x)
#else
	#define MK_GMT_TIME(x) timegm(x)
#endif

std::string timeToStr(std::time_t & time, int year, int month, int day, int hour, int minute, int second, int msec, int mode)
{
	struct tm tm;
	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = minute;
	tm.tm_sec = second;
	tm.tm_isdst = 0;
	time = MK_GMT_TIME(&tm);

	char buf[64];
	if (mode & 1) {
		// "2009-01-23 02:53:44"
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
	} else {
		// "2009-Jan-23 02:53:44"
		strftime(buf, sizeof(buf), "%Y-%b-%d %H:%M:%S", &tm);
	}
	std::string str = buf;
	if (mode & 2) {
		char buf2[64];
		CYBOZU_SNPRINTF(buf2, 5, ".%03d", msec);
		str += buf2;
	}
	return str;
}

CYBOZU_TEST_AUTO(fromString1)
{
	std::string str;
	std::time_t time;
	for (int mode = 0; mode < 4; mode++) {
		int year = 2009;
		int day = 23;
		int hour = 2;
		int minute = 53;
		int second = 41;
		int msec = 72;
		for (int month = 1; month <= 12; month++) {
			str = timeToStr(time, year, month, day, hour, minute, second, msec, mode);
			cybozu::Time tm(str);
			CYBOZU_TEST_EQUAL(tm.getTime(), time);
			if (mode & 2) {
				CYBOZU_TEST_EQUAL(tm.getMsec(), msec);
			}
		}
	}
}

CYBOZU_TEST_AUTO(fromString2)
{
	const struct Data {
		const char *str;
		int year;
		int month;
		int day;
		int hour;
		int minute;
		int second;
		int msec;
	} tbl[] = {
		{ "2009-Jan-23T02:53:44Z", 2009, 1, 23, 2, 53, 44, 0 },
		{ "2009-Jan-23T02:53:44.078Z", 2009, 1, 23, 2, 53, 44, 78 },
		{ "2009-Jan-23T02:53:44", 2009, 1, 23, 2, 53, 44, 0 },
		{ "2009-Jan-23T02:53:44.078", 2009, 1, 23, 2, 53, 44, 78 },
		{ "2009-Jan-23 02:53:44", 2009, 1, 23, 2, 53, 44, 0 },
		{ "2009-Jan-23 02:53:44.078", 2009, 1, 23, 2, 53, 44, 78 },
		{ "2009/Jan/23 02:53:44", 2009, 1, 23, 2, 53, 44, 0 },
		{ "2009/Jan/23 02:53:44.078", 2009, 1, 23, 2, 53, 44, 78 },
		{ "2009/01/23 02:53:44", 2009, 1, 23, 2, 53, 44, 0 },
		{ "2009/01/23 02:53:44.078", 2009, 1, 23, 2, 53, 44, 78 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const Data& d = tbl[i];
		std::time_t time;
		timeToStr(time, d.year, d.month, d.day, d.hour, d.minute, d.second, d.msec, 0);
		{
			cybozu::Time t;
			t.fromString(std::string(d.str));
			CYBOZU_TEST_EQUAL(t.getTime(), time);
		}
		cybozu::Time tm(d.str);
		CYBOZU_TEST_EQUAL(tm.getTime(), time);
		CYBOZU_TEST_EQUAL(tm.getMsec(), d.msec);
		uint32_t high, low;
		tm.getFILETIME(low, high);
		cybozu::Time tm2;
		tm2.setByFILETIME(low, high);
		CYBOZU_TEST_EQUAL(tm, tm2);
	}
	bool b;
	cybozu::Time t;
	t.fromString(&b, "2009-01-23T02:53:44Z");
	CYBOZU_TEST_ASSERT(b);
	t.fromString(&b, "2009-01-23T02:53:44x");
	CYBOZU_TEST_ASSERT(!b);
}

CYBOZU_TEST_AUTO(toString)
{
	const struct Data {
		const char *str;
		const char *strMsec;
		int year;
		int month;
		int day;
		int hour;
		int minute;
		int second;
		int msec;
	} tbl[] = {
		{ "2013-11-05 12:23:56", ".123", 2013, 11, 5, 12, 23, 56, 123 },
		{ "1970-01-01 00:00:00", ".000", 1970, 1, 1, 0, 0, 0, 0 },
		{ "2040-02-05 12:30:20", ".999", 2040, 2, 5, 12, 30, 20, 999 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		const Data& d = tbl[i];
		std::time_t time;
		timeToStr(time, d.year, d.month, d.day, d.hour, d.minute, d.second, d.msec, 0);
		cybozu::Time tm(time, d.msec);
		std::string s;
		tm.toString(s);
		CYBOZU_TEST_EQUAL(s, std::string(tbl[i].str) + tbl[i].strMsec);
		tm.toString(s, false);
		CYBOZU_TEST_EQUAL(s, tbl[i].str);
	}
}
#ifdef _WIN32
#include <sstream>

CYBOZU_TEST_AUTO(filetime_win)
{
	SYSTEMTIME st;
	GetSystemTime(&st);
	// 2009-01-23 02:53:44.078
	char buf[256];
	CYBOZU_SNPRINTF(buf, sizeof(buf) - 1, "%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	std::string t1 = buf;

	FILETIME ft;
	SystemTimeToFileTime(&st, &ft);
	cybozu::Time time;
	time.setByFILETIME(ft.dwLowDateTime, ft.dwHighDateTime);
	std::string t2 = time.toString();
	CYBOZU_TEST_EQUAL(t1, t2);
	FILETIME ft2;
	time.getFILETIME(ft2.dwLowDateTime, ft2.dwHighDateTime);
	CYBOZU_TEST_EQUAL(ft.dwLowDateTime, ft2.dwLowDateTime);
	CYBOZU_TEST_EQUAL(ft.dwHighDateTime, ft2.dwHighDateTime);
}
#endif
