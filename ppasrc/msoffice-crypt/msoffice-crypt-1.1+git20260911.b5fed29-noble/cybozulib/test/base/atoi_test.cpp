#include <stdio.h>
#include <iostream>
#include <cybozu/atoi.hpp>
#include <cybozu/test.hpp>

CYBOZU_TEST_AUTO(test_int8_t)
{
    const struct {
        const char *str;
        int8_t x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "126", 126 },
        { "127", 127 },
        { "-1", -1 },
        { "-12", -12 },
        { "-123", -123 },
        { "-126", -126 },
        { "-127", -127 },
        { "-128", -128 },
        { "00000", 0 },
        { "-0", 0 },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "-00000", 0 },
        { "-001", -1 },
        { "-0012", -12 },
        { "-00000123", -123 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        int8_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const int8_t numTbl[] = { 1, 12, 123 };
        const char str[] = "123";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            int8_t x = 0;
            CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str, i + 1));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        int8_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str2, 2));
        CYBOZU_TEST_EQUAL(x, 12);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "128", "129", "-129", "-130",
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<int8_t>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<int8_t>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(test_uint8_t)
{
    const struct {
        const char *str;
        uint8_t x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "254", 254 },
        { "255", 255 },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "000255", 255 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        uint8_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const uint8_t numTbl[] = { 1, 12, 123 };
        const char str[] = "123";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            uint8_t x = 0;
            CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str, i + 1));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        uint8_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str2, 2));
        CYBOZU_TEST_EQUAL(x, 12U);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "-2", "4294967296", "4294967297", "4294967298", "4294967299", "4294967300"
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<uint8_t>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<uint8_t>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(test_int)
{
    const struct {
        const char *str;
        int x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "1223424", 1223424 },
        { "214748364", 214748364 },
        { "314748364", 314748364 },
        { "2147483639", 2147483639 },
        { "2147483640", 2147483640 },
        { "2147483641", 2147483641 },
        { "2147483642", 2147483642 },
        { "2147483643", 2147483643 },
        { "2147483644", 2147483644 },
        { "2147483645", 2147483645 },
        { "2147483646", 2147483646 },
        { "2147483647", 2147483647 },
        { "-1", -1 },
        { "-12", -12 },
        { "-123", -123 },
        { "-1223424", -1223424 },
        { "-214748364", -214748364 },
        { "-314748364", -314748364 },
        { "-2147483645", -2147483645 },
        { "-2147483646", -2147483646 },
        { "-2147483647", -2147483647 },
        { "-2147483648", -2147483647 - 1 },
        { "00000", 0 },
        { "-0", 0 },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "01223424", 1223424 },
        { "0000214748364", 214748364 },
        { "00314748364", 314748364 },
        { "002147483645", 2147483645 },
        { "002147483646", 2147483646 },
        { "0002147483647", 2147483647 },
        { "-00000", 0 },
        { "-001", -1 },
        { "-0012", -12 },
        { "-00000123", -123 },
        { "-01223424", -1223424 },
        { "-0000214748364", -214748364 },
        { "-00314748364", -314748364 },
        { "-002147483645", -2147483645 },
        { "-002147483646", -2147483646 },
        { "-0002147483647",-2147483647 },
        { "-0002147483648", -2147483647 - 1 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        int x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const int numTbl[] = { 1, 12, 123, 1234, 12345, 12345, 12345 };
        const char str[] = "12345";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            int x = 0;
            CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str, i + 1));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        int x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str2, 2));
        CYBOZU_TEST_EQUAL(x, 12);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "2147483648", "2147483649", "2147483650", "2147483651",
        "-2147483649", "-2147483650", "-2147483651",
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<int>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<int>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(test_short)
{
    const struct {
        const char *str;
        short x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "32765", 32765 },
        { "32766", 32766 },
        { "32767", 32767 },
        { "-1", -1 },
        { "-12", -12 },
        { "-123", -123 },
        { "-32766", -32766 },
        { "-32767", -32767 },
        { "-32768", -32768 },
        { "00000", 0 },
        { "-0", 0 },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "0032766", 32766 },
        { "00032767", 32767 },
        { "-00000", 0 },
        { "-001", -1 },
        { "-0012", -12 },
        { "-00000123", -123 },
        { "-000032767", -32767 },
        { "-000032768", -32768 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        short x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const short numTbl[] = { 1, 12, 123, 1234, 12345, 12345, 12345 };
        const char str[] = "12345";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            short x = 0;
            CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str, i + 1));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        short x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str2, 2));
        CYBOZU_TEST_EQUAL(x, 12);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "32768", "32769",
        "-32769", "-32770", "-32771",
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<short>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<short>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(test_unsigned_short)
{
    const struct {
        const char *str;
        unsigned short x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "12234", 12234 },
        { "32767", 32767 },
        { "32768", 32768 },
        { "65534", 65534 },
        { "65535", 65535 },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "01223", 1223 },
        { "000065534", 65534 },
        { "000065535", 65535 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        unsigned short x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const unsigned short numTbl[] = { 1, 12, 123, 1234, 12345, 12345, 12345 };
        const char str[] = "12345";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            unsigned short x = 0;
            CYBOZU_TEST_NO_EXCEPTION(cybozu::disable_warning_unused_variable(x = cybozu::atoi(str, i + 1)));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        unsigned short x = 0;
        CYBOZU_TEST_NO_EXCEPTION(cybozu::disable_warning_unused_variable(x = cybozu::atoi(str2, 2)));
        CYBOZU_TEST_EQUAL(x, 12);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "-2", "65536", "65537",
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<unsigned short>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<unsigned short>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(test_uint)
{
    const struct {
        const char *str;
        unsigned int x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "1223424", 1223424 },
        { "214748364", 214748364 },
        { "314748364", 314748364 },
        { "2147483639", 2147483639 },
        { "2147483640", 2147483640 },
        { "2147483641", 2147483641 },
        { "2147483642", 2147483642 },
        { "2147483643", 2147483643 },
        { "2147483644", 2147483644 },
        { "2147483645", 2147483645 },
        { "2147483646", 2147483646 },
        { "2147483647", 2147483647 },
        { "2147483648", 2147483648U },
        { "2147483649", 2147483649U },
        { "2147483650", 2147483650U },
        { "2147483651", 2147483651U },
        { "2147483652", 2147483652U },
        { "2147483653", 2147483653U },
        { "2147483654", 2147483654U },
        { "2147483655", 2147483655U },
        { "4294967286", 4294967286U },
        { "4294967287", 4294967287U },
        { "4294967288", 4294967288U },
        { "4294967289", 4294967289U },
        { "4294967290", 4294967290U },
        { "4294967291", 4294967291U },
        { "4294967292", 4294967292U },
        { "4294967293", 4294967293U },
        { "4294967294", 4294967294U },
        { "4294967295", 4294967295U },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "01223424", 1223424 },
        { "0000214748364", 214748364 },
        { "00314748364", 314748364 },
        { "002147483645", 2147483645 },
        { "002147483646", 2147483646 },
        { "0002147483647", 2147483647 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        unsigned int x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const unsigned numTbl[] = { 1, 12, 123, 1234, 12345, 12345, 12345 };
        const char str[] = "12345";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            unsigned int x = 0;
            CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str, i + 1));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        unsigned int x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str2, 2));
        CYBOZU_TEST_EQUAL(x, 12U);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "-2", "4294967296", "4294967297", "4294967298", "4294967299", "4294967300"
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<unsigned int>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<unsigned int>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(test_int64)
{
    const struct {
        const char *str;
        int64_t x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "1223424", 1223424 },
        { "214748364", 214748364 },
        { "314748364", 314748364 },
        { "2147483639", 2147483639 },
        { "2147483640", 2147483640 },
        { "2147483641", 2147483641 },
        { "2147483642", 2147483642 },
        { "2147483643", 2147483643 },
        { "2147483644", 2147483644 },
        { "2147483645", 2147483645 },
        { "2147483646", 2147483646 },
        { "2147483647", 2147483647 },
        { "9223372036854775794", 9223372036854775794LL },
        { "9223372036854775795", 9223372036854775795LL },
        { "9223372036854775796", 9223372036854775796LL },
        { "9223372036854775797", 9223372036854775797LL },
        { "9223372036854775798", 9223372036854775798LL },
        { "9223372036854775799", 9223372036854775799LL },
        { "9223372036854775800", 9223372036854775800LL },
        { "9223372036854775801", 9223372036854775801LL },
        { "9223372036854775802", 9223372036854775802LL },
        { "9223372036854775803", 9223372036854775803LL },
        { "9223372036854775804", 9223372036854775804LL },
        { "9223372036854775805", 9223372036854775805LL },
        { "9223372036854775806", 9223372036854775806LL },
        { "9223372036854775807", 9223372036854775807LL },
        { "-1", -1 },
        { "-12", -12 },
        { "-123", -123 },
        { "-1223424", -1223424 },
        { "-214748364", -214748364 },
        { "-314748364", -314748364 },
        { "-2147483645", -2147483645 },
        { "-2147483646", -2147483646 },
        { "-2147483647", -2147483647 },
        { "-2147483648", -2147483647 - 1 },
        { "-9223372036854775795", -9223372036854775795LL },
        { "-9223372036854775796", -9223372036854775796LL },
        { "-9223372036854775797", -9223372036854775797LL },
        { "-9223372036854775798", -9223372036854775798LL },
        { "-9223372036854775799", -9223372036854775799LL },
        { "-9223372036854775800", -9223372036854775800LL },
        { "-9223372036854775801", -9223372036854775801LL },
        { "-9223372036854775802", -9223372036854775802LL },
        { "-9223372036854775803", -9223372036854775803LL },
        { "-9223372036854775804", -9223372036854775804LL },
        { "-9223372036854775805", -9223372036854775805LL },
        { "-9223372036854775806", -9223372036854775806LL },
        { "-9223372036854775807", -9223372036854775807LL },
        { "-9223372036854775808", -9223372036854775807LL - 1 },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "01223424", 1223424 },
        { "0000214748364", 214748364 },
        { "00314748364", 314748364 },
        { "002147483645", 2147483645 },
        { "002147483646", 2147483646 },
        { "0002147483647", 2147483647 },
        { "-0", 0 },
        { "-00000", 0 },
        { "-001", -1 },
        { "-0012", -12 },
        { "-00000123", -123 },
        { "-01223424", -1223424 },
        { "-0000214748364", -214748364 },
        { "-00314748364", -314748364 },
        { "-002147483645", -2147483645 },
        { "-002147483646", -2147483646 },
        { "-0002147483647",-2147483647 },
        { "-0002147483648", -2147483647 - 1 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        int64_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const int64_t numTbl[] = { 1, 12, 123, 1234, 12345, 12345, 12345 };
        const char str[] = "12345";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            int64_t x = 0;
            CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str, i + 1));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        int64_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str2, 2));
        CYBOZU_TEST_EQUAL(x, 12);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "9223372036854775808", "9223372036854775809", "9223372036854775810",
        "-9223372036854775809",
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<int64_t>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<int64_t>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(test_uint64)
{
    const struct {
        const char *str;
        uint64_t x;
    } okTbl[] = {
        { "0", 0 },
        { "1", 1 },
        { "12", 12 },
        { "123", 123 },
        { "1223424", 1223424 },
        { "214748364", 214748364 },
        { "314748364", 314748364 },
        { "2147483639", 2147483639 },
        { "2147483640", 2147483640 },
        { "2147483641", 2147483641 },
        { "2147483642", 2147483642 },
        { "2147483643", 2147483643 },
        { "2147483644", 2147483644 },
        { "2147483645", 2147483645 },
        { "2147483646", 2147483646 },
        { "2147483647", 2147483647 },
        { "9223372036854775794", 9223372036854775794LL },
        { "9223372036854775795", 9223372036854775795LL },
        { "9223372036854775796", 9223372036854775796LL },
        { "9223372036854775797", 9223372036854775797LL },
        { "9223372036854775798", 9223372036854775798LL },
        { "9223372036854775799", 9223372036854775799LL },
        { "9223372036854775800", 9223372036854775800LL },
        { "9223372036854775801", 9223372036854775801LL },
        { "9223372036854775802", 9223372036854775802LL },
        { "9223372036854775803", 9223372036854775803LL },
        { "9223372036854775804", 9223372036854775804LL },
        { "9223372036854775805", 9223372036854775805LL },
        { "9223372036854775806", 9223372036854775806LL },
        { "9223372036854775807", 9223372036854775807LL },
        { "18446744073709551607", 18446744073709551607ULL },
        { "18446744073709551608", 18446744073709551608ULL },
        { "18446744073709551609", 18446744073709551609ULL },
        { "18446744073709551610", 18446744073709551610ULL },
        { "18446744073709551611", 18446744073709551611ULL },
        { "18446744073709551612", 18446744073709551612ULL },
        { "18446744073709551613", 18446744073709551613ULL },
        { "18446744073709551614", 18446744073709551614ULL },
        { "18446744073709551615", 18446744073709551615ULL },
        { "00000", 0 },
        { "001", 1 },
        { "0012", 12 },
        { "00000123", 123 },
        { "01223424", 1223424 },
        { "0000214748364", 214748364 },
        { "00314748364", 314748364 },
        { "002147483645", 2147483645 },
        { "002147483646", 2147483646 },
        { "0002147483647", 2147483647 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(okTbl); i++) {
        uint64_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(okTbl[i].str));
        CYBOZU_TEST_EQUAL(x, okTbl[i].x);
    }
    {
        const uint64_t numTbl[] = { 1, 12, 123, 1234, 12345, 12345, 12345 };
        const char str[] = "12345";
        for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(numTbl); i++) {
            uint64_t x = 0;
            CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str, i + 1));
            CYBOZU_TEST_EQUAL(x, numTbl[i]);
        }
        const char str2[] = "12abc";
        uint64_t x = 0;
        CYBOZU_TEST_NO_EXCEPTION(x = cybozu::atoi(str2, 2));
        CYBOZU_TEST_EQUAL(x, 12U);
    }
    const char ngTbl[][40] = {
        "", "a", "000-", "-", "00s",
        "-2", "18446744073709551616", "18446744073709551617", "18446744073709551618",
        "18446744073709551619", "18446744073709551620"
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ngTbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<uint64_t>(cybozu::atoi(ngTbl[i]))), cybozu::Exception);
    }
    const struct {
        const char *str;
        size_t len;
    } ng2Tbl[] = {
        { "", 0 },
        { "", 1 },
        { "1a", 2 },
        { "1a", 3 },
        { "234b", 4 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(ng2Tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<uint64_t>(cybozu::atoi(ng2Tbl[i].str, ng2Tbl[i].len))), cybozu::Exception);
    }
}

CYBOZU_TEST_AUTO(itohexchar)
{
    const struct {
        const char *strL;
        const char *strH;
        unsigned char val;
    } tbl[] = {
        { "00", "00", 0 },
        { "01", "01", 1 },
        { "02", "02", 2 },
        { "03", "03", 3 },
        { "04", "04", 4 },
        { "05", "05", 5 },
        { "06", "06", 6 },
        { "07", "07", 7 },
        { "08", "08", 8 },
        { "09", "09", 9 },
        { "0a", "0A", 10 },
        { "0b", "0B", 11 },
        { "0c", "0C", 12 },
        { "0d", "0D", 13 },
        { "0e", "0E", 14 },
        { "0f", "0F", 15 },
        { "31", "31", 49 },
        { "32", "32", 50 },
        { "33", "33", 51 },
        { "34", "34", 52 },
        { "35", "35", 53 },
        { "36", "36", 54 },
        { "37", "37", 55 },
        { "38", "38", 56 },
        { "39", "39", 57 },
        { "3a", "3A", 58 },
        { "3b", "3B", 59 },
        { "3c", "3C", 60 },
        { "3d", "3D", 61 },
        { "3e", "3E", 62 },
        { "3f", "3F", 63 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
        unsigned char a = cybozu::hextoi(tbl[i].strL);
        CYBOZU_TEST_EQUAL(a, tbl[i].val);
        unsigned char b = cybozu::hextoi(tbl[i].strH);
        CYBOZU_TEST_EQUAL(b, tbl[i].val);
    }
}

CYBOZU_TEST_AUTO(hextoi)
{
    CYBOZU_TEST_EQUAL(static_cast<unsigned char>(cybozu::hextoi("ff")), 0xff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned short>(cybozu::hextoi("ff")), 0xff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned short>(cybozu::hextoi("ff")), 0xff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned short>(cybozu::hextoi("ffff")), 0xffff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned int>(cybozu::hextoi("ffffffff")), 0xffffffff);
    CYBOZU_TEST_EQUAL(static_cast<uint64_t>(cybozu::hextoi("ffffffff")), uint64_t(0xffffffffULL));
    CYBOZU_TEST_EQUAL(static_cast<unsigned char>(cybozu::hextoi("00000ff")), 0xff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned short>(cybozu::hextoi("00000ff")), 0xff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned short>(cybozu::hextoi("00000ff")), 0xff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned short>(cybozu::hextoi("00000ffff")), 0xffff);
    CYBOZU_TEST_EQUAL(static_cast<unsigned int>(cybozu::hextoi("00000ffffffff")), 0xffffffff);
    CYBOZU_TEST_EQUAL(static_cast<uint64_t>(cybozu::hextoi("00000ffffffff")), uint64_t(0xffffffffULL));

    CYBOZU_TEST_EQUAL(static_cast<unsigned int>(cybozu::hextoi("123xxx", 3)), 0x123U);
    CYBOZU_TEST_EQUAL(static_cast<unsigned int>(cybozu::hextoi("1234xx", 4)), 0x1234U);
    CYBOZU_TEST_EQUAL(static_cast<unsigned int>(cybozu::hextoi("12345x", 5)), 0x12345U);
    CYBOZU_TEST_EQUAL(static_cast<unsigned int>(cybozu::hextoi("12345", 5)), 0x12345U);
    CYBOZU_TEST_EQUAL(static_cast<unsigned int>(cybozu::hextoi("12345", 6)), 0x12345U);

    CYBOZU_TEST_EQUAL(static_cast<int>(cybozu::hextoi("123xxx", 3)), 0x123);
    CYBOZU_TEST_EQUAL(static_cast<int>(cybozu::hextoi("1234xx", 4)), 0x1234);
    CYBOZU_TEST_EQUAL(static_cast<int>(cybozu::hextoi("12345x", 5)), 0x12345);
    CYBOZU_TEST_EQUAL(static_cast<int>(cybozu::hextoi("12345", 5)), 0x12345);
    CYBOZU_TEST_EQUAL(static_cast<int>(cybozu::hextoi("12345", 6)), 0x12345);

    CYBOZU_TEST_EQUAL(static_cast<char>(cybozu::hextoi("7f")), 0x7f);
    CYBOZU_TEST_EQUAL(static_cast<short>(cybozu::hextoi("7fff")), 0x7fff);
    CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<uint8_t>(cybozu::hextoi("100"))), cybozu::Exception);
    CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<int8_t>(cybozu::hextoi("80"))), cybozu::Exception);

    const struct {
        const char *str;
        size_t len;
    } tbl[] = {
        { "", 0 },
        { "", 1 },
        { "x", 1 },
        { "234x", 10 },
        { "234x", 10 },
        { "fffffffff", 20 },
        { "fffffffff", 9 },
    };
    for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
        CYBOZU_TEST_EXCEPTION(cybozu::disable_warning_unused_variable(static_cast<unsigned int>(cybozu::hextoi(tbl[i].str, tbl[i].len))), cybozu::Exception);
    }
}
