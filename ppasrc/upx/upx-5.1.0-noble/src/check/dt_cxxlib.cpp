/* dt_cxxlib.cpp -- doctest check

   This file is part of the UPX executable compressor.

   Copyright (C) Markus Franz Xaver Johannes Oberhumer
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer
   <markus@oberhumer.com>
 */

// lots of tests (and probably quite a number of redundant tests)
// modern compilers will optimize away much of this code

#include "../util/system_headers.h"
#include <vector> // std::vector
#include "../conf.h"

/*************************************************************************
// standard C++ library
**************************************************************************/

TEST_CASE("std::vector") {
    constexpr size_t N = 16;
    std::vector<int> v(N);
    CHECK(v.end() - v.begin() == N);
    CHECK(&v[0] == &(*(v.begin())));
    // CHECK(&v[0] + N == &(*(v.end()))); // TODO later: is this legal??
#if defined(_LIBCPP_HARDENING_MODE) && defined(_LIBCPP_HARDENING_MODE_DEBUG) &&                    \
    (_LIBCPP_HARDENING_MODE == _LIBCPP_HARDENING_MODE_DEBUG)
    // unfortunately this does NOT throw but ABORTS
    ////CHECK_THROWS((void) &v[N]);
#endif
    UNUSED(v);
}

/*************************************************************************
// core util: UPX_CXX_DISABLE_xxx, noncopyable
**************************************************************************/

namespace {
template <class TA, class TB, int TC = 0>
struct MyType1 {
    MyType1() noexcept {}
    UPX_CXX_DISABLE_ADDRESS(MyType1)
    UPX_CXX_DISABLE_COPY_MOVE(MyType1)
    UPX_CXX_DISABLE_NEW_DELETE_NO_VIRTUAL(MyType1)
};
template <class TA, class TB, int TC = 0>
struct MyType2 {
    MyType2() noexcept {}
    UPX_CXX_DISABLE_COPY_MOVE(MyType2)
    typedef MyType2<TA, TB, TC> Self;
    UPX_CXX_DISABLE_ADDRESS(Self)
    UPX_CXX_DISABLE_NEW_DELETE_NO_VIRTUAL(Self)
};
template <class TA, class TB, int TC = 0>
struct MyVType1 {
    MyVType1() noexcept {}
    virtual ~MyVType1() noexcept {}
    UPX_CXX_DISABLE_ADDRESS(MyVType1)
    UPX_CXX_DISABLE_COPY_MOVE(MyVType1)
    UPX_CXX_DISABLE_NEW_DELETE(MyVType1)
};
template <class TA, class TB, int TC = 0>
struct MyVType2 {
    MyVType2() noexcept {}
    virtual ~MyVType2() noexcept {}
    UPX_CXX_DISABLE_COPY_MOVE(MyVType2)
    typedef MyVType2<TA, TB, TC> Self;
    UPX_CXX_DISABLE_ADDRESS(Self)
    UPX_CXX_DISABLE_NEW_DELETE(Self)
};
TEST_CASE("UPX_CXX_DISABLE_xxx") {
    MyType1<char, int, 1> dummy1;
    MyType2<char, int, 2> dummy2;
    MyVType1<char, int, 1> vdummy1;
    MyVType2<char, int, 2> vdummy2;
    (void) dummy1;
    (void) dummy2;
    (void) vdummy1;
    (void) vdummy2;
}
} // namespace

namespace test_disable_new_delete {

struct A1 {
    int a;
};
struct A2 {
    int a;
    UPX_CXX_DISABLE_NEW_DELETE_NO_VIRTUAL(A2)
};
struct B1_A1 : public A1 {
    int b;
};
struct B1_A2 : public A2 {
    int b;
};
struct B2_A1 : public A1 {
    int b;
    UPX_CXX_DISABLE_NEW_DELETE_NO_VIRTUAL(B2_A1)
};
struct B2_A2 : public A2 {
    int b;
    UPX_CXX_DISABLE_NEW_DELETE_NO_VIRTUAL(B2_A2)
};

struct X1 {
    virtual ~X1() noexcept {}
    int x;
};
struct X2 {
    virtual ~X2() noexcept {}
    int x;
    UPX_CXX_DISABLE_NEW_DELETE(X2)
};
struct Y1_X1 : public X1 {
    int y;
};
struct Y1_X2 : public X2 {
    int y;
};
struct Y2_X1 : public X1 {
    int y;
    UPX_CXX_DISABLE_NEW_DELETE(Y2_X1)
};
struct Y2_X2 : public X2 {
    int y;
    UPX_CXX_DISABLE_NEW_DELETE(Y2_X2)
};
struct Z1_X1 : public X1 {
    virtual ~Z1_X1() noexcept {}
    int z;
};
struct Z1_X2 : public X2 {
    virtual ~Z1_X2() noexcept {}
    int z;
};
struct Z2_X1 : public X1 {
    virtual ~Z2_X1() noexcept {}
    int z;
    UPX_CXX_DISABLE_NEW_DELETE(Z2_X1)
};
struct Z2_X2 : public X2 {
    virtual ~Z2_X2() noexcept {}
    int z;
    UPX_CXX_DISABLE_NEW_DELETE(Z2_X2)
};

} // namespace test_disable_new_delete

TEST_CASE("upx::noncopyable") {
    struct Test : private upx::noncopyable {
        int v = 1;
    };
    Test t = {};
    CHECK(t.v == 1);
#if (ACC_CC_MSC) // MSVC thinks that Test is not std::is_trivially_copyable; true or compiler bug?
    // @COMPILER_BUG @MSVC_BUG
    t.v = 0;
#else
    mem_clear(&t);
#endif
    CHECK(t.v == 0);
    constexpr Test x = {};
    static_assert(x.v == 1);
}

/*************************************************************************
// <type_traits>
**************************************************************************/

static_assert(!upx::is_bounded_array_v<std::nullptr_t>);
static_assert(!upx::is_bounded_array_v<decltype(nullptr)>);
static_assert(!upx::is_bounded_array_v<void *>);
static_assert(!upx::is_bounded_array_v<int *>);
static_assert(!upx::is_bounded_array_v<const int *>);
static_assert(!upx::is_bounded_array_v<volatile int *>);
static_assert(!upx::is_bounded_array_v<const volatile int *>);
static_assert(upx::is_bounded_array_v<int[1]>);
static_assert(upx::is_bounded_array_v<const int[1]>);
static_assert(upx::is_bounded_array_v<volatile int[1]>);
static_assert(upx::is_bounded_array_v<const volatile int[1]>);
static_assert(upx::is_bounded_array_v<int[1u]>);
static_assert(upx::is_bounded_array_v<const int[1u]>);
static_assert(upx::is_bounded_array_v<volatile int[1u]>);
static_assert(upx::is_bounded_array_v<const volatile int[1u]>);
static_assert(upx::is_bounded_array_v<int[1l]>);
static_assert(upx::is_bounded_array_v<const int[1l]>);
static_assert(upx::is_bounded_array_v<volatile int[1l]>);
static_assert(upx::is_bounded_array_v<const volatile int[1l]>);

static_assert(upx::is_same_all_v<int>);
static_assert(upx::is_same_all_v<int, int>);
static_assert(upx::is_same_all_v<int, int, int>);
static_assert(!upx::is_same_all_v<int, char>);
static_assert(!upx::is_same_all_v<int, char, int>);
static_assert(!upx::is_same_all_v<int, int, char>);

static_assert(!upx::is_same_any_v<int>);
static_assert(upx::is_same_any_v<int, int>);
static_assert(upx::is_same_any_v<int, char, int>);
static_assert(upx::is_same_any_v<int, int, char>);
static_assert(!upx::is_same_any_v<int, char>);
static_assert(!upx::is_same_any_v<int, char, char>);
static_assert(!upx::is_same_any_v<int, char, long>);

static_assert(upx::is_same_any_v<ptrdiff_t, int, long, long long>);
static_assert(upx::is_same_any_v<size_t, unsigned, unsigned long, unsigned long long>);
static_assert(upx::is_same_any_v<upx_ptraddr_t, unsigned, unsigned long, unsigned long long>);
#if defined(__CHERI__) && defined(__CHERI_PURE_CAPABILITY__)
static_assert(!upx::is_same_any_v<upx_uintptr_t, unsigned, unsigned long, unsigned long long>);
#else
static_assert(upx::is_same_any_v<upx_uintptr_t, unsigned, unsigned long, unsigned long long>);
#endif

static_assert(std::is_same_v<int, upx::remove_cvref_t<int> >);
static_assert(std::is_same_v<int, upx::remove_cvref_t<const int> >);
static_assert(std::is_same_v<int, upx::remove_cvref_t<int &> >);
static_assert(std::is_same_v<int, upx::remove_cvref_t<const int &> >);
static_assert(std::is_same_v<int, upx::remove_cvref_t<int &&> >);
static_assert(std::is_same_v<int, upx::remove_cvref_t<const int &&> >);
static_assert(std::is_same_v<int *, upx::remove_cvref_t<int *> >);
static_assert(std::is_same_v<int *, upx::remove_cvref_t<int *const> >);
static_assert(std::is_same_v<const int *, upx::remove_cvref_t<const int *> >);
static_assert(std::is_same_v<int *, upx::remove_cvref_t<int *&> >);
static_assert(std::is_same_v<int *, upx::remove_cvref_t<int *const &> >);
static_assert(std::is_same_v<const int *, upx::remove_cvref_t<const int *&> >);
static_assert(std::is_same_v<int *, upx::remove_cvref_t<int *&&> >);
static_assert(std::is_same_v<int *, upx::remove_cvref_t<int *const &&> >);
static_assert(std::is_same_v<const int *, upx::remove_cvref_t<const int *&&> >);
static_assert(std::is_same_v<int[1], upx::remove_cvref_t<int[1]> >);
static_assert(std::is_same_v<int[1], upx::remove_cvref_t<const int[1]> >);

static_assert(std::is_same_v<int, upx::type_identity_t<int> >);
static_assert(std::is_same_v<const int, upx::type_identity_t<const int> >);
static_assert(std::is_same_v<int *, upx::type_identity_t<int *> >);
static_assert(std::is_same_v<int *const, upx::type_identity_t<int *const> >);
static_assert(std::is_same_v<const int *, upx::type_identity_t<const int *> >);
static_assert(std::is_same_v<int &, upx::type_identity_t<int &> >);
static_assert(std::is_same_v<const int &, upx::type_identity_t<const int &> >);
static_assert(std::is_same_v<int &&, upx::type_identity_t<int &&> >);
static_assert(std::is_same_v<const int &&, upx::type_identity_t<const int &&> >);
static_assert(std::is_same_v<int[1], upx::type_identity_t<int[1]> >);
static_assert(std::is_same_v<const int[1], upx::type_identity_t<const int[1]> >);

/*************************************************************************
// <bit>
**************************************************************************/

static_assert(!upx::has_single_bit(0));
static_assert(upx::has_single_bit(1));
static_assert(upx::has_single_bit(2));
static_assert(!upx::has_single_bit(3));
static_assert(upx::has_single_bit(4));

/*************************************************************************
// <algorithm>
**************************************************************************/

static_assert(upx::align_down(0, 4) == 0);
static_assert(upx::align_down(1, 4) == 0);
static_assert(upx::align_down(2, 4) == 0);
static_assert(upx::align_down(3, 4) == 0);
static_assert(upx::align_down(4, 4) == 4);
static_assert(upx::align_up(0, 4) == 0);
static_assert(upx::align_up(1, 4) == 4);
static_assert(upx::align_up(2, 4) == 4);
static_assert(upx::align_up(3, 4) == 4);
static_assert(upx::align_up(4, 4) == 4);
static_assert(upx::align_up_gap(0, 4) == 0);
static_assert(upx::align_up_gap(1, 4) == 3);
static_assert(upx::align_up_gap(2, 4) == 2);
static_assert(upx::align_up_gap(3, 4) == 1);
static_assert(upx::align_up_gap(4, 4) == 0);

static_assert(upx::min<upx_int8_t>(1, 2) == 1);
static_assert(upx::min<upx_int16_t>(1, 2) == 1);
static_assert(upx::min<upx_int32_t>(1, 2) == 1);
static_assert(upx::min<upx_int64_t>(1, 2) == 1);
static_assert(upx::min<intmax_t>(1, 2) == 1);
static_assert(upx::max<upx_int8_t>(1, 2) == 2);
static_assert(upx::max<upx_int16_t>(1, 2) == 2);
static_assert(upx::max<upx_int32_t>(1, 2) == 2);
static_assert(upx::max<upx_int64_t>(1, 2) == 2);
static_assert(upx::max<intmax_t>(1, 2) == 2);

static_assert(upx::min(1, 2) == 1);
static_assert(upx::min(1l, 2l) == 1);
static_assert(upx::min(1ll, 2ll) == 1);
static_assert(upx::max(1, 2) == 2);
static_assert(upx::max(1l, 2l) == 2);
static_assert(upx::max(1ll, 2ll) == 2);

static_assert(upx::umin<upx_uint8_t>(1, 2) == 1);
static_assert(upx::umin<upx_uint16_t>(1, 2) == 1);
static_assert(upx::umin<upx_uint32_t>(1, 2) == 1);
static_assert(upx::umin<upx_uint64_t>(1, 2) == 1);
static_assert(upx::umin<uintmax_t>(1, 2) == 1);
static_assert(upx::umax<upx_uint8_t>(1, 2) == 2);
static_assert(upx::umax<upx_uint16_t>(1, 2) == 2);
static_assert(upx::umax<upx_uint32_t>(1, 2) == 2);
static_assert(upx::umax<upx_uint64_t>(1, 2) == 2);
static_assert(upx::umax<uintmax_t>(1, 2) == 2);

static_assert(upx::umin(1u, 2u) == 1);
static_assert(upx::umin(1ul, 2ul) == 1);
static_assert(upx::umin(1ull, 2ull) == 1);
static_assert(upx::umax(1u, 2u) == 2);
static_assert(upx::umax(1ul, 2ul) == 2);
static_assert(upx::umax(1ull, 2ull) == 2);

static_assert(upx::wrapping_add<upx_int8_t>(127, 2) == -127);
static_assert(upx::wrapping_add<upx_int16_t>(32767, 2) == -32767);
static_assert(upx::wrapping_add(2147483647, 2) == -2147483647);
static_assert(upx::wrapping_add(9223372036854775807ll, 2ll) == -9223372036854775807ll);
static_assert(upx::wrapping_sub<upx_int8_t>(-127, 2) == 127);
static_assert(upx::wrapping_sub<upx_int16_t>(-32767, 2) == 32767);
static_assert(upx::wrapping_sub(-2147483647, 2) == 2147483647);
static_assert(upx::wrapping_sub(-9223372036854775807ll, 2ll) == 9223372036854775807ll);

static_assert(upx::wrapping_add<upx_uint8_t>(255, 2) == 1);
static_assert(upx::wrapping_sub<upx_uint8_t>(1, 2) == 255);

/*************************************************************************
// util
**************************************************************************/

// upx::UnsignedSizeOf
static_assert(usizeof(int) == sizeof(int));
static_assert(usizeof('a') == sizeof(char));
static_assert(usizeof("") == 1);
static_assert(usizeof("a") == 2);
static_assert(usizeof("ab") == 3);
static_assert(usizeof(L'a') == sizeof(wchar_t));
static_assert(usizeof(L"") == 1 * sizeof(wchar_t));
static_assert(usizeof(L"a") == 2 * sizeof(wchar_t));
static_assert(usizeof(L"ab") == 3 * sizeof(wchar_t));
static_assert(usizeof(0) == sizeof(int));
static_assert(usizeof(0L) == sizeof(long));
static_assert(usizeof(0LL) == sizeof(long long));
static_assert(usizeof(nullptr) == sizeof(void *));
static_assert(usizeof(sizeof(0)) == sizeof(size_t));
static_assert(usizeof(usizeof(0)) == sizeof(unsigned));
#if 0
// works, but may trigger clang/gcc warnings "-Wunused-value"
static_assert(usizeof((1LL, 1)) == sizeof(int));
static_assert(usizeof((1, 1LL)) == sizeof(long long));
#endif

TEST_CASE("upx::ptr_static_cast") {
    // check that we do not trigger any -Wcast-align warnings
    using upx::ptr_static_cast;

    void *vp = nullptr;
    byte *bp = nullptr;
    int *ip = nullptr;
    double *dp = nullptr;

    assert((vp == ptr_static_cast<void *>(vp)));
    assert((vp == ptr_static_cast<void *>(bp)));
    assert((vp == ptr_static_cast<void *>(ip)));
    assert((vp == ptr_static_cast<void *>(dp)));

    assert((bp == ptr_static_cast<byte *>(vp)));
    assert((bp == ptr_static_cast<byte *>(bp)));
    assert((bp == ptr_static_cast<byte *>(ip)));
    assert((bp == ptr_static_cast<byte *>(dp)));

    assert((ip == ptr_static_cast<int *>(vp)));
    assert((ip == ptr_static_cast<int *>(bp)));
    assert((ip == ptr_static_cast<int *>(ip)));
    assert((ip == ptr_static_cast<int *>(dp)));

    assert((dp == ptr_static_cast<double *>(vp)));
    assert((dp == ptr_static_cast<double *>(bp)));
    assert((dp == ptr_static_cast<double *>(ip)));
    assert((dp == ptr_static_cast<double *>(dp)));

    const byte *bc = nullptr;
    const int *ic = nullptr;
    assert((bc == ptr_static_cast<byte *>(bp)));
    assert((bc == ptr_static_cast<const byte *>(bc)));
    assert((bc == ptr_static_cast<byte *>(ip)));
    assert((bc == ptr_static_cast<const byte *>(ic)));
    assert((ic == ptr_static_cast<int *>(bp)));
    assert((ic == ptr_static_cast<const int *>(bc)));
    assert((ic == ptr_static_cast<int *>(ip)));
    assert((ic == ptr_static_cast<const int *>(ic)));
}

TEST_CASE("upx::ptr_static_cast constexpr 1") {
    // check that casts work at compile-time
    using upx::ptr_static_cast;

    constexpr void *vp = nullptr;
    constexpr byte *bp = nullptr;
    constexpr int *ip = nullptr;
    constexpr double *dp = nullptr;
    static_assert((vp == ptr_static_cast<void *>(vp)));
    static_assert((bp == ptr_static_cast<byte *>(bp)));
    static_assert((ip == ptr_static_cast<int *>(ip)));
    static_assert((dp == ptr_static_cast<double *>(dp)));

    constexpr const void *vc = nullptr;
    constexpr const byte *bc = nullptr;
    constexpr const int *ic = nullptr;
    constexpr const double *dc = nullptr;
    static_assert((vc == ptr_static_cast<const void *>(vc)));
    static_assert((bc == ptr_static_cast<const byte *>(bc)));
    static_assert((ic == ptr_static_cast<const int *>(ic)));
    static_assert((dc == ptr_static_cast<const double *>(dc)));

    constexpr void **vpp = nullptr;
    constexpr byte **bpp = nullptr;
    constexpr int **ipp = nullptr;
    constexpr double **dpp = nullptr;
    static_assert((vpp == ptr_static_cast<void **>(vpp)));
    static_assert((bpp == ptr_static_cast<byte **>(bpp)));
    static_assert((ipp == ptr_static_cast<int **>(ipp)));
    static_assert((dpp == ptr_static_cast<double **>(dpp)));

    constexpr const void **vcp = nullptr;
    constexpr const byte **bcp = nullptr;
    constexpr const int **icp = nullptr;
    constexpr const double **dcp = nullptr;
    static_assert((vcp == ptr_static_cast<const void **>(vcp)));
    static_assert((bcp == ptr_static_cast<const byte **>(bcp)));
    static_assert((icp == ptr_static_cast<const int **>(icp)));
    static_assert((dcp == ptr_static_cast<const double **>(dcp)));

    constexpr void *const *vpc = nullptr;
    constexpr byte *const *bpc = nullptr;
    constexpr int *const *ipc = nullptr;
    constexpr double *const *dpc = nullptr;
    static_assert((vpc == ptr_static_cast<void *const *>(vpc)));
    static_assert((bpc == ptr_static_cast<byte *const *>(bpc)));
    static_assert((ipc == ptr_static_cast<int *const *>(ipc)));
    static_assert((dpc == ptr_static_cast<double *const *>(dpc)));

    constexpr const void *const *vcc = nullptr;
    constexpr const byte *const *bcc = nullptr;
    constexpr const int *const *icc = nullptr;
    constexpr const double *const *dcc = nullptr;
    static_assert((vcc == ptr_static_cast<const void *const *>(vcc)));
    static_assert((bcc == ptr_static_cast<const byte *const *>(bcc)));
    static_assert((icc == ptr_static_cast<const int *const *>(icc)));
    static_assert((dcc == ptr_static_cast<const double *const *>(dcc)));
}

TEST_CASE("upx::ptr_static_cast constexpr 2") {
    // check that casts work at compile-time
    using upx::ptr_static_cast;

    constexpr void *vp = nullptr;
    constexpr byte *bp = nullptr;
    constexpr int *ip = nullptr;
    constexpr double *dp = nullptr;
    static_assert((vp == static_cast<void *>(vp)));
    static_assert((vp == static_cast<void *>(bp)));
    static_assert((vp == static_cast<void *>(ip)));
    static_assert((vp == static_cast<void *>(dp)));
    static_assert((vp == ptr_static_cast<void *>(vp)));
    static_assert((vp == ptr_static_cast<void *>(bp)));
    static_assert((vp == ptr_static_cast<void *>(ip)));
    static_assert((vp == ptr_static_cast<void *>(dp)));

    constexpr const void *vc = nullptr;
    constexpr const byte *bc = nullptr;
    constexpr const int *ic = nullptr;
    constexpr const double *dc = nullptr;
    static_assert((vc == static_cast<const void *>(vp)));
    static_assert((vc == static_cast<const void *>(bp)));
    static_assert((vc == static_cast<const void *>(ip)));
    static_assert((vc == static_cast<const void *>(dp)));
    static_assert((vc == ptr_static_cast<const void *>(vp)));
    static_assert((vc == ptr_static_cast<const void *>(dp)));
    static_assert((vc == ptr_static_cast<const void *>(bp)));
    static_assert((vc == ptr_static_cast<const void *>(ip)));
    static_assert((vc == static_cast<const void *>(vc)));
    static_assert((vc == static_cast<const void *>(bc)));
    static_assert((vc == static_cast<const void *>(ic)));
    static_assert((vc == static_cast<const void *>(dc)));
    static_assert((vc == ptr_static_cast<const void *>(vc)));
    static_assert((vc == ptr_static_cast<const void *>(dc)));
    static_assert((vc == ptr_static_cast<const void *>(bc)));
    static_assert((vc == ptr_static_cast<const void *>(ic)));

    // these are invalid:
    //// constexpr char *cc1 = static_cast<char *>(bp);
    //// constexpr char *cc2 = ptr_static_cast<char *>(bp);
    //// constexpr unsigned *uc1 = static_cast<unsigned *>(ip);
    //// constexpr unsigned *uc2 = ptr_static_cast<unsigned *>(ip);
}

#if WITH_THREADS
TEST_CASE("upx::ptr_std_atomic_cast") {
    // pointer-size
    CHECK_EQ(upx::ptr_std_atomic_cast((void **) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((uintptr_t *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((upx_uintptr_t *) nullptr), nullptr);
#if 1
    // more fundamental types
    CHECK_EQ(upx::ptr_std_atomic_cast((char *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((short *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((int *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((long *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((ptrdiff_t *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((size_t *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((upx_int8_t *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((upx_int16_t *) nullptr), nullptr);
    CHECK_EQ(upx::ptr_std_atomic_cast((upx_int32_t *) nullptr), nullptr);
#endif
}
#endif // WITH_THREADS

TEST_CASE("upx::atomic_exchange") {
    {
        upx_uintptr_t x = (upx_uintptr_t) 0 - 1;
        upx_uintptr_t y = upx::atomic_exchange(&x, (upx_uintptr_t) 2);
        CHECK_EQ(x, 2);
        CHECK_EQ(y, (upx_uintptr_t) 0 - 1);
        UNUSED(y);
    }
    {
        const int buf[2] = {101, 202};
        const int *ptr_array[2] = {&buf[0], &buf[1]};
        assert_noexcept(*ptr_array[0] == 101 && *ptr_array[1] == 202);
        const int *p = upx::atomic_exchange(&ptr_array[0], ptr_array[1]);
        CHECK_EQ(p, buf + 0);
        assert_noexcept(*ptr_array[0] == 202 && *ptr_array[1] == 202);
        p = upx::atomic_exchange(&ptr_array[1], p);
        CHECK_EQ(p, buf + 1);
        assert_noexcept(*ptr_array[0] == 202 && *ptr_array[1] == 101);
        UNUSED(p);
    }
}

TEST_CASE("upx::ObjectDeleter 1") {
    LE16 *o = nullptr; // object
    LE32 *a = nullptr; // array
    LE64 *m = nullptr; // malloc
    {
        // auto o_deleter = upx::ObjectDeleter(&o, 1);
        upx::ObjectDeleter<LE16> o_deleter = upx::ObjectDeleter(&o, 1);
        o = new LE16;
        assert(o != nullptr);
        auto a_deleter = upx::ArrayDeleter(&a, 1);
        a = New(LE32, 1);
        assert(a != nullptr);
        auto m_deleter = upx::MallocDeleter(&m, 1);
        m = (LE64 *) ::malloc(sizeof(LE64));
        assert(m != nullptr);
    }
    assert(o == nullptr);
    assert(a == nullptr);
    assert(m == nullptr);
    // test "const" versions
    {
        const auto o_deleter = upx::ObjectDeleter(&o, 1);
        o = new LE16;
        assert(o != nullptr);
        const auto a_deleter = upx::ArrayDeleter(&a, 1);
        a = New(LE32, 1);
        assert(a != nullptr);
        const auto m_deleter = upx::MallocDeleter(&m, 1);
        m = (LE64 *) ::malloc(sizeof(LE64));
        assert(m != nullptr);
    }
    assert(o == nullptr);
    assert(a == nullptr);
    assert(m == nullptr);
}

TEST_CASE("upx::ObjectDeleter 2") {
    constexpr size_t N = 2;
    BE16 *o[N]; // multiple objects
    BE32 *a[N]; // multiple arrays
    BE64 *m[N]; // multiple mallocs
    {
        // auto o_deleter = upx::ObjectDeleter(o, 0);
        upx::ObjectDeleter<BE16> o_deleter = upx::ObjectDeleter(o, 0);
        auto a_deleter = upx::ArrayDeleter(a, 0);
        auto m_deleter = upx::MallocDeleter(m, 0);
        for (size_t i = 0; i < N; i++) {
            o[i] = new BE16;
            assert(o[i] != nullptr);
            o_deleter.count += 1;
            a[i] = New(BE32, 1 + i);
            assert(a[i] != nullptr);
            a_deleter.count += 1;
            m[i] = (BE64 *) ::malloc(sizeof(BE64));
            assert(m[i] != nullptr);
            m_deleter.count += 1;
        }
    }
    for (size_t i = 0; i < N; i++) {
        assert(o[i] == nullptr);
        assert(a[i] == nullptr);
        assert(m[i] == nullptr);
    }
}

/*************************************************************************
// namespace upx::compile_time
**************************************************************************/

static_assert(upx::compile_time::string_len("") == 0);
static_assert(upx::compile_time::string_len("a") == 1);
static_assert(upx::compile_time::string_len("ab") == 2);
static_assert(upx::compile_time::string_len("abc") == 3);

static_assert(upx::compile_time::string_eq("", ""));
static_assert(!upx::compile_time::string_eq("a", ""));
static_assert(!upx::compile_time::string_eq("", "a"));
static_assert(upx::compile_time::string_eq("abc", "abc"));
static_assert(!upx::compile_time::string_eq("ab", "abc"));
static_assert(!upx::compile_time::string_eq("abc", "ab"));

static_assert(!upx::compile_time::string_lt("", ""));
static_assert(!upx::compile_time::string_lt("a", ""));
static_assert(upx::compile_time::string_lt("", "a"));
static_assert(!upx::compile_time::string_lt("abc", "abc"));
static_assert(upx::compile_time::string_lt("ab", "abc"));
static_assert(!upx::compile_time::string_lt("abc", "ab"));
static_assert(!upx::compile_time::string_lt("abc", "aba"));
static_assert(upx::compile_time::string_lt("abc", "abz"));

static_assert(upx::compile_time::string_ne("abc", "abz"));
static_assert(!upx::compile_time::string_gt("abc", "abz"));
static_assert(!upx::compile_time::string_ge("abc", "abz"));
static_assert(upx::compile_time::string_le("abc", "abz"));

static_assert(upx::compile_time::mem_eq((const char *) nullptr, (const char *) nullptr, 0));
static_assert(upx::compile_time::mem_eq((const char *) nullptr, (const byte *) nullptr, 0));
static_assert(upx::compile_time::mem_eq((const byte *) nullptr, (const char *) nullptr, 0));
static_assert(upx::compile_time::mem_eq((const byte *) nullptr, (const byte *) nullptr, 0));
static_assert(upx::compile_time::mem_eq("", "", 0));
static_assert(upx::compile_time::mem_eq("abc", "abc", 3));
static_assert(!upx::compile_time::mem_eq("abc", "abz", 3));

static_assert(upx::compile_time::bswap16(0x0102) == 0x0201);
static_assert(upx::compile_time::bswap32(0x01020304) == 0x04030201);
static_assert(upx::compile_time::bswap64(0x0102030405060708ull) == 0x0807060504030201ull);

namespace {
struct alignas(1) TestCT final {
    byte d[8]; // public data

    static constexpr TestCT makeBE16(upx_uint16_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_be16(x.d, v);
        return x;
    }
    static constexpr TestCT makeBE24(upx_uint32_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_be24(x.d, v);
        return x;
    }
    static constexpr TestCT makeBE32(upx_uint32_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_be32(x.d, v);
        return x;
    }
    static constexpr TestCT makeBE64(upx_uint64_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_be64(x.d, v);
        return x;
    }
    static constexpr TestCT makeLE16(upx_uint16_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_le16(x.d, v);
        return x;
    }
    static constexpr TestCT makeLE24(upx_uint32_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_le24(x.d, v);
        return x;
    }
    static constexpr TestCT makeLE32(upx_uint32_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_le32(x.d, v);
        return x;
    }
    static constexpr TestCT makeLE64(upx_uint64_t v) noexcept {
        TestCT x = {};
        upx::compile_time::set_le64(x.d, v);
        return x;
    }

    // run-time
    static noinline upx_uint16_t noinline_bswap16(upx_uint16_t v) noexcept {
        return upx::compile_time::bswap16(v);
    }
    static noinline upx_uint32_t noinline_bswap32(upx_uint32_t v) noexcept {
        return upx::compile_time::bswap32(v);
    }
    static noinline upx_uint64_t noinline_bswap64(upx_uint64_t v) noexcept {
        return upx::compile_time::bswap64(v);
    }

    static noinline upx_uint16_t noinline_get_be16(const byte *p) noexcept {
        return upx::compile_time::get_be16(p);
    }
    static noinline upx_uint32_t noinline_get_be24(const byte *p) noexcept {
        return upx::compile_time::get_be24(p);
    }
    static noinline upx_uint32_t noinline_get_be32(const byte *p) noexcept {
        return upx::compile_time::get_be32(p);
    }
    static noinline upx_uint64_t noinline_get_be64(const byte *p) noexcept {
        return upx::compile_time::get_be64(p);
    }
    static noinline upx_uint16_t noinline_get_le16(const byte *p) noexcept {
        return upx::compile_time::get_le16(p);
    }
    static noinline upx_uint32_t noinline_get_le24(const byte *p) noexcept {
        return upx::compile_time::get_le24(p);
    }
    static noinline upx_uint32_t noinline_get_le32(const byte *p) noexcept {
        return upx::compile_time::get_le32(p);
    }
    static noinline upx_uint64_t noinline_get_le64(const byte *p) noexcept {
        return upx::compile_time::get_le64(p);
    }

    static noinline void noinline_set_be16(byte * p, upx_uint16_t v) noexcept {
        upx::compile_time::set_be16(p, v);
    }
    static noinline void noinline_set_be24(byte * p, upx_uint32_t v) noexcept {
        upx::compile_time::set_be24(p, v);
    }
    static noinline void noinline_set_be32(byte * p, upx_uint32_t v) noexcept {
        upx::compile_time::set_be32(p, v);
    }
    static noinline void noinline_set_be64(byte * p, upx_uint64_t v) noexcept {
        upx::compile_time::set_be64(p, v);
    }
    static noinline void noinline_set_le16(byte * p, upx_uint16_t v) noexcept {
        upx::compile_time::set_le16(p, v);
    }
    static noinline void noinline_set_le24(byte * p, upx_uint32_t v) noexcept {
        upx::compile_time::set_le24(p, v);
    }
    static noinline void noinline_set_le32(byte * p, upx_uint32_t v) noexcept {
        upx::compile_time::set_le32(p, v);
    }
    static noinline void noinline_set_le64(byte * p, upx_uint64_t v) noexcept {
        upx::compile_time::set_le64(p, v);
    }
};
static_assert(sizeof(TestCT) == 8);
static_assert(alignof(TestCT) == 1);
} // namespace

TEST_CASE("upx::compile_time 1") {
    constexpr upx_uint16_t v16 = 0x0201;
    constexpr upx_uint32_t v24 = 0x030201;
    constexpr upx_uint32_t v32 = 0x04030201;
    constexpr upx_uint64_t v64 = 0x0807060504030201ull;
    {
        static_assert(upx::compile_time::bswap16(v16) == 0x0102);
        static_assert(upx::compile_time::bswap32(v32) == 0x01020304);
        static_assert(upx::compile_time::bswap64(v64) == 0x0102030405060708ull);
        assert_noexcept(TestCT::noinline_bswap16(v16) == 0x0102);
        assert_noexcept(TestCT::noinline_bswap32(v32) == 0x01020304);
        assert_noexcept(TestCT::noinline_bswap64(v64) == 0x0102030405060708ull);
    }
    {
        constexpr const byte d[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        static_assert(upx::compile_time::get_be16(d) == 0x0102);
        static_assert(upx::compile_time::get_be24(d) == 0x010203);
        static_assert(upx::compile_time::get_be32(d) == 0x01020304);
        static_assert(upx::compile_time::get_be64(d) == 0x0102030405060708ull);
        static_assert(upx::compile_time::get_le16(d) == 0x0201);
        static_assert(upx::compile_time::get_le24(d) == 0x030201);
        static_assert(upx::compile_time::get_le32(d) == 0x04030201);
        static_assert(upx::compile_time::get_le64(d) == 0x0807060504030201ull);
    }
    {
        using upx::compile_time::mem_eq;
        upx_alignas_max byte aligned_buffer[16] = {};
        upx::compile_time::mem_set(aligned_buffer, 0xff, 16);
        assert_noexcept(mem_eq(aligned_buffer, aligned_buffer + 8, 8));
        byte *const buf = aligned_buffer + 7;

        constexpr auto be16 = TestCT::makeBE16(v16);
        static_assert(upx::compile_time::get_be16(be16.d) == v16);
        static_assert(mem_eq(be16.d, "\x02\x01", 2));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_be16(buf, v16);
        assert_noexcept(TestCT::noinline_get_be16(buf) == v16);
        assert_noexcept(upx::compile_time::get_be16(buf) == v16);
        assert_noexcept(memcmp(buf, be16.d, 8) == 0);

        constexpr auto be24 = TestCT::makeBE24(v24);
        static_assert(upx::compile_time::get_be24(be24.d) == v24);
        static_assert(mem_eq(be24.d, "\x03\x02\x01", 3));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_be24(buf, v24);
        assert_noexcept(TestCT::noinline_get_be24(buf) == v24);
        assert_noexcept(upx::compile_time::get_be24(buf) == v24);
        assert_noexcept(memcmp(buf, be24.d, 8) == 0);

        constexpr auto be32 = TestCT::makeBE32(v32);
        static_assert(upx::compile_time::get_be32(be32.d) == v32);
        static_assert(mem_eq(be32.d, "\x04\x03\x02\x01", 4));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_be32(buf, v32);
        assert_noexcept(TestCT::noinline_get_be32(buf) == v32);
        assert_noexcept(upx::compile_time::get_be32(buf) == v32);
        assert_noexcept(memcmp(buf, be32.d, 8) == 0);

        constexpr auto be64 = TestCT::makeBE64(v64);
        static_assert(upx::compile_time::get_be64(be64.d) == v64);
        static_assert(mem_eq(be64.d, "\x08\x07\x06\x05\x04\x03\x02\x01", 8));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_be64(buf, v64);
        assert_noexcept(TestCT::noinline_get_be64(buf) == v64);
        assert_noexcept(upx::compile_time::get_be64(buf) == v64);
        assert_noexcept(memcmp(buf, be64.d, 8) == 0);

        constexpr auto le16 = TestCT::makeLE16(v16);
        static_assert(upx::compile_time::get_le16(le16.d) == v16);
        static_assert(mem_eq(le16.d, "\x01\x02", 2));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_le16(buf, v16);
        assert_noexcept(TestCT::noinline_get_le16(buf) == v16);
        assert_noexcept(upx::compile_time::get_le16(buf) == v16);
        assert_noexcept(memcmp(buf, le16.d, 8) == 0);

        constexpr auto le24 = TestCT::makeLE24(v24);
        static_assert(upx::compile_time::get_le24(le24.d) == v24);
        static_assert(mem_eq(le24.d, "\x01\x02\x03", 3));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_le24(buf, v24);
        assert_noexcept(TestCT::noinline_get_le24(buf) == v24);
        assert_noexcept(upx::compile_time::get_le24(buf) == v24);
        assert_noexcept(memcmp(buf, le24.d, 8) == 0);

        constexpr auto le32 = TestCT::makeLE32(v32);
        static_assert(upx::compile_time::get_le32(le32.d) == v32);
        static_assert(mem_eq(le32.d, "\x01\x02\x03\x04", 4));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_le32(buf, v32);
        assert_noexcept(TestCT::noinline_get_le32(buf) == v32);
        assert_noexcept(upx::compile_time::get_le32(buf) == v32);
        assert_noexcept(memcmp(buf, le32.d, 8) == 0);

        constexpr auto le64 = TestCT::makeLE64(v64);
        static_assert(upx::compile_time::get_le64(le64.d) == v64);
        static_assert(mem_eq(le64.d, "\x01\x02\x03\x04\x05\x06\x07\x08", 8));
        upx::compile_time::mem_clear(buf, 8);
        TestCT::noinline_set_le64(buf, v64);
        assert_noexcept(TestCT::noinline_get_le64(buf) == v64);
        assert_noexcept(upx::compile_time::get_le64(buf) == v64);
        assert_noexcept(memcmp(buf, le64.d, 8) == 0);

        static_assert(upx::compile_time::bswap16(upx::compile_time::get_be16(be16.d)) ==
                      upx::compile_time::get_be16(le16.d));
        static_assert(upx::compile_time::bswap32(upx::compile_time::get_be32(be32.d)) ==
                      upx::compile_time::get_be32(le32.d));
        static_assert(upx::compile_time::bswap64(upx::compile_time::get_be64(be64.d)) ==
                      upx::compile_time::get_be64(le64.d));
        assert_noexcept(TestCT::noinline_bswap16(TestCT::noinline_get_be16(be16.d)) ==
                        TestCT::noinline_get_be16(le16.d));
        assert_noexcept(TestCT::noinline_bswap32(TestCT::noinline_get_be32(be32.d)) ==
                        TestCT::noinline_get_be32(le32.d));
        assert_noexcept(TestCT::noinline_bswap64(TestCT::noinline_get_be64(be64.d)) ==
                        TestCT::noinline_get_be64(le64.d));
    }
}

TEST_CASE("upx::compile_time 2") {
    constexpr upx_uint16_t v16 = 0xf2f1;
    constexpr upx_uint32_t v24 = 0xf3f2f1;
    constexpr upx_uint32_t v32 = 0xf4f3f2f1;
    constexpr upx_uint64_t v64 = 0xf8f7f6f5f4f3f2f1ull;
    {
        using upx::compile_time::mem_eq;
        upx_alignas_max byte aligned_buffer[32];
        byte *const buf1 = aligned_buffer + 3;
        byte *const buf2 = aligned_buffer + 13;

        upx::compile_time::set_be16(buf1, v16);
        TestCT::noinline_set_be16(buf2, v16);
        assert_noexcept(TestCT::noinline_get_be16(buf1) == v16);
        assert_noexcept(TestCT::noinline_get_be16(buf2) == v16);
        assert_noexcept(memcmp(buf1, buf2, 2) == 0);
        upx::compile_time::set_be24(buf1, v24);
        TestCT::noinline_set_be24(buf2, v24);
        assert_noexcept(TestCT::noinline_get_be24(buf1) == v24);
        assert_noexcept(TestCT::noinline_get_be24(buf2) == v24);
        assert_noexcept(memcmp(buf1, buf2, 3) == 0);
        upx::compile_time::set_be32(buf1, v32);
        TestCT::noinline_set_be32(buf2, v32);
        assert_noexcept(TestCT::noinline_get_be32(buf1) == v32);
        assert_noexcept(TestCT::noinline_get_be32(buf2) == v32);
        assert_noexcept(memcmp(buf1, buf2, 4) == 0);
        upx::compile_time::set_be64(buf1, v64);
        TestCT::noinline_set_be64(buf2, v64);
        assert_noexcept(TestCT::noinline_get_be64(buf1) == v64);
        assert_noexcept(TestCT::noinline_get_be64(buf2) == v64);
        assert_noexcept(memcmp(buf1, buf2, 8) == 0);

        upx::compile_time::set_le16(buf1, v16);
        TestCT::noinline_set_le16(buf2, v16);
        assert_noexcept(TestCT::noinline_get_le16(buf1) == v16);
        assert_noexcept(TestCT::noinline_get_le16(buf2) == v16);
        assert_noexcept(memcmp(buf1, buf2, 2) == 0);
        upx::compile_time::set_le24(buf1, v24);
        TestCT::noinline_set_le24(buf2, v24);
        assert_noexcept(TestCT::noinline_get_le24(buf1) == v24);
        assert_noexcept(TestCT::noinline_get_le24(buf2) == v24);
        assert_noexcept(memcmp(buf1, buf2, 3) == 0);
        upx::compile_time::set_le32(buf1, v32);
        TestCT::noinline_set_le32(buf2, v32);
        assert_noexcept(TestCT::noinline_get_le32(buf1) == v32);
        assert_noexcept(TestCT::noinline_get_le32(buf2) == v32);
        assert_noexcept(memcmp(buf1, buf2, 4) == 0);
        upx::compile_time::set_le64(buf1, v64);
        TestCT::noinline_set_le64(buf2, v64);
        assert_noexcept(TestCT::noinline_get_le64(buf1) == v64);
        assert_noexcept(TestCT::noinline_get_le64(buf2) == v64);
        assert_noexcept(memcmp(buf1, buf2, 8) == 0);
    }
}

/*************************************************************************
// TriBool
**************************************************************************/

namespace {
template <class T>
struct TestTriBool final {
    static noinline void test(bool expect_true) {
        static_assert(std::is_class<T>::value);
        static_assert(std::is_nothrow_default_constructible<T>::value);
        static_assert(std::is_nothrow_destructible<T>::value);
        static_assert(std::is_standard_layout<T>::value);
        static_assert(std::is_trivially_copyable<T>::value);
        static_assert(sizeof(typename T::value_type) == sizeof(typename T::underlying_type));
        static_assert(alignof(typename T::value_type) == alignof(typename T::underlying_type));
#if defined(__m68k__) && defined(__atarist__) && defined(__GNUC__)
        // broken compiler or broken ABI
#elif defined(__i386__) && defined(__GNUC__) && (__GNUC__ == 7) && !defined(__clang__)
        static_assert(sizeof(T) == sizeof(typename T::underlying_type));
        // i386: "long long" enum align bug/ABI problem on older compilers
        static_assert(alignof(T) <= alignof(typename T::underlying_type));
#else
        static_assert(sizeof(T) == sizeof(typename T::underlying_type));
        static_assert(alignof(T) == alignof(typename T::underlying_type));
#endif
        static_assert(!bool(T(false)));
        static_assert(bool(T(true)));
        static_assert(bool(T(T::Third)) == T::is_third_true);
        static_assert(T(false) == T::False);
        static_assert(T(true) == T::True);
        static_assert(T(T::False) == T::False);
        static_assert(T(T::True) == T::True);
        static_assert(T(T::Third) == T::Third);
        static_assert(T(T::Third) == T(9));
        static_assert(T(8) == T(9));
        static_assert(!(T(0) == T(9)));
        static_assert(!(T(1) == T(9)));
        static_assert(T(T::Third) == 9);
        static_assert(T(8) == 9);
        static_assert(!(T(0) == 9));
        static_assert(!(T(1) == 9));
        constexpr T array[] = {false, true, T::Third};
        static_assert(array[0].isStrictFalse());
        static_assert(array[1].isStrictTrue());
        static_assert(array[2].isThird());
        static_assert(sizeof(array) == 3 * sizeof(T));
        T a;
        assert(a.getValue() == T::False);
        assert(!a);
        assert(!bool(a));
        assert((!a ? true : false));
        assert(a.isStrictFalse());
        assert(!a.isStrictTrue());
        assert(a.isStrictBool());
        assert(!a.isThird());
        a = false;
        assert(a.getValue() == T::False);
        assert(!a);
        assert(!bool(a));
        assert((!a ? true : false));
        assert(a.isStrictFalse());
        assert(!a.isStrictTrue());
        assert(a.isStrictBool());
        assert(!a.isThird());
        a = true;
        assert(a.getValue() == T::True);
        assert(a);
        assert(bool(a));
        assert((a ? true : false));
        assert(!a.isStrictFalse());
        assert(a.isStrictTrue());
        assert(a.isStrictBool());
        assert(!a.isThird());
        a = T::Third;
        assert(a.getValue() == T::Third);
        assert(T::is_third_true == expect_true);
        if (expect_true) {
            assert(a);
            assert(bool(a));
            assert((a ? true : false));
        } else {
            assert(!a);
            assert(!bool(a));
            assert((!a ? true : false));
        }
        assert(!a.isStrictFalse());
        assert(!a.isStrictTrue());
        assert(!a.isStrictBool());
        assert(a.isThird());
        a = 99;
        assert(a.getValue() == T::Third);
        if (expect_true) {
            assert(a);
            assert(bool(a));
            assert((a ? true : false));
            assert((!a ? false : true));
        } else {
            assert(!a);
            assert(!bool(a));
            assert((a ? false : true));
            assert((!a ? true : false));
        }
        assert(!a.isStrictFalse());
        assert(!a.isStrictTrue());
        assert(!a.isStrictBool());
        assert(a.isThird());
        mem_clear(&a);
        assert(a.isStrictFalse());
    }
};
} // namespace

TEST_CASE("upx::TriBool") {
    using upx::TriBool, upx::tribool;
    static_assert(!tribool(false));
    static_assert(tribool(true));
    static_assert(!tribool(tribool::Third));
    TestTriBool<tribool>::test(false);
#if DEBUG || 1
    TestTriBool<TriBool<upx_int8_t> >::test(false);
    TestTriBool<TriBool<upx_uint8_t> >::test(false);
    TestTriBool<TriBool<upx_int16_t> >::test(false);
    TestTriBool<TriBool<upx_uint16_t> >::test(false);
    TestTriBool<TriBool<upx_int32_t> >::test(false);
    TestTriBool<TriBool<upx_uint32_t> >::test(false);
    TestTriBool<TriBool<upx_int64_t> >::test(false);
    TestTriBool<TriBool<upx_uint64_t> >::test(false);
    TestTriBool<TriBool<upx_int8_t, true> >::test(true);
    TestTriBool<TriBool<upx_uint8_t, true> >::test(true);
    TestTriBool<TriBool<upx_int16_t, true> >::test(true);
    TestTriBool<TriBool<upx_uint16_t, true> >::test(true);
    TestTriBool<TriBool<upx_int32_t, true> >::test(true);
    TestTriBool<TriBool<upx_uint32_t, true> >::test(true);
    TestTriBool<TriBool<upx_int64_t, true> >::test(true);
    TestTriBool<TriBool<upx_uint64_t, true> >::test(true);
#endif
}

/* vim:set ts=4 sw=4 et: */
