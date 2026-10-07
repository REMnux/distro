#include <cybozu/test.hpp>
#include <cybozu/thread.hpp>
#include <cybozu/socket.hpp>

CYBOZU_TEST_AUTO(open_move)
{
	cybozu::Socket s;
	CYBOZU_TEST_ASSERT(!s.isValid());
	s.bind(65000);
	CYBOZU_TEST_ASSERT(s.isValid());
#if CYBOZU_CPP_VERSION == CYBOZU_CPP_VERSION_CPP11
	cybozu::Socket t(std::move(s));
#else
	cybozu::Socket t;
	t.moveFrom(s);
#endif
	CYBOZU_TEST_ASSERT(!s.isValid());
	CYBOZU_TEST_ASSERT(t.isValid());
#if CYBOZU_CPP_VERSION == CYBOZU_CPP_VERSION_CPP11
	cybozu::Socket u(std::move(t));
#else
	cybozu::Socket u;
	u.moveFrom(t);
#endif
	CYBOZU_TEST_ASSERT(!t.isValid());
	CYBOZU_TEST_ASSERT(u.isValid());

	cybozu::Socket v;
	CYBOZU_TEST_ASSERT(!v.isValid());
	v.moveFrom(u);
	CYBOZU_TEST_ASSERT(v.isValid());
	CYBOZU_TEST_ASSERT(!u.isValid());
}

CYBOZU_TEST_AUTO(timeout)
{
	cybozu::Socket s;
	s.bind(60000);
	s.setSendTimeout(12000);
	CYBOZU_TEST_EQUAL(s.getSendTimeout(), 12000);
	s.setReceiveTimeout(54000);
	CYBOZU_TEST_EQUAL(s.getReceiveTimeout(), 54000);
}

CYBOZU_TEST_AUTO(compare_SocketAddr)
{
	cybozu::SocketAddr v4("74.125.235.73", 80, false);
	cybozu::SocketAddr v6("74.125.235.73", 81, true);
	cybozu::SocketAddr v4x("74.125.235.72", 82, false);
	cybozu::SocketAddr v6x("2001:db8::1234:ace:6006:1e", 83, true);

	CYBOZU_TEST_ASSERT(v4.hasSameAddr(v4));
	CYBOZU_TEST_ASSERT(v4.hasSameAddr(v6));
	CYBOZU_TEST_ASSERT(!v4.hasSameAddr(v4x));
	CYBOZU_TEST_ASSERT(!v4.hasSameAddr(v6x));

	CYBOZU_TEST_ASSERT(v6.hasSameAddr(v4));
	CYBOZU_TEST_ASSERT(v6.hasSameAddr(v6));
	CYBOZU_TEST_ASSERT(!v6.hasSameAddr(v4x));
	CYBOZU_TEST_ASSERT(!v6.hasSameAddr(v6x));

	CYBOZU_TEST_ASSERT(!v4x.hasSameAddr(v4));
	CYBOZU_TEST_ASSERT(!v4x.hasSameAddr(v6));
	CYBOZU_TEST_ASSERT(v4x.hasSameAddr(v4x));
	CYBOZU_TEST_ASSERT(!v4x.hasSameAddr(v6x));

	CYBOZU_TEST_ASSERT(!v6x.hasSameAddr(v4));
	CYBOZU_TEST_ASSERT(!v6x.hasSameAddr(v6));
	CYBOZU_TEST_ASSERT(!v6x.hasSameAddr(v4x));
	CYBOZU_TEST_ASSERT(v6x.hasSameAddr(v6x));

	CYBOZU_TEST_EQUAL(v4.getPort(), 80);
	CYBOZU_TEST_EQUAL(v6.getPort(), 81);
	CYBOZU_TEST_EQUAL(v4x.getPort(), 82);
	CYBOZU_TEST_EQUAL(v6x.getPort(), 83);
}
