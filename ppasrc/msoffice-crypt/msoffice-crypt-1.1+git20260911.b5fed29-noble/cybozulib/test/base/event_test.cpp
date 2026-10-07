#include <stdio.h>
#include <cybozu/thread.hpp>
#include <cybozu/event.hpp>
#include <cybozu/test.hpp>

class Thread : public cybozu::ThreadBase {
	cybozu::Event& ev_;
public:
	bool done_;
	Thread(cybozu::Event& ev)
		: ev_(ev)
		, done_(false)
	{
	}

	void threadEntry()
	{
		puts("thread");
		puts("sleep 100msec");
		cybozu::Sleep(100);
		puts("wakeup");
		ev_.wakeup();
		cybozu::Sleep(100);
		ev_.wakeup();
	}
};

CYBOZU_TEST_AUTO(event_test)
{
	cybozu::Event ev;

	Thread th(ev);
	th.beginThread();

	ev.wait();
	puts("done");
	ev.wait();
	puts("done");

	th.joinThread();
}
