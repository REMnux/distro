#include <cybozu/quit_signal_handler.hpp>
#include <cybozu/thread.hpp>
#include <stdio.h>

struct App {
	volatile bool quit_;
	App()
		: quit_(false)
	{
	}
	void quit()
	{
		quit_ = true;
	}
	void run()
	{
		while (!quit_) {
			puts("wait 1sec");
			cybozu::Sleep(1000);
		}
		puts("Ctrl-C is typed!");
	}
};

int main()
{
	App app;
	cybozu::QuitSignalHandler<App> qs(app);
	app.run();
}
