#pragma once
/**
	@file
	@brief quit signal handler

	@author MITSUNARI Shigeo(@herumi)
*/
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
	#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <signal.h>
#endif
#include <stdio.h>
#include <stdlib.h>

namespace cybozu {

/*
	class App must have quit() method
*/
template<class App>
class QuitSignalHandler {
	static App *app_;
#ifdef _WIN32
	static inline BOOL WINAPI ctrlHandler(DWORD) CYBOZU_NOEXCEPT
	{
		if (app_) app_->quit();
		return TRUE;
	}
#else
	static void ctrlHandler(int) CYBOZU_NOEXCEPT
	{
		app_->quit();
//		signal(SIGINT, SIG_IGN);
	}
#endif
public:
	explicit QuitSignalHandler(App& app)
	{
		app_ = &app;
#ifdef _WIN32
		bool isOK = SetConsoleCtrlHandler(ctrlHandler, TRUE) != 0;
#else
		struct sigaction sa;
		sa.sa_handler = ctrlHandler;
		sigfillset(&sa.sa_mask);
		sa.sa_flags = 0;
		bool isOK = (sigaction(SIGINT, &sa, NULL) == 0)
		         && (sigaction(SIGQUIT, &sa, NULL) == 0)
		         && (sigaction(SIGABRT, &sa, NULL) == 0)
		         && (sigaction(SIGTERM, &sa, NULL) == 0);
#endif
		if (!isOK) {
			fprintf(stderr, "can't setup ctrl handler\n");
			exit(1);
		}
	}
};

template<class App>
App *QuitSignalHandler<App>::app_;

} // cybozu
