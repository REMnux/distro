#pragma once

/**
    @file
    @brief process class

    @author MITSUNARI Shigeo(@herumi)
    @author MITSUNARI Shigeo
*/
#include <vector>
#include <string>
#include <assert.h>
#include <cybozu/exception.hpp>

#ifdef _WIN32
	#ifndef WIN32_LEAN_AND_MEAN
		#define WIN32_LEAN_AND_MEAN
	#endif
	#include <windows.h>
#else
	#include <unistd.h>
	#include <fcntl.h>
	#include <sys/types.h>
	#include <sys/wait.h>
	#include <stdlib.h>
#endif

namespace cybozu {

namespace process {

#ifdef _WIN32
typedef HANDLE Handle;
const Handle InvalidHandle = (Handle)0;
#else
typedef pid_t Handle;
const Handle InvalidHandle = (Handle)-1;
#endif

#ifndef _WIN32
class Pipe {
	int fd_[2];
public:
	enum Mode {
		Read = 0,
		Write = 1
	};
	Pipe()
	{
		fd_[0] = fd_[1] = -1;
	}
	bool init()
	{
		if (::pipe (fd_) < 0) {
			return false;
		}
		if (::fcntl (fd_[Write], F_SETFD, FD_CLOEXEC) < 0) {
			return false;
		}
		return true;
	}
	void close(Mode mode)
	{
		if (fd_[mode] != -1) {
			::close(fd_[mode]);
			fd_[mode] = -1;
		}
	}
	int write(const char* buf, size_t size)
	{
		return ::write(fd_[Write], buf, size);
	}
	int read(char* buf, size_t size)
	{
		return ::read(fd_[Read], buf, size);
	}
	~Pipe()
	{
		close(Read);
		close(Write);
	}
};

bool toDevNull(int fd, int flags)
{
	int newFd = open("/dev/null", flags);

	if (newFd < 0) return false;

	int ret = dup2(newFd, fd);
	close(newFd);
	return ret >= 0;
}

#endif

inline std::string escape(const std::string& in)
{
	std::string out;
	for (size_t i = 0, n = in.size(); i < n; i++) {
		char c = in[i];
		if (c == '"') {
			out += "\\\"";
		} else {
			out += c;
		}
	}
	return out;
}

/**
	start process and return the handle of it
	argv[0] = exe
*/
static inline bool Start(Handle* hdl, const std::string& exe, const std::vector<std::string>& arg, bool closeStdio = true)
{
#ifdef _WIN32
	cybozu::disable_warning_unused_variable(closeStdio);
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	std::string cmdLine = "\"" + exe + '"';

	for (size_t i = 0, n = arg.size(); i < n; i++) {
		cmdLine += " \"" + escape(arg[i]) + '"';
	}

	cmdLine += '\0';

	if (!CreateProcess(exe.c_str(), &cmdLine[0], NULL, NULL, FALSE
		/* Advanced Windows p.123 */
		, CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP | CREATE_DEFAULT_ERROR_MODE, NULL, 0, &si, &pi)) {
		return false;
	}

	if (pi.hThread) CloseHandle(pi.hThread);

//  if (pi.hProcess) CloseHandle(pi.hProcess);
	*hdl = pi.hProcess;
	return true;
#else
	Pipe pipe;

	if (!pipe.init()) {
		return false;
	}

	pid_t pid = fork();

	if (pid < 0) {
		return false;

	} else if (pid == 0) {
		pipe.close(Pipe::Read);
		std::vector<char*> argv;
		argv.push_back(const_cast<char*>(exe.c_str()));

		for (size_t i = 0, n = arg.size(); i < n; i++) {
			argv.push_back(const_cast<char*>(arg[i].c_str()));
		}

		argv.push_back(0);

		if (closeStdio) {
			if (!toDevNull(0, O_RDONLY)) goto ERR_EXIT;
			if (!toDevNull(1, O_RDWR)) goto ERR_EXIT;
			if (!toDevNull(2, O_RDWR)) goto ERR_EXIT;
		}
		{
			const int ret = static_cast<int>(sysconf(_SC_OPEN_MAX));
			const int maxFd = ret < 0 ? 1024 : maxFd;
			for (int i = 3; i < maxFd; i++) {
				close(i);
			}
		}

		execv(exe.c_str(), &argv[0]);
ERR_EXIT:
		/*
			write pipe if execv fails
		*/
		pipe.write("x", 1);
		pipe.close(Pipe::Write);
		::exit(1);
	}

	pipe.close(Pipe::Write);
	char buf[1];

	/*
		if execv succeeds then Pipe::Read is closed and returns error
		otherwise gets 'x' from child
	*/
	if (pipe.read(buf, 1) == 1) {
		waitpid(pid, 0, WNOHANG);
		return false;
	}

	*hdl = pid;
	return true;
#endif
}

#ifdef _WIN32
inline bool Close(Handle hdl)
{
	return CloseHandle(hdl) != 0;
}
#else
inline bool Close(Handle)
{
	return true;
}
#endif

/**
	whether process is alive or not
	@param hdl [in] handle of process
	@param exitCode [out] return exitCode if !IsAlive()
*/
inline bool IsAlive(Handle hdl, int* exitCode = 0)
{
#ifdef _WIN32
//	int ret = WaitForSingleObject(hdl, 0);
//	return ret == WAIT_TIMEOUT;
	DWORD code;
	if (GetExitCodeProcess(hdl, &code)) {
		if (code == STILL_ACTIVE) {
			return true;
		}
		if (exitCode) {
			*exitCode = (int)code;
		}
	}
	return false;
#else
	int status;
	pid_t p = waitpid(hdl, &status, WNOHANG);
	if (p == 0) return true;
	if (p == hdl) {
		if (exitCode) {
			if (WIFEXITED(status)) {
				*exitCode = WEXITSTATUS(status);
			} else {
				*exitCode = -1;
			}
		}
	}
	return false;
#endif
}

} // process

class Process {
	mutable process::Handle hdl_;
	void move(const Process& rhs) const
	{
		assert(!isValid());
		hdl_ = rhs.hdl_;
		rhs.hdl_ = process::InvalidHandle;
	}
	void close()
	{
		if (!isValid()) return;

		process::Close(hdl_);
		hdl_ = process::InvalidHandle;
	}
public:
	Process()
		: hdl_(process::InvalidHandle)
	{
	}
	~Process()
	{
		close();
	}
	Process(const Process& rhs)
		: hdl_(process::InvalidHandle)
	{
		move(rhs);
	}
	Process& operator=(const Process& rhs)
	{
		if (this != &rhs) {
			move (rhs);
		}

		return *this;
	}
	bool run(const std::string& exe, const std::vector<std::string>& arg = std::vector<std::string>(), bool closeStdio = true)
	{
		close();
		return process::Start(&hdl_, exe, arg, closeStdio);
	}
	bool run(const std::string& exe, const std::string& p1 = "", const std::string& p2 = "", const std::string& p3 = "", const std::string& p4 = "", const std::string& p5 = "", const std::string& p6 = "", const std::string& p7 = "", const std::string& p8 = "", const std::string& p9 = "")
	{
		std::vector<std::string> arg;
		if (!p1.empty()) arg.push_back(p1);
		if (!p2.empty()) arg.push_back(p2);
		if (!p3.empty()) arg.push_back(p3);
		if (!p4.empty()) arg.push_back(p4);
		if (!p5.empty()) arg.push_back(p5);
		if (!p6.empty()) arg.push_back(p6);
		if (!p7.empty()) arg.push_back(p7);
		if (!p8.empty()) arg.push_back(p8);
		if (!p9.empty()) arg.push_back(p9);
		return run(exe, arg, false);
	}
	bool isValid() const
	{
		return hdl_ != process::InvalidHandle;
	}
	bool isAlive(int* exitCode = 0) const
	{
		if (exitCode) *exitCode = 0;
		return isValid() && process::IsAlive(hdl_, exitCode);
	}
};

} // cybozu

