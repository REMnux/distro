#pragma once
/**
	@file
	@brief logger

	@author MITSUNARI Shigeo(@herumi)
*/
#include <cybozu/format.hpp>
#include <cybozu/time.hpp>
#ifdef _WIN32
#else
	#include <syslog.h>
#endif

namespace cybozu {

enum LogPriority {
	LogDebug = 0,
	LogInfo = 1,
	LogWarning = 2,
	LogError = 3
};

namespace log_local {

class Logger {
	int priority_;
	FILE *fp_;
	bool doClose_;
	bool useSyslog_;
	bool useMsec_;
public:
	Logger()
		: priority_(cybozu::LogInfo)
		, fp_(stderr)
		, doClose_(false)
		, useSyslog_(true)
		, useMsec_(false)
	{
	}
	~Logger() CYBOZU_NOEXCEPT
	{
		closeFile();
	}
	void put(LogPriority priority, const std::string& str)
	{
		if (priority < priority_) return;
		if (fp_) {
			cybozu::Time cur(true);
			if (fprintf(fp_, "%s %s\n", cur.toString(useMsec_).c_str(), str.c_str()) < 0) {
				fprintf(stderr, "ERR:cybozu:Logger:put:fprintf:%s\n", str.c_str());
			}
			if (fflush(fp_) < 0) {
				fprintf(stderr, "ERR:cybozu:Logger:put:fflush:%s\n", str.c_str());
			}
		}
		if (useSyslog_) {
#ifdef __linux__
			int pri = LOG_CRIT;
			if (priority == LogDebug) {
				pri = LOG_DEBUG;
			} else if (priority == LogInfo) {
				pri = LOG_INFO;
			} else if (priority == LogWarning) {
				pri = LOG_WARNING;
			}
			::syslog(pri, "%s\n", str.c_str());
#endif
		}
	}
	void put(LogPriority priority, const char *format, va_list args)
	{
		if (priority < priority_) return;
		std::string str;
		cybozu::vformat(str, format, args);
		put(priority, str);
	}

	static Logger& getInstance()
	{
		static Logger logger;
		return logger;
	}
	/*
		@note : not thread safe
		@param path [in] open path for log
	*/
	void openFile(const std::string& path)
	{
		FILE *fp = 0;
#ifdef _MSC_VER
		if (fopen_s(&fp, path.c_str(), "a+b")) fp = 0;
#else
		fp = fopen(path.c_str(), "a+b");
#endif
		if (fp == 0) throw cybozu::Exception("cybozu:Logger:openFile") << path;
		if (!closeFile()) throw cybozu::Exception("cybozu:Logger:openFile:fail to closeFile");
		fp_ = fp;
		doClose_ = true;
		useSyslog_ = false;
	}
	/*
		set FILE pointer
		@param fp [in] write log to fp if fp != NULL
		@note Logger does not close the pointer
	*/
	void set(FILE *fp)
	{
		if (!closeFile()) throw cybozu::Exception("cybozu:Logger:set:fail to closeFile");
		fp_ = fp;
		doClose_ = false;
		useSyslog_ = false;
	}
	/*
		use syslog if useSyslog is true
	*/
	void useSyslog(bool useSyslog)
	{
		useSyslog_ = useSyslog;
	}
	bool closeFile() CYBOZU_NOEXCEPT
	{
		if (!doClose_ || fp_ == 0) return true;
		if (fp_ == stdout || fp_ == stderr) {
			fp_ = NULL;
			return true;
		}
		bool isOK = fclose(fp_) == 0;
		fp_ = NULL;
		return isOK;
	}
	void setPriority(LogPriority priority)
	{
		priority_ = priority;
	}
	void setUseMsec(bool useMsec)
	{
		useMsec_ = useMsec;
	}
};

} // cybozu::log_local

/*
	write log to path(default is stderr, syslog)
	@param path [in] open path for log
	@note this function is not thread safe
*/
inline void OpenLogFile(const std::string& path)
{
	return log_local::Logger::getInstance().openFile(path);
}

/*
	set FILE pointer
	@param fp [in] write log to fp if fp != NULL
	@note Logger does not close the pointer
	@note this function is not thread safe
*/
inline void SetLogFILE(FILE *fp)
{
	return log_local::Logger::getInstance().set(fp);
}

/*
	use syslog if useSyslog is true
*/
inline void useSyslog(bool useSyslog)
{
	log_local::Logger::getInstance().useSyslog(useSyslog);
}
/*
	set priority(default cybozu::LogInfo)
	does not show the message of which is less or equal to the priority
*/
inline void SetLogPriority(LogPriority priority)
{
	log_local::Logger::getInstance().setPriority(priority);
}
/*
	set useMsec
*/
inline void SetLogUseMsec(bool useMsec = true)
{
	log_local::Logger::getInstance().setUseMsec(useMsec);
}
/*
	write log like printf
	Linux : default is syslog
	Windows : default is file(use openFile)
*/
#ifdef __GNUC__
inline void PutLog(LogPriority priority, const char *format, ...) CYBOZU_NOEXCEPT __attribute__((format(printf, 2, 3)));
#endif
inline void PutLog(LogPriority priority, const char *format, ...) CYBOZU_NOEXCEPT
	try
{
	va_list args;
	va_start(args, format);
	log_local::Logger::getInstance().put(priority, format, args);
	va_end(args);
} catch (std::exception& e) {
	fprintf(stderr, "faital error in cybozu::PutLog %s\n", e.what());
} catch (...) {
	fprintf(stderr, "faital error in cybozu::PutLog\n");
}

} // cybozu

namespace cybozu {
/*
	write log like std::cout
	Linux : default is syslog
	Windows : default is file(use openFile)
*/
class Log {
	LogPriority pri_;
	std::ostringstream os_;
	Log(const Log&);
	void operator=(const Log&);
public:
	explicit Log(LogPriority priority = cybozu::LogInfo) : pri_(priority) { }
	~Log() CYBOZU_NOEXCEPT
	{
		try {
			log_local::Logger::getInstance().put(pri_, os_.str());
		} catch (std::exception& e) {
			fprintf(stderr, "faital error in cybozu::Log %s\n", e.what());
		} catch (...) {
			fprintf(stderr, "faital error in cybozu::Log\n");
		}
	}
	template<class T>
	Log& operator<<(const T& t) { os_ << t; return *this; }
};

} // cybozu
