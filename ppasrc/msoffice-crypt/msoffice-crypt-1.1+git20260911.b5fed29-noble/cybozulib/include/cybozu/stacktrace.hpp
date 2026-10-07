#pragma once
/**
	@file
	@brief stacktrace class
	@author MITSUNARI Shigeo(@herumi)
*/
#include <string>
#include <vector>
#include <cybozu/itoa.hpp>
#include <stdlib.h>
#include <iosfwd>

#ifdef _WIN32
	#ifndef WIN32_LEAN_AND_MEAN
		#define WIN32_LEAN_AND_MEAN
	#endif
	#include <windows.h>
	#include <imagehlp.h>
	#include <stdio.h>
	#pragma comment(lib, "imagehlp.lib")
#else
	#include <execinfo.h>
	#include <string.h>
	#include <cxxabi.h>
	#include <stdint.h>
	#ifdef CYBOZU_STACKTRACE_WITH_BFD_GPL
		#include <cybozu/bfd.hpp>
	#endif
#endif

#ifndef NDEBUG
	#define CYBOZU_STACKTRACE_RESOLVE_SYMBOL
#endif

namespace cybozu {

namespace stacktrace_local {

#ifdef _WIN32

struct InitSymbol {
	HANDLE hdl_;
	InitSymbol()
		: hdl_(GetCurrentProcess())
	{
#ifdef CYBOZU_STACKTRACE_RESOLVE_SYMBOL
		SymInitialize(hdl_, NULL, TRUE);
#endif
	}
	~InitSymbol()
	{
#ifdef CYBOZU_STACKTRACE_RESOLVE_SYMBOL
		SymCleanup(hdl_);
#endif
	}
	HANDLE getHandle() const { return hdl_; }
};

template<int dummy = 0>
struct InstanceIsHere { static InitSymbol is_; };

template<int dummy>
InitSymbol InstanceIsHere<dummy>::is_;

struct DummyCall {
	DummyCall() { InstanceIsHere<>::is_.getHandle(); }
};

#endif

class AutoFree {
	void *p_;
public:
	AutoFree(void *p)
		: p_(p)
	{
	}
	~AutoFree()
	{
		free(p_);
	}
};

#if defined(CYBOZU_STACKTRACE_WITH_BFD_GPL) || defined(CYBOZU_STACKTRACE_RESOLVE_SYMBOL)
	const char delim = '\n';
#else
	#define CYBOZU_STACKTRACE_ONELINE
	const char delim = ' ';
#endif

inline std::string addrToHex(const void *addr)
{
	char buf[32];
#ifdef CYBOZU_STACKTRACE_ONELINE
	CYBOZU_SNPRINTF(buf, sizeof(buf), "0x%llx", (long long)addr);
#else
	CYBOZU_SNPRINTF(buf, sizeof(buf), "[0x%llx]", (long long)addr);
#endif
	return buf;
}

} // stacktrace_local

#ifdef __GNUC__
inline bool Demangle(std::string& out, const std::string& func)
{
	int status;
	char *demangled = abi::__cxa_demangle(func.c_str(), 0, 0, &status);
	stacktrace_local::AutoFree afDemangle(demangled);
	if (status == 0) {
		out = demangled;
		return true;
	} else {
		out = func;
		return false;
	}
}
#endif

class StackTrace {
	std::vector<void*> data_;
#ifdef CYBOZU_STACKTRACE_WITH_BFD_GPL
	static inline cybozu::Bfd& getBfd()
	{
		static cybozu::Bfd bfd;
		return bfd;
	}
#endif
public:
	/**
		set current stack trace
	*/
	StackTrace()
	{
		data_.clear();

		const int maxTraceNum = 32;

#ifdef _WIN32

		CONTEXT ctx;
		memset(&ctx, 0, sizeof(ctx));
		ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
		RtlCaptureContext(&ctx);

		STACKFRAME64 sf;
		memset(&sf, 0, sizeof(sf));

#ifdef _WIN64
		sf.AddrPC.Offset = ctx.Rip;
		sf.AddrFrame.Offset = ctx.Rbp;
		sf.AddrStack.Offset = ctx.Rsp;
		DWORD machineType = IMAGE_FILE_MACHINE_AMD64;
#else
		sf.AddrPC.Offset = ctx.Eip;
		sf.AddrFrame.Offset = ctx.Ebp;
		sf.AddrStack.Offset = ctx.Esp;
		DWORD machineType = IMAGE_FILE_MACHINE_I386;
#endif
		sf.AddrPC.Mode = AddrModeFlat;
		sf.AddrFrame.Mode = AddrModeFlat;
		sf.AddrStack.Mode = AddrModeFlat;

		HANDLE threadHdl = GetCurrentThread();

		HANDLE processHdl = stacktrace_local::InstanceIsHere<>::is_.getHandle();
		for(;;) {
			BOOL ret;
			ret = StackWalk64(machineType, processHdl, threadHdl, &sf, &ctx, NULL,
					SymFunctionTableAccess64, SymGetModuleBase64, NULL);
			if (!ret || sf.AddrFrame.Offset == 0) return;

			data_.push_back((void*)sf.AddrPC.Offset);
			if (data_.size() == maxTraceNum) return;
		}
#else
		data_.resize(maxTraceNum);
		int traceNum = backtrace(&data_[0], maxTraceNum);
		data_.resize(traceNum);
#endif
	}
	/**
		get stack trace
	*/
	std::string toString() const
	{
		size_t traceNum = data_.size();
		if (traceNum == 0) return "";

		std::string out;

#ifdef _WIN32
#ifdef CYBOZU_STACKTRACE_RESOLVE_SYMBOL
		HANDLE processHdl = stacktrace_local::InstanceIsHere<>::is_.getHandle();
#endif
		if (traceNum > 1) traceNum--; // last information is unnecessary
		for (size_t i = 0; i < traceNum; i++) {
			uintptr_t ptr = (uintptr_t)data_[i];

#ifdef CYBOZU_STACKTRACE_RESOLVE_SYMBOL
			DWORD disp;
			IMAGEHLP_LINE64 line;
			memset(&line, 0, sizeof(line));
			line.SizeOfStruct = sizeof(line);
			if (SymGetLineFromAddr64(processHdl, ptr, &disp, &line)) {
				out += line.FileName;
				out += ':';
				out += cybozu::itoa((int)line.LineNumber);
				out += ' ';
			}
#endif
			out += stacktrace_local::addrToHex((const void*)ptr);
			if (i < traceNum - 1) out += stacktrace_local::delim;
		}
#else

#ifdef CYBOZU_STACKTRACE_RESOLVE_SYMBOL
		char **symbol = backtrace_symbols(&data_[0], traceNum);
		stacktrace_local::AutoFree freeSymbol(symbol);
#endif
		for (size_t i = 0; i < traceNum; i++) {
			std::string funcName;
#ifdef CYBOZU_STACKTRACE_WITH_BFD_GPL
			{
				std::string fileName;
				int line;
				if (getBfd().getInfo(&fileName, &funcName, &line, data_[i])) {
					Demangle(funcName, funcName);
					out += fileName;
					out += ':';
					out += cybozu::itoa(line);
					out += ' ';
				}
			}
#endif
#ifdef CYBOZU_STACKTRACE_RESOLVE_SYMBOL
			if (symbol) {
				std::string str(symbol[i]);
				str += '\0';
				size_t p = str.find('(');
				const char *obj = 0, *addr = 0;
				if (p != std::string::npos) {
					size_t q = str.find('+', p + 1);
					if (q != std::string::npos) {
						obj = &str[0]; str[p] = '\0';
						const char *const func = &str[p + 1]; str[q] = '\0';
						addr = &str[q + 1];
						if (funcName.empty()) {
							Demangle(funcName, func);
						}
					}
				}
				bool doPrint = false;
				if (obj && addr) {
					out += obj;
					out += '(';
					out += funcName;
					out += '+';
					out += addr;
					out += ' ';
					doPrint = true;
				} else if (!funcName.empty()) {
					out += funcName;
					out += ' ';
				}
				if (!doPrint) {
					out += symbol[i];
					out += ' ';
				}
			} else
#endif
			{
				out += stacktrace_local::addrToHex(data_[i]);
			}
			if (i < traceNum - 1) out += stacktrace_local::delim;
		}
#endif
		return out;
	}
	bool empty() const CYBOZU_NOEXCEPT { return data_.empty(); }
	void clear() CYBOZU_NOEXCEPT { data_.clear(); }
};

inline std::ostream& operator<<(std::ostream& os, const StackTrace& self)
{
	return os << self.toString();
}

} // cybozu

#undef CYBOZU_STACKTRACE_RESOLVE_SYMBOL
