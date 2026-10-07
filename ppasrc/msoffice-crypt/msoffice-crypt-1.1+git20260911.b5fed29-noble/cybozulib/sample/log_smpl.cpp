#include <stdio.h>
#include <cybozu/log.hpp>

int main()
{
	cybozu::PutLog(cybozu::LogInfo, "this is a pen1");
	cybozu::useSyslog(false);
	cybozu::SetLogUseMsec();
	cybozu::PutLog(cybozu::LogInfo, "this is a pen2");
	cybozu::OpenLogFile("test.log");
	cybozu::PutLog(cybozu::LogInfo, "this is a pen3");
	cybozu::useSyslog(true);
	cybozu::PutLog(cybozu::LogInfo, "this is a pen4");

	cybozu::PutLog(cybozu::LogInfo, "AAtest");
	cybozu::SetLogPriority(cybozu::LogInfo);
	cybozu::PutLog(cybozu::LogInfo, "AAtest2");
	cybozu::PutLog(cybozu::LogDebug, "not print");
}
