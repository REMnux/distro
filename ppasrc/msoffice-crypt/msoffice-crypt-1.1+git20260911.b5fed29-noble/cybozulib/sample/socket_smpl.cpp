/*
	cf. ping6 -I eth0 <IPv6 addr>
	Linux : <IPv6>%eth0
	Windows : <IPv6>%<number>
*/
#include <cybozu/option.hpp>
#include <cybozu/socket.hpp>

int main(int argc, char *argv[])
	try
{
	std::string ip;
	uint16_t port;
	std::string cmd;
	bool verbose = false;
	int mode = 0;
	int timeoutSec = 0;

	cybozu::Option opt;
	opt.appendOpt(&ip, "", "ip", ": ip address");
	opt.appendBoolOpt(&verbose, "v", ": verbose");
	opt.appendOpt(&mode, 0, "m", ": mode = 4(v4only), 6(v6only), 0(both)");
	opt.appendOpt(&port, uint16_t(50000), "p", ": port");
	opt.appendOpt(&timeoutSec, 5, "t", ": timeout(sec)");
	opt.appendParamOpt(&cmd, "cmd", ":string to send");
	switch (mode) {
	case 0:
		mode = cybozu::Socket::allowIPv4 | cybozu::Socket::allowIPv6;
		break;
	case 4:
		mode = cybozu::Socket::allowIPv4;
		break;
	case 6:
		mode = cybozu::Socket::allowIPv6;
		break;
	default:
		printf("bad mode=%d\n", mode);
		return 1;
	}

	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 1;
	}
	if (verbose) opt.put();
	const int timeoutMsec = timeoutSec * 1000;
	if (ip.empty()) {
		printf("server port=%d\n", port);
		cybozu::Socket server;
		server.bind(port, mode);
		for (;;) {
			while (!server.queryAccept()) {
			}
			cybozu::Socket client;
			if (verbose) {
				cybozu::SocketAddr addr;
				server.accept(client, &addr);
				printf("addr=%s, port=%d\n", addr.toStr().c_str(), addr.getPort());
			} else {
				server.accept(client);
			}
			client.setSendTimeout(timeoutMsec);
			client.setReceiveTimeout(timeoutMsec);
			{
				char buf[128];
				size_t readSize = client.readSome(buf, sizeof(buf));
				printf("rec=%s(%d)\n", std::string(buf, readSize).c_str(), (int)readSize);
			}
		}
	} else {
		printf("client ip=%s port=%d\n", ip.c_str(), port);
		cybozu::SocketAddr sa(ip, port);
		printf("addr=%s\n", sa.toStr().c_str());
		cybozu::Socket client;
		client.connect(sa, timeoutMsec);
		client.setSendTimeout(timeoutMsec);
		client.setReceiveTimeout(timeoutMsec);
		client.write(cmd.c_str(), cmd.size());
	}
} catch (std::exception& e) {
	printf("ERR %s\n", e.what());
}
