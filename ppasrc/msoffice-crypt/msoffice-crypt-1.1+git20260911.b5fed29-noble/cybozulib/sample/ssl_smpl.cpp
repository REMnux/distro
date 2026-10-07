#include <stdio.h>
#include <string>
#include <cybozu/ssl.hpp>

int main(int argc, char *argv[])
{
	try {
		argc--, argv++;
		if (argc < 2) {
			fprintf(stderr, "ssl_smpl host dir\n");
			fprintf(stderr, " ex ssl_smpl www.cybozu.com /\n");
			return 1;
		}
		const std::string host = argv[0];
		const std::string path = argv[1];
		cybozu::ssl::ClientSocket s;
		printf("connect %s\n", host.c_str());
		s.connect(host, 443);
		const std::string http = "GET " + path + " HTTP/1.0\r\n\r\n";
		printf("cmd=%s\n", http.c_str());
		s.write(http.c_str(), http.size());
		puts("write end");
		ssize_t total = 0;
		for (;;) {
			char buf[1024];
			size_t readSize = s.readSome(buf, sizeof(buf));
			if (readSize == 0) {
				break;
			}
			total += readSize;
			printf("%s", std::string(buf, readSize).c_str());
		}
		printf("\ntotal=%d\n", (int)total);
	} catch (cybozu::Exception& e) {
		printf("err=%s\n", e.what());
		return 1;
	}
}

