#include <cybozu/csucvector.hpp>
#include <cybozu/mmap.hpp>
#include <sstream>

void test(const std::string& inName)
{
	cybozu::Mmap m(inName);
	const uint64_t *blk = reinterpret_cast<const uint64_t*>(m.get());
	cybozu::CSucVector cv2(blk, m.size() * 8);
	cybozu::CSucVector cv;
	{
		std::stringstream ss;
		cv2.save(ss);
		cv.load(ss);
		const int inSize = (int)m.size();
		const int outSize = (int)ss.str().size();
		printf("rate = %.2f%% %d / %d\n", outSize * 100.0 / inSize, outSize, inSize);
	}
	cybozu::BitVector bv;
	bv.resize(m.size() * 8);
	for (size_t i = 0, n = bv.size(); i < n; i++) {
		if (cv.get(i)) bv.set(i);
	}
	const uint64_t *p = bv.getBlock();
	for (size_t i = 0, n = bv.getBlockSize(); i < n; i++) {
		if (p[i] != blk[i]) {
			printf("err i=%d %llx %llx\n", (int)i, (long long)blk[i], (long long)p[i]);
			exit(1);
		}
	}
}

int main(int argc, char *argv[])
{
	argc--, argv++;
	if (argc != 1) {
		fprintf(stderr, "csucvector_smp.exe\n");
		return 1;
	}
	const std::string inName(argv[0]);
	test(inName);
}
