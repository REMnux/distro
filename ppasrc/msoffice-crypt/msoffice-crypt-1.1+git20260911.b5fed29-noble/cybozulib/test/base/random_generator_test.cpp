#include <cybozu/test.hpp>
#include <cybozu/random_generator.hpp>

CYBOZU_TEST_AUTO(read)
{
	cybozu::RandomGenerator rg;
#if 0
	char buf8[3] = {};
	rg.read(buf8, sizeof(buf8));
	for (size_t i = 0; i < sizeof(buf8); i++) {
		CYBOZU_TEST_ASSERT(buf8[i] != 0); // maybe
	}
#endif

	const size_t N = 10;

	uint32_t buf32[N] = {};
	rg.read(buf32, N);
	for (size_t i = 0; i < N; i++) {
		CYBOZU_TEST_ASSERT(buf32[i] != 0); // maybe
	}

	uint64_t buf64[N] = {};
	rg.read(buf64, N);
	for (size_t i = 0; i < N; i++) {
		CYBOZU_TEST_ASSERT(buf64[i] != 0); // maybe
	}
}
