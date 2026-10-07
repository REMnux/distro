#define CYBOZU_TEST_DISABLE_AUTO_RUN
#include <cybozu/test.hpp>
#include <cybozu/zlib.hpp>
#include <cybozu/file.hpp>
#include <cybozu/stream.hpp>
#include <cybozu/mmap.hpp>
#include <cybozu/serializer.hpp>
#include <cybozu/nlp/sparse.hpp>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <map>

const char *g_testFile = "zlib_test.log";
const char *g_extraFile = 0;
const char *g_compressFile = 0;

CYBOZU_TEST_AUTO(test1_deflate)
{
	typedef cybozu::ZlibCompressorT<std::stringstream> Compressor;
	typedef cybozu::ZlibDecompressorT<std::stringstream> Decompressor;
	const std::string in = "this is a pen";

	std::stringstream os;
	{
		Compressor comp(os);
		comp.write(in.c_str(), in.size());
		comp.flush();
	}
	const std::string enc = os.str();

	const char encTbl[] = "\x78\x9c\x2b\xc9\xc8\x2c\x56\x00\xa2\x44\x85\x82\xd4\x3c\x00\x21\x0c\x04\x99";

	const std::string encOk(encTbl, encTbl + sizeof(encTbl) - 1);
	CYBOZU_TEST_EQUAL(enc, encOk);

	std::stringstream is;
	is << encOk;

	{
		Decompressor dec(is);
		char buf[2048];
		std::string out;
		for (;;) {
			size_t size = dec.readSome(buf, sizeof(buf));
			if (size == 0) break;
			out.append(buf, buf + size);
		}
		CYBOZU_TEST_EQUAL(in, out);
	}
}

CYBOZU_TEST_AUTO(test2_deflate)
{
	typedef cybozu::ZlibCompressorT<std::stringstream, 1> Compressor;
	typedef cybozu::ZlibDecompressorT<std::stringstream, 1> Decompressor;
	const std::string in = "this is a pen";

	std::stringstream os;
	{
		Compressor comp(os);
		for (size_t i = 0; i < in.size(); i++) {
			comp.write(&in[i], 1);
		}
		comp.flush();
	}
	const std::string enc = os.str();

	const char encTbl[] = "\x78\x9c\x2b\xc9\xc8\x2c\x56\x00\xa2\x44\x85\x82\xd4\x3c\x00\x21\x0c\x04\x99";

	const std::string encOk(encTbl, encTbl + sizeof(encTbl) - 1);
	CYBOZU_TEST_EQUAL(enc, encOk);

	std::stringstream is;
	is << encOk;

	{
		Decompressor dec(is);
		char buf[2048];
		std::string out;
		for (;;) {
			size_t size = dec.readSome(buf, sizeof(buf));
			if (size == 0) break;
			out.append(buf, buf + size);
		}
		CYBOZU_TEST_EQUAL(in, out);
	}
}

CYBOZU_TEST_AUTO(enc_and_dec)
{
	std::string body = "From: cybozu\r\n"
				 "To: cybozu\r\n"
				 "\r\n"
				 "hello with zlib compressed\r\n"
				 ".\r\n";
	std::stringstream ss;
	cybozu::ZlibCompressorT<std::stringstream> comp(ss);
	comp.write(&body[0], body.size());
	comp.flush();

	std::string enc = ss.str();

	cybozu::StringInputStream ims(enc);

	cybozu::ZlibDecompressorT<cybozu::StringInputStream> dec(ims);
	char buf[4096];
	size_t size = dec.readSome(buf, sizeof(buf));
	std::string decStr(buf, buf + size);
	CYBOZU_TEST_EQUAL(body, decStr);
}

CYBOZU_TEST_AUTO(output_gzip1)
{
	std::string str = "Only a test, test, test, test, test, test, test, test!\n";
	std::stringstream ss;
	cybozu::ZlibCompressorT<std::stringstream> comp(ss, true);
	comp.write(&str[0], str.size());
	comp.flush();
	std::string enc = ss.str();

	{
		cybozu::ZlibDecompressorT<std::stringstream> dec(ss, true);
		char buf[4096];
		size_t size = dec.readSome(buf, sizeof(buf));
		std::string decStr(buf, buf + size);
		CYBOZU_TEST_EQUAL(decStr, str);
	}

	{
		cybozu::StringInputStream is(enc);
		cybozu::ZlibDecompressorT<cybozu::StringInputStream> dec(is, true);
		char buf[4096];
		size_t size = dec.readSome(buf, sizeof(buf));
		std::string decStr(buf, buf + size);
		CYBOZU_TEST_EQUAL(decStr, str);
	}
}

#ifdef _MSC_VER
	#pragma warning(disable : 4309)
#endif

CYBOZU_TEST_AUTO(output_gzip2)
{
	const uint8_t textBufTbl[] = {
		0x23, 0x69, 0x6E, 0x63, 0x6C, 0x75, 0x64, 0x65, 0x20, 0x3C, 0x73, 0x74, 0x64, 0x69, 0x6F, 0x2E,
		0x68, 0x3E, 0x0A, 0x0A, 0x69, 0x6E, 0x74, 0x20, 0x6D, 0x61, 0x69, 0x6E, 0x28, 0x29, 0x0A, 0x7B,
		0x0A, 0x09, 0x70, 0x75, 0x74, 0x73, 0x28, 0x22, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x22, 0x29, 0x3B,
		0x0A, 0x09, 0x72, 0x65, 0x74, 0x75, 0x72, 0x6E, 0x20, 0x30, 0x3B, 0x0A, 0x7D, 0x0A, 0x0A,
	};

	const uint8_t encBufTbl[] = {
		0x1F, 0x8B, 0x08, 0x08, 0xA4, 0x7E, 0x20, 0x4B, 0x00, 0x03, 0x74, 0x2E, 0x63, 0x70, 0x70, 0x00,
		0x53, 0xCE, 0xCC, 0x4B, 0xCE, 0x29, 0x4D, 0x49, 0x55, 0xB0, 0x29, 0x2E, 0x49, 0xC9, 0xCC, 0xD7,
		0xCB, 0xB0, 0xE3, 0xE2, 0xCA, 0xCC, 0x2B, 0x51, 0xC8, 0x4D, 0xCC, 0xCC, 0xD3, 0xD0, 0xE4, 0xAA,
		0xE6, 0xE2, 0x2C, 0x28, 0x2D, 0x29, 0xD6, 0x50, 0xCA, 0x48, 0xCD, 0xC9, 0xC9, 0x57, 0xD2, 0xB4,
		0xE6, 0xE2, 0x2C, 0x4A, 0x2D, 0x29, 0x2D, 0xCA, 0x53, 0x30, 0xB0, 0xE6, 0xAA, 0xE5, 0xE2, 0x02,
		0x00, 0x48, 0xAB, 0x48, 0x61, 0x3F, 0x00, 0x00, 0x00,
	};
	const char *const textBuf = cybozu::cast<const char*>(textBufTbl);
	const char *const encBuf = cybozu::cast<const char*>(encBufTbl);
	const std::string text(textBuf, textBuf + sizeof(textBufTbl));

	{
		std::stringstream ss;
		ss.write(encBuf, sizeof(encBufTbl));
		cybozu::ZlibDecompressorT<std::stringstream> dec(ss, true);
		char buf[4096];
		size_t size = dec.readSome(buf, sizeof(buf));
		std::string decStr(buf, buf + size);
		CYBOZU_TEST_EQUAL(decStr, text);
	}
}

template<class Map>
void compareMap(const Map& x, const Map& y)
{
	CYBOZU_TEST_EQUAL(x.size(), y.size());
	for (typename Map::const_iterator i = x.begin(), ie = x.end(), j = y.begin(); i != ie; ++i, ++j) {
		CYBOZU_TEST_EQUAL(i->first, j->first);
		CYBOZU_TEST_EQUAL(i->second, j->second);
	}
}

#if 0
CYBOZU_TEST_AUTO(serializer_with_zlib)
{
	typedef std::map<int, double> Map;
	Map src;
	for (int i = 0; i < 100; i++) {
		src[i * i] = (i + i * i) / 3.42;
	}
	std::stringstream ss;
	{
		cybozu::ZlibCompressorT<std::stringstream> enc(ss);
		cybozu::save(enc, src);
	}
	{
		cybozu::ZlibDecompressorT<std::stringstream> dec(ss);
		Map dst;
		cybozu::load(dst, dec);
		compareMap(src, dst);
	}
	{
		std::ofstream ofs(g_testFile, std::ios::binary);
		cybozu::ZlibCompressorT<std::ofstream> enc(ofs);
		cybozu::save(enc, src);
	}
	{
		std::ifstream ifs(g_testFile, std::ios::binary);
		cybozu::ZlibDecompressorT<std::ifstream> dec(ifs);
		Map dst;
		cybozu::load(dst, dec);
		compareMap(src, dst);
	}
}

CYBOZU_TEST_AUTO(sparse_with_zlib)
{
	typedef cybozu::nlp::SparseVector<double> Vec;
	Vec x;
	const struct {
		int pos;
		double val;
	} tbl[] = {
		{ 3, 1.2 }, { 5, 9.4 }, { 8, 123.4 }, { 999, -324.0 },
	};
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		x.push_back(tbl[i].pos, tbl[i].val);
	}
	{
		std::ofstream ofs(g_testFile, std::ios::binary);
		cybozu::ZlibCompressorT<std::ofstream> enc(ofs);
		cybozu::save(enc, x);
	}
	{
		Vec y;
		std::ifstream ifs(g_testFile, std::ios::binary);
		cybozu::ZlibDecompressorT<std::ifstream> dec(ifs);
		cybozu::load(y, dec);
//		CYBOZU_TEST_ASSERT(x == y);
		CYBOZU_TEST_EQUAL(x.size(), y.size());
		Vec::const_iterator xi = x.begin();
		Vec::const_iterator yi = y.begin();
		while (xi != x.end()) {
			CYBOZU_TEST_EQUAL(xi->pos(), yi->pos());
			CYBOZU_TEST_EQUAL(xi->val(), yi->val());
			++xi;
			++yi;
		}
		CYBOZU_TEST_ASSERT(yi == y.end());
	}
}
#endif

CYBOZU_TEST_AUTO(random)
{
	std::vector<char> out;
	std::string in;
	std::vector<char> out2;

	for (size_t inSize = 12000; inSize < 14000; inSize += 3) {
		in.resize(inSize);
		out.resize(inSize + 100);
		for (size_t i = 0; i < inSize; i++) {
			in[i] = char((3 * i * i + i) % 1905);
		}
		cybozu::MemoryOutputStream os(out.data(), out.size());
		{
			cybozu::ZlibCompressorT<cybozu::MemoryOutputStream> enc(os, false, Z_DEFAULT_COMPRESSION);
			enc.write(in.data(), inSize);
			enc.flush();
			out.resize(os.getPos());
		}
		{
			std::string ok;
			ok.resize(in.size());
			size_t okSize = cybozu::ZlibCompress(&ok[0], ok.size(), in.data(), in.size());
			CYBOZU_TEST_EQUAL(okSize, out.size());
			CYBOZU_TEST_ASSERT(memcmp(ok.data(), out.data(), okSize) == 0);
		}
		{
			std::string dec;
			dec.resize(in.size() + 100);
			size_t decSize = cybozu::ZlibUncompress(&dec[0], dec.size(), out.data(), out.size());
			dec.resize(decSize);
			CYBOZU_TEST_EQUAL(decSize, in.size());
			CYBOZU_TEST_EQUAL(dec, in);
		}
		out2.resize(in.size() + 100);
		size_t outSize = out.size();
		{
			cybozu::MemoryInputStream is(out.data(), outSize);
			cybozu::ZlibDecompressorT<cybozu::MemoryInputStream> dec(is);
			char *const top = (char*)out2.data();
			size_t pos = 0;
			for (;;) {
				size_t readSize = dec.readSome(top + pos, out2.size() - pos);
				if (readSize == 0) break;
				pos += readSize;
			}
			CYBOZU_TEST_ASSERT(dec.isEmpty());
			CYBOZU_TEST_ASSERT(memcmp(in.data(), out2.data(), pos) == 0);
		}
	}
}

CYBOZU_TEST_AUTO(extra)
{
	if (g_extraFile == 0) return;
	cybozu::Mmap f(g_extraFile);
	printf("extraFile=%s\n", g_extraFile);
	std::string comp;
	std::string decomp;
	{
		cybozu::MemoryInputStream is(f.get(), f.size());
		cybozu::StringOutputStream os(comp);
		cybozu::ZlibCompressorT<cybozu::StringOutputStream> enc(os);
		enc.write(f.get(), f.size());
	}
	if (g_compressFile) {
		std::ofstream ofs(g_compressFile, std::ios::binary);
		ofs.write(comp.data(), comp.size());
	}

	{
		std::string ok;
		ok.resize(f.size());
		size_t okSize = cybozu::ZlibCompress(&ok[0], ok.size(), f.get(), f.size());
		ok.resize(okSize);
		CYBOZU_TEST_EQUAL(okSize, comp.size());
		CYBOZU_TEST_EQUAL(ok, comp);
	}

	const size_t decompSize = f.size() + 100;
	decomp.resize(decompSize);
	{
		cybozu::StringInputStream is(comp);
		cybozu::ZlibDecompressorT<cybozu::StringInputStream> dec(is);
		char *top = &decomp[0];
		size_t pos = 0;
		for (;;) {
			size_t readSize = dec.readSome(top + pos, decompSize - pos);
			if (readSize == 0) break;
			pos += readSize;
		}
		CYBOZU_TEST_ASSERT(dec.isEmpty());
		decomp.resize(pos);
		CYBOZU_TEST_EQUAL(pos, f.size());
		CYBOZU_TEST_ASSERT(memcmp(f.get(), decomp.data(), f.size()) == 0);
	}
	{
		std::string ok;
		ok.resize(decomp.size() + 100);
		size_t okSize = cybozu::ZlibUncompress(&ok[0], ok.size(), comp.data(), comp.size());
		ok.resize(okSize);
		CYBOZU_TEST_EQUAL(okSize, decomp.size());
		CYBOZU_TEST_ASSERT(ok == decomp);
	}
}

int main(int argc, char *argv[])
{
	if (argc >= 2) {
		g_extraFile = argv[1];
	}
	if (argc == 3) {
		g_compressFile = argv[2];
	}
	return cybozu::test::autoRun.run(argc, argv);
}
