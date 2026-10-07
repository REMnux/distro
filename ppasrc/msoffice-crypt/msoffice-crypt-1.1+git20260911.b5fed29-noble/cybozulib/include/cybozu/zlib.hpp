#pragma once
/**
	@file
	@brief zlib compressor and decompressor class

	@author MITSUNARI Shigeo(@herumi)
*/

#include <cybozu/stream.hpp>
#include <cybozu/endian.hpp>
#include <assert.h>
#include <stdio.h>
#include <zlib.h>

#ifdef _MSC_VER
	#ifdef _DLL_CPPLIB
		#pragma comment(lib, "zlib_md.lib")
	#else
		#pragma comment(lib, "zlib_mt.lib")
	#endif
#endif

namespace cybozu {

namespace zlib_local {

const int DEF_MEM_LEVEL = 8;

inline const char *safePtr(const char *str)
{
	return str ? str : "unknown";
}

} // zlib_local

/**
	zlib compressor class
	OutputStream must have size_t write(const char *buf, size_t size);
*/
template<class OutputStream, size_t maxBufSize = 2048>
class ZlibCompressorT {
	OutputStream& os_;
	unsigned int crc_;
	unsigned int totalSize_; /* mod 2^32 */
	z_stream z_;
	char buf_[maxBufSize];
	bool isFlushCalled_;
	const bool useGzip_;
	ZlibCompressorT(const ZlibCompressorT&);
	void operator=(const ZlibCompressorT&);
public:
	/**
		@param os [in] output stream
		@param useGzip [in] useGzip if true, use deflate if false
		@note useGzip option is not fully tested, so default off
	*/
	ZlibCompressorT(OutputStream& os, bool useGzip = false, int compressionLevel = Z_DEFAULT_COMPRESSION)
		: os_(os)
		, crc_(crc32(0L, Z_NULL, 0))
		, totalSize_(0)
		, isFlushCalled_(false)
		, useGzip_(useGzip)
	{
		z_.zalloc = Z_NULL;
		z_.zfree = Z_NULL;
		z_.opaque = Z_NULL;
		if (useGzip_) {
			if (deflateInit2(&z_, compressionLevel, Z_DEFLATED, -MAX_WBITS, zlib_local::DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
				throw cybozu::Exception("zlib:ZlibCompressorT:deflateInit2") << zlib_local::safePtr(z_.msg);
			}
			char header[] = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"; /* OS_CODE = 0x03(Unix) */
			write_os(header, 10);
		} else {
			if (deflateInit(&z_, compressionLevel) != Z_OK) {
				throw cybozu::Exception("zlib:ZlibCompressorT:deflateInit") << zlib_local::safePtr(z_.msg);
			}
		}
	}
	~ZlibCompressorT()
	{
		if (!isFlushCalled_) {
			try {
				flush();
			} catch (std::exception& e) {
				fprintf(stderr, "zlib:ZlibCompressor:flush:exception:%s\n", e.what());
			} catch (...) {
				fprintf(stderr, "zlib:ZlibCompressor:flush:unknown exception\n");
			}
		}
		deflateEnd(&z_);
	}
	/*
		compress buf
		@param buf [in] input data
		@param size [in] input data size
	*/
	void write(const void *buf, size_t _size)
	{
		if (_size >= (1u << 31)) throw cybozu::Exception("zlib:ZlibCompressor:write:too large size") << _size;
		uint32_t size = (uint32_t)_size;
		if (useGzip_) {
			crc_ = crc32(crc_, (const Bytef *)buf, size);
			totalSize_ += (unsigned int)size;
		}
		z_.next_in = (Bytef*)const_cast<char*>((const char*)buf);
		z_.avail_in = size;
		while (z_.avail_in > 0) {
			z_.next_out = (Bytef*)buf_;
			z_.avail_out = maxBufSize;

			int ret = deflate(&z_, Z_NO_FLUSH);
			if (ret != Z_STREAM_END && ret != Z_OK) {
				throw cybozu::Exception("zlib:ZlibCompressor:exec:compress") << zlib_local::safePtr(z_.msg);
			}
			write_os(buf_, maxBufSize - z_.avail_out);
			if (ret == Z_STREAM_END) break;
		}
	}
	void flush()
	{
		if (isFlushCalled_) return;
		isFlushCalled_ = true;
		z_.next_in = 0;
		z_.avail_in = 0;

		for (;;) {
			z_.next_out = (Bytef*)buf_;
			z_.avail_out = maxBufSize;

			int ret = deflate(&z_, Z_FINISH);
			if (ret != Z_STREAM_END && ret != Z_OK) {
				throw cybozu::Exception("zlib:ZlibCompressor:flush") << zlib_local::safePtr(z_.msg);
			}
			write_os(buf_, sizeof(buf_) - z_.avail_out);
			if (ret == Z_STREAM_END) break;
		}
		if (useGzip_) {
			char tail[8];
			cybozu::Set32bitAsLE(&tail[0], crc_);
			cybozu::Set32bitAsLE(&tail[4], totalSize_);
			write_os(tail, sizeof(tail));
		}
	}
private:
	void write_os(const char *buf, size_t size)
	{
		cybozu::OutputStreamTag<OutputStream>::write(os_, buf, size);
	}
};

/**
	zlib decompressor class
	InputStream must have size_t read(char *str, size_t size);
*/
template<class InputStream, size_t maxBufSize = 2048>
class ZlibDecompressorT {
	InputStream& is_;
	unsigned int crc_;
	unsigned int totalSize_; /* mod 2^32 */
	z_stream z_;
	int ret_;
	char buf_[maxBufSize];
	const bool useGzip_;
	bool readGzipHeader_;
	void readAll(char *buf, size_t size)
	{
		cybozu::read(buf, size, is_);
	}
	void skipToZero()
	{
		for (;;) {
			char buf[1];
			readAll(buf, 1);
			if (buf[0] == '\0') break;
		}
	}
	void skip(int size)
	{
		for (int i = 0 ; i < size; i++) {
			char buf[1];
			readAll(buf, 1);
		}
	}
	void readGzipHeader()
	{
		char header[10];
		readAll(header, sizeof(header));
		enum {
			FHCRC = 1 << 1,
			FEXTRA = 1 << 2,
			FNAME = 1 << 3,
			FCOMMENT = 1 << 4,
			RESERVED = 7 << 5,
		};
		char flg = header[3];
		if (header[0] == '\x1f'
			&& header[1] == '\x8b'
			&& header[2] == Z_DEFLATED
			&& !(flg & RESERVED)) {
			if (flg & FEXTRA) {
				char xlen[2];
				readAll(xlen, sizeof(xlen));
				int size = cybozu::Get16bitAsLE(xlen);
				skip(size);
			}
			if (flg & FNAME) {
				skipToZero();
			}
			if (flg & FCOMMENT) {
				skipToZero();
			}
			if (flg & FHCRC) {
				skip(2);
			}
			return;
		}
		throw cybozu::Exception("zlib:ZlibDecompressorT:readGzipHeader:bad gzip header") << std::string(header, 10);
	}
	ZlibDecompressorT(const ZlibDecompressorT&);
	void operator=(const ZlibDecompressorT&);
public:
	/**
		@param os [in] input stream
		@param useGzip [in] useGzip if true, use deflate if false
		@note useGzip option is not fully tested, so default off
	*/
	ZlibDecompressorT(InputStream& is, bool useGzip = false)
		: is_(is)
		, crc_(crc32(0L, Z_NULL, 0))
		, totalSize_(0)
		, ret_(Z_OK)
		, useGzip_(useGzip)
		, readGzipHeader_(false)
	{
		z_.zalloc = Z_NULL;
		z_.zfree = Z_NULL;
		z_.opaque = Z_NULL;
		z_.next_in = 0;
		z_.avail_in = 0;
		if (useGzip_) {
			if (inflateInit2(&z_, -MAX_WBITS) != Z_OK) {
				throw cybozu::Exception("zlib:ZlibDecompressorT:inflateInit2") << zlib_local::safePtr(z_.msg);
			}
		} else {
			if (inflateInit(&z_) != Z_OK) {
				throw cybozu::Exception("zlib:ZlibDecompressorT:inflateInit") << zlib_local::safePtr(z_.msg);
			}
		}
	}
	~ZlibDecompressorT()
	{
		inflateEnd(&z_);
	}
	/*
		decompress is
		@param str [out] decompressed data
		@param str [out] max buf size
		@return read size
	*/
	size_t readSome(void *buf, size_t _size)
	{
		if (_size >= (1u << 31)) throw cybozu::Exception("zlib:ZlibDecompressorT:readSome:too large size") << _size;
		uint32_t size = (uint32_t)_size;
		if (useGzip_ && !readGzipHeader_) {
			readGzipHeader();
			readGzipHeader_ = true;
		}
		z_.next_out = (Bytef*)buf;
		z_.avail_out = size;
		do {
			if (z_.avail_in == 0) {
				z_.avail_in = (uint32_t)cybozu::readSome(buf_, maxBufSize, is_);
				if (ret_ == Z_STREAM_END && z_.avail_in == 0) return 0;
				z_.next_in = (Bytef*)buf_;
			}
			ret_ = inflate(&z_, Z_NO_FLUSH);
			if (ret_ == Z_STREAM_END) break;
			if (ret_ != Z_OK) {
				throw cybozu::Exception("zlib:ZlibDecompressorT:readSome:inflate") << zlib_local::safePtr(z_.msg);
			}
		} while (size == z_.avail_out);

		return size - z_.avail_out;
	}
	bool isEmpty() const { return ret_ == Z_STREAM_END; }
	void read(void *buf, size_t size)
	{
		char *p = (char *)buf;
		while (size > 0) {
			size_t readSize = readSome(p, size);
			if (readSize == 0) throw cybozu::Exception("zlib:ZlibDecompressorT:read");
			p += readSize;
			size -= readSize;
		}
	}
};

/*
	compress in[0, inSize) to out
	return 0 if compressed size > maxOutSize
*/
inline size_t ZlibCompress(void *out, size_t maxOutSize, const void *in, size_t inSize, int level = Z_DEFAULT_COMPRESSION)
{
	uLongf outSize = (uLongf)maxOutSize;
	int ret = ::compress2((Bytef*)out, &outSize, (const Bytef*)in, (uLong)inSize, level);
	if (ret == Z_BUF_ERROR) {
		return 0;
	}
	if (ret == Z_OK) {
		return (size_t)outSize;
	}
	throw cybozu::Exception("zlibCompress") << ret << inSize << level;
}

inline size_t ZlibUncompress(void *out, size_t maxOutSize, const void *in, size_t inSize)
{
	uLongf outSize = (uLongf)maxOutSize;
	int ret = ::uncompress((Bytef*)out, &outSize, (const Bytef*)in, (uLong)inSize);
	if (ret == Z_OK) {
		return (size_t)outSize;
	}
	throw cybozu::Exception("zlibUncompress") << ret << maxOutSize << inSize;
}

} // cybozu
