/*
	how to serialize user data
*/
#include <stdio.h>
#include <cybozu/file.hpp>
#include <cybozu/serializer.hpp>
#include <cybozu/mmap.hpp>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <cybozu/string.hpp>

struct Data {
	typedef std::map<std::string, double> Str2Double;
	typedef std::set<int> IntSet;
	typedef std::vector<float> FloatVec;
	typedef std::vector<cybozu::String> StrVec;
	Str2Double sd_;
	IntSet is_;
	FloatVec fv_;
	StrVec sv_;
	bool operator==(const Data& rhs) const
	{
		return sd_ == rhs.sd_ && is_ == rhs.is_ && fv_ == rhs.fv_ && sv_ == rhs.sv_;
	}
	/*
		define load and save function
	*/
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(sd_, is);
		cybozu::load(is_, is);
		cybozu::load(fv_, is);
		cybozu::load(sv_, is);
	}
	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, sd_);
		cybozu::save(os, is_);
		cybozu::save(os, fv_);
		cybozu::save(os, sv_);
	}
};

struct Data2 {
	Data d;
	int a;
	bool operator==(const Data2& rhs) const
	{
		return d == rhs.d && a == rhs.a;
	}
	template<class InputStream>
	void load(InputStream& is)
	{
		cybozu::load(d, is);
		cybozu::load(a, is);
	}
	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, d);
		cybozu::save(os, a);
	}
};

/*
	how to make InputStream
	InputStream must have size_t readSome(void *, size_t)
	return read size
*/
struct VecInputStream {
	std::vector<char> data;
	size_t pos;
	VecInputStream() : pos(0) {}

	size_t readSome(void *buf, size_t size)
	{
		size_t readSize = std::min(size, data.size() - pos);
		memcpy(buf, &data[pos], readSize);
		pos += readSize;
		return readSize;
	}
};

/*
	how to make OutputStream
	OutputStream must have void write(const void *, size_t)
*/
struct VecOutputStream {
	std::vector<char> data;
	void write(const void *buf, size_t size)
	{
		data.insert(data.end(), (const char*)buf, (const char*)buf + size);
	}
};

/*
	VecInputStream2 does not have readSome() then
	specialize cybozu::InputStreamTag<VecInputStream2>
*/
struct VecInputStream2 {
	std::vector<char> data;
	size_t pos;
	VecInputStream2() : pos(0) {}

	size_t readSome(void *buf, size_t size)
	{
		size_t readSize = std::min(size, data.size() - pos);
		memcpy(buf, &data[pos], readSize);
		pos += readSize;
		return readSize;
	}
};

namespace cybozu {
template<>
struct InputStreamTag<VecInputStream2>
{
	static size_t readSome(void *buf, size_t size, VecInputStream2& is)
	{
		return is.readSome(buf, size);
	}
};
} // cybozu

int main()
{
	const char *file = "test.data";
	Data x;
	x.sd_["abc"] = 9.3;
	x.sd_["999"] = -123459.3;
	x.sd_["AAAA"] = 7;
	x.is_.insert(5);
	x.is_.insert(55);
	x.is_.insert(555);
	x.is_.insert(5555);
	x.fv_.push_back(9.2);
	x.fv_.push_back(-0.1);
	x.sv_.push_back("aiueo");
	x.sv_.push_back("xxx");
	x.sv_.push_back("doremi");

	// save data by std::ofstream
	{
		std::ofstream os(file, std::ios::binary);
		cybozu::save(os, x);
	}
	// load data from std::ifstream
	{
		std::ifstream is(file, std::ios::binary);

		Data y;
		cybozu::load(y, is);
		puts(x == y ? "ok" : "ng");
	}
	Data2 x2;
	x2.d = x;
	x2.d.sd_["aaaaa"] = 1.2;
	x2.a = 98765432;
	// save data by cybozu::File
	{
		cybozu::File os(file, std::ios::out);
		cybozu::save(os, x2);
	}
	// load data from cybozu::Mmap
	{
		cybozu::Mmap m(file);
		cybozu::MemoryInputStream is(m.get(), m.size());

		Data2 y2;
		cybozu::load(y2, is);
		puts(x2 == y2 ? "ok" : "ng");
	}
	// how to use VecInputStream and VecOutputStream
	{
		VecOutputStream os;
		cybozu::save(os, x2);
		{
			VecInputStream is;
			is.data = os.data;
			Data2 y2;
			cybozu::load(y2, is);
			puts(x2 == y2 ? "ok" : "ng");
		}
		{
			VecInputStream2 is;
			is.data = os.data;
			Data2 y2;
			cybozu::load(y2, is);
			puts(x2 == y2 ? "ok" : "ng");
		}
	}
}
