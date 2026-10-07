#pragma once
/**
	@file
	@brief csv reader and write class

	@author MITSUNARI Shigeo(@herumi)
*/

#include <string>
#include <list>
#include <fstream>
#include <cybozu/stream.hpp>

namespace cybozu {

namespace csv_local {

inline bool isValidSeparator(char c)
{
	return c == ',' || c == '\t' || c == ';' || c == ' ';
}

} // csv_local
/**
	CSV reader class
	InputStream must have ssize_t read(char *str, size_t size);
*/
template<class InputStream, size_t MAX_LINE_SIZE = 10 * 1024 * 1024>
class CsvReaderT {
	CsvReaderT(const CsvReaderT&);
	void operator=(const CsvReaderT&);
	typedef cybozu::InputStreamTag<InputStream> In;
public:
	/**
		@param is [in] input stream
		@param sep [in] separator character(comma, tab, semicolon, space)
	*/
	CsvReaderT(InputStream& is, char sep = ',')
		: sep_(sep)
		, is_(is)
		, line_(0)
		, lineSize_(0)
		, pos_(0)
		, bufSize_(0)
		, eof_(false)
	{
		if (!csv_local::isValidSeparator(sep)) {
			throw cybozu::Exception("csv:CsvReaderT:invalid separator") << sep;
		}
	}
	/**
		get one line from InputStream and push_back() into out
		@return false if no data(eof)
		@note out must have push_back(std::string)
		@note string must be UTF-8
		ignore all \x0d
	*/
	template<class Container>
	bool read(Container& out)
	{
		if (eof_) return false;
		line_++;
		out.clear();
		enum {
			Top,
			InQuote,
			SearchSep,
			NeedSepOrQuote
		} state = Top;

		const char CR = '\x0d';
		const char LF = '\x0a';
		const char quote = '"';

		std::string str;
		for (;;) {
			int c = my_getchar();
			if (c == EOF && str.empty()) return false;
			if (c == CR) continue;
			switch (state) {
			case Top:
				if (c == EOF || c == LF) {
					if (!str.empty()) {
						appendAndClear(out, str);
					}
					return true;
				}
				if (c == quote) {
					state = InQuote;
				} else if (c == sep_) {
					appendAndClear(out, str);
				} else {
					addChar(str, c);
					state = SearchSep;
				}
				break;
			case InQuote:
				if (c == EOF) {
					throw cybozu::Exception("csv:read:quote is necessary") << line_ << str;
				}
				if (c == quote) {
					state = NeedSepOrQuote;
				} else {
					addChar(str, c);
				}
				break;
			case NeedSepOrQuote:
				if (c == EOF || c == LF) {
					appendAndClear(out, str);
					return true;
				}
				if (c == quote) {
					addChar(str, quote);
					state = InQuote;
				} else if (c == sep_) {
					appendAndClear(out, str);
					state = Top;
				} else {
					throw cybozu::Exception("csv:read:bad character after quote") << line_ << str << c;
				}
				break;
			case SearchSep:
			default:
				if (c == EOF || c == LF) {
					appendAndClear(out, str);
					return true;
				}
				if (c == sep_) {
					appendAndClear(out, str);
					state = Top;
				} else {
					addChar(str, c);
				}
				break;
			}
		}
	}
private:
	void addChar(std::string& str, int c)
	{
		str += static_cast<char>(c);
		lineSize_++;
		if (lineSize_ == MAX_LINE_SIZE) {
			throw cybozu::Exception("csv:addChar:too large size") << line_ << str << MAX_LINE_SIZE;
		}
	}
	template<class Container>
	void appendAndClear(Container& out, std::string& str)
	{
		out.push_back(str);
		str.clear();
	}
	int my_getchar()
	{
		if (pos_ < bufSize_) {
			return buf_[pos_++];
		}
		bufSize_ = cybozu::readSome(buf_, sizeof(buf_), is_);
		if (bufSize_ > 0) {
			pos_ = 1;
			return buf_[0];
		} else {
			pos_ = 0;
			eof_ = true;
			return EOF;
		}
	}
	char sep_;
	InputStream& is_;
	size_t line_;
	size_t lineSize_;
	char buf_[2048];
	size_t pos_;
	size_t bufSize_;
	bool eof_;
};

/**
	CSV writer class
	OutputStream must have ssize_t write(const char *str, size_t size);
*/
template<class OutputStream>
class CsvWriterT {
	CsvWriterT(const CsvWriterT&);
	void operator=(const CsvWriterT&);
	typedef cybozu::OutputStreamTag<OutputStream> Out;
public:
	/**
		@param os [in] output stream
		@param sep [in] separator character(comma, tab, semicolon, space)
	*/
	CsvWriterT(OutputStream& os, char sep = ',')
		: os_(os)
		, sep_(sep)
	{
		if (!csv_local::isValidSeparator(sep)) {
			throw cybozu::Exception("csv:CsvWriteT:inavlid separator") << sep;
		}
	}
	/**
		make one line from [begin, end) and write it
		@note type of *begin must be std::string
		@note string must be UTF-8
	*/
	template<class Iterator>
	void write(Iterator begin, Iterator end)
	{
		bool isFirst = true;
		while (begin != end) {
			if (isFirst) {
				isFirst = false;
			} else {
				appendSeparator();
			}
			append(*begin);
			++begin;
		}
		appendEndLine();
	}
private:
	void append(const std::string& str)
	{
		std::string out = "\"";
		for (size_t i = 0, n = str.size(); i < n; i++) {
			char c = str[i];
			if (c == '"') {
				out += '"';
			}
			out += c;
		}
		out += "\"";
		writeToStream(&out[0], out.size());
	}
	void appendSeparator()
	{
		writeToStream(&sep_, 1);
	}
	void appendEndLine()
	{
		writeToStream("\x0d\x0a", 2);
	}
	void writeToStream(const char *str, size_t size)
	{
		Out::write(os_, str, size);
	}
	OutputStream& os_;
	char sep_;
};

class CsvReader {
	std::ifstream ifs_;
	cybozu::CsvReaderT<std::ifstream> csv_;
public:
	CsvReader(const std::string& name, char sep = ',')
		: ifs_(name.c_str(), std::ios::binary)
		, csv_(ifs_, sep)
	{
	}
	/**
		get one line from InputStream and push_back() into out
		@return false if no data(eof)
		@note out must have push_back(std::string)
		@note string must be UTF-8
		ignore all \x0d
	*/
	template<class Container>
	bool read(Container& out)
	{
		return csv_.read(out);
	}
};

class CsvWriter {
	std::ofstream ofs_;
	cybozu::CsvWriterT<std::ofstream> csv_;
public:
	CsvWriter(const std::string& name, char sep = ',')
		: ofs_(name.c_str(), std::ios::binary)
		, csv_(ofs_, sep)
	{
	}
	/**
		make one line from [begin, end) and write it
		@note type of *begin must be std::string
		@note string must be UTF-8
	*/
	template<class Iterator>
	void write(Iterator begin, Iterator end)
	{
		csv_.write(begin, end);
	}
};

} // cybozu
