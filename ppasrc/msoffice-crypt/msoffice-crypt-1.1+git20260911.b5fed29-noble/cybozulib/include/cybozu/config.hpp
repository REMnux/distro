#pragma once
/**
	@file
	@brief config file class

	@author MITSUNARI Shigeo(@herumi)
*/

#include <assert.h>
#include <string>
#include <map>
#include <fstream>
#include <cybozu/exception.hpp>
#include <cybozu/atoi.hpp>

namespace cybozu {

namespace config_local {

inline bool isName(const std::string& str, char *badChar)
{
	for (size_t i = 0, n = str.size(); i < n; i++) {
		char c = str[i];
		if (!('0' <= c && c <= '9')
			&& !('a' <= c && c <= 'z')
			&& !('A' <= c && c <= 'Z')
			&& c != '_') {
			*badChar = c;
			return false;
		}
	}
	return true;
}

inline void trimEndSpace(std::string& str)
{
	if (str.empty()) return;
	size_t i = str.size();
	while (i > 0) {
		char c = str[i - 1];
		if (c == ' ' || c == '\t') {
			i--;
		} else {
			break;
		}
	}
	return str.resize(i);
}

inline void split(std::string& key, std::string& value, const std::string& line)
{
	const char *p = line.c_str();
	const char *q = strchr(p, '=');
	if (q == 0) {
		throw cybozu::Exception("config:split:no equal") << line;
	}
	key = line.substr(0, q - p);
	trimEndSpace(key);
	char badChar;
	if (!cybozu::config_local::isName(key, &badChar)) {
		throw cybozu::Exception("config:split:bad key") << key << badChar;
	}
	const size_t valueTop = q + 1 - p;
	value = line.substr(valueTop, line.size() - valueTop);
}

} // config_local

/**
	config class
	config format is the following
	<pre>
	CF = "\r\n" | "\n"
	NAME = [0-9a-zA-Z_]+
	VALUE = [^\\r\\n]*
	LINE = (EMPTY | COMMENT | SECTION | KEY_VALUE) CF
	EMPTY = ""
	COMMENT = "[;#]" [^\\r\\n]*
	SECTION = "[" NAME "]"
	SP = [ \t]
	KEY_VALUE = NAME SP* "=" VALUE
	</pre>
	how to use Config
	<pre>
		using namespace cybozu;
		Config config;
		config.load("config.ini");
		Config::Section *section = config.querySection("db");
		if (section) {
			const std::string *value = section->queryValue("name");
			std::cout << "name:" << *value << std::endl;
		}
	</pre>
*/
class Config {
public:
	/**
		section class
	*/
	class Section {
		// auto converter to integer or string
		class ResultType {
			const std::string& str_;
			const std::string& key_;
			void operator=(const ResultType&);
			template<typename T>
			T get() const
			{
				bool b;
				T t = cybozu::atoi(&b, str_);
				if (!b) {
					throw cybozu::Exception("config:get:bad integer") << str_ << key_;
				}
				return t;
			}
		public:
			ResultType(const std::string& str, const std::string& key)
				: str_(str)
				, key_(key)
			{
			}
			operator short() const { return get<short>(); }
			operator unsigned short() const { return get<unsigned short>(); }
			operator int() const { return get<int>(); }
			operator unsigned int() const { return get<unsigned int>(); }
			operator int64_t() const { return get<int64_t>(); }
			operator uint64_t() const { return get<uint64_t>(); }
			operator const std::string&() const { return str_; }
		};
		template<typename T>
		T getValueInteger(const std::string& key, T defaultValue) const
		{
			const std::string *value = queryValue(key);
			if (value) {
				bool b;
				T t = cybozu::atoi(&b, *value);
				if (!b) {
					throw cybozu::Exception("config:getValueInteger:bad integer") << *value << key;
				}
				return t;
			} else {
				return defaultValue;
			}
		}
	public:
		typedef std::map<std::string, std::string> Map;
		/**
			append a pair of (key, value)
			@param key [in] key
			@param value [in] value
		*/
		void append(const std::string& key, const std::string& value)
		{
			char badChar;
			if (!config_local::isName(key, &badChar)) {
				throw cybozu::Exception("config:append:bad key") << key << badChar;
			}
			std::pair<Map::iterator, bool> ret = map_.insert(Map::value_type(key, value));
			if (!ret.second) {
				throw cybozu::Exception("config:append:key already exists") << key;
			}
		}
		/**
			query key
			@param key [in] key
			@retval 0 not found
			@retval !0 pointer to value
		*/
		const std::string *queryValue(const std::string& key) const
		{
			Map::const_iterator i = map_.find(key);
			return i != map_.end() ? &(i->second) : 0;
		}
		/**
			get key if key exists
			@param key [in] key
			@retval value
			@note throw exception if not found
		*/
		Section::ResultType getValue(const std::string& key) const
		{
			const std::string *value = queryValue(key);
			if (value) {
				return Section::ResultType(*value, key);
			} else {
				throw cybozu::Exception("config:getValue") << key;
			}
		}
		/**
			get key if key exists or use default
			@param key [in] key
			@param defaultValue [in] default Value
			@retval value
			@note throw exception if not found
		*/
		short getValue(const std::string& key, short defaultValue) const
		{
			return getValueInteger<short>(key, defaultValue);
		}
		unsigned short getValue(const std::string& key, unsigned short defaultValue) const
		{
			return getValueInteger<unsigned short>(key, defaultValue);
		}
		int getValue(const std::string& key, int defaultValue) const
		{
			return getValueInteger<int>(key, defaultValue);
		}
		unsigned int getValue(const std::string& key, unsigned int defaultValue) const
		{
			return getValueInteger<unsigned int>(key, defaultValue);
		}
		int64_t getValue(const std::string& key, int64_t defaultValue) const
		{
			return getValueInteger<int64_t >(key, defaultValue);
		}
		uint64_t getValue(const std::string& key, uint64_t defaultValue) const
		{
			return getValueInteger<uint64_t >(key, defaultValue);
		}
		const std::string& getValue(const std::string& key, const std::string& defaultValue) const
		{
			const std::string *value = queryValue(key);
			if (value) {
				return *value;
			} else {
				return defaultValue;
			}
		}

		/**
			convert section to string
		*/
		std::string toString() const
		{
			std::string ret;
			for (Map::const_iterator i = map_.begin(), ie = map_.end(); i != ie; ++i) {
				ret += i->first + "=" + i->second + "\n";
			}
			return ret;
		}
		/**
			get map
		*/
		const Config::Section::Map& getMap() const { return map_; }
	private:
		Map map_;
	};
	typedef std::map<std::string, Section> Map;
	Config()
	{
	}
	/**
		constructor with loading config file
		@param name [in] config file name
	*/
	explicit Config(const std::string& name)
	{
		load(name);
	}
	/**
		append empty Section named as name
		@param name [in] section name
		@return pointer to section
	*/
	Config::Section* appendSection(const std::string& name)
	{
		char badChar;
		if (!config_local::isName(name, &badChar)) {
			throw cybozu::Exception("config:appendSection:bad section") << name << badChar;
		}
		std::pair<Map::iterator, bool> ret = map_.insert(Map::value_type(name, Section()));
		return &ret.first->second;
	}
	/**
		append section
		@param name [in] section name
		@param section [in] section data
	*/
	cybozu::Config& appendSection(const std::string& name, const cybozu::Config::Section& section)
	{
		*appendSection(name) = section;
		return *this;
	}
	/**
		query const section
		@param name [in] section name
		@retval 0 not found
		@retval !0 pointer to section
	*/
	const Config::Section* querySection(const std::string& name) const
	{
		Map::const_iterator i = map_.find(name);
		return (i != map_.end()) ? &(i->second) : 0;
	}
	/**
		query section
		@param name [in] section name
		@retval 0 not found
		@retval !0 pointer to section
	*/
	Config::Section* querySection(const std::string& name)
	{
		return const_cast<Config::Section*>(static_cast<const Config*>(this)->querySection(name));
	}
	/**
		get const section
		@param name [in] section name("" means global section)
		@return section
		@note throw exception if not found
	*/
	const Config::Section& getSection(const std::string& name = "") const
	{
		const Config::Section *section = querySection(name);
		if (section) {
			return *section;
		} else {
			throw cybozu::Exception("config:getSection:no section") << name;
		}
	}
	/**
		load config file
		@param name [in] config file name
	*/
	void load(const std::string& name)
	{
		std::ifstream ifs(name.c_str());
		if (!ifs) {
			throw cybozu::Exception("config:load") << name;
		}
		load(ifs);
	}
	/**
		load config file
		@param is [in] istream
	*/
	void load(std::istream& is)
	{
		Config::Section *section = appendSection(""); // global section
		assert(section);

		std::string line;
		while (std::getline(is, line)) {
			size_t n = line.size();

			if (n == 0) continue; // skip if empty

			// remove '\r' at the end of line
			char c = line[n - 1];
			if (c == '\r') {
				if (n == 1) continue;
				line.resize(n - 1);
				n--;
			}
			// skip if comment
			c = line[0];
			if (c == ';' || c == '#') continue;
			// section
			if (c == '[') {
				if (line[n - 1] != ']') {
					throw cybozu::Exception("config:load:bad section") << line;
				}
				section = appendSection(line.substr(1, n - 2));
				continue;
			}
			std::string key, value;
			config_local::split(key, value, line);
			section->append(key, value);
		}
	}
	/**
		get map
	*/
	const Config::Map& getMap() const { return map_; }
	/**
		convert section to string
	*/
	std::string toString() const
	{
		std::string ret;
		for (Map::const_iterator i = map_.begin(), ie = map_.end(); i != ie; ++i) {
			if (!i->first.empty()) {
				ret += "[" + i->first + "]\n";
			}
			ret += i->second.toString();
		}
		return ret;
	}
private:
	Map map_;
};

} // end of cybozu
