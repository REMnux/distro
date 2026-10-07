#pragma once
/**
	@file
	@brief json parser

	@author MITSUNARI Shigeo(@herumi)
*/
#include <assert.h>
#include <vector>
#include <map>
#include <cybozu/exception.hpp>

namespace cybozu {

class Json {
public:
	enum Type {
		T_Null,
		T_String,
		T_Object,
		T_Array,
		T_Number,
		T_Bool
	};
	struct Object;
	struct Array;
	struct Value {
		Type type_;
		union {
			std::string *str_;
			Object *obj_;
			Array *arr_;
			bool b_;
			double num_;
			uint64_t ptn_;
		};
		Value() : type_(T_Null), ptn_(0) {}
		~Value()
		{
			switch (type_) {
			case T_String: delete str_; break;
			case T_Object: delete obj_; break;
			case T_Array: delete arr_; break;
			}
		}
		explicit Value(double num)
			: type_(T_Number)
		{
			num_ = num;
		}
		explicit Value(const std::string& str)
			: type_(T_String)
		{
			str_ = new std::string(str);
		}
		explicit Value(const char *str)
			: type_(T_String)
		{
			str_ = new std::string(str);
		}
		explicit Value(bool b)
			: type_(T_Bool)
		{
			b_ = b;
		}
		explicit Value(const Array& arr)
			: type_(T_Array)
		{
			arr_ = new Array(arr);
		}
		explicit Value(const Object& obj)
			: type_(T_Object)
		{
			obj_ = new Object(obj);
		}
		void swap(Value& rhs) CYBOZU_NOEXCEPT
		{
			std::swap(type_, rhs.type_);
			std::swap(ptn_, rhs.ptn_);
		}
		Value(const Value& rhs)
			: type_(rhs.type_)
		{
			switch (type_) {
			case T_Null: ptn_ = 0; break;
			case T_String: str_ = new std::string(*rhs.str_); break;
			case T_Object: obj_ = new Object(*rhs.obj_); break;
			case T_Array: arr_ = new Array(*rhs.arr_); break;
			case T_Number: num_ = rhs.num_; break;
			case T_Bool: b_ = rhs.b_; break;
			}
		}
		bool isNull() const { return type_ == T_Null; }
		bool isString() const { return type_ == T_String; }
		bool isObject() const { return type_ == T_Object; }
		bool isArray() const { return type_ == T_Array; }
		bool isBool() const { return type_ == T_Bool; }
		bool isNumber() const { return type_ == T_Number; }

		const std::string& getString() const { assert(isString()); return *str_; }
		const Object& getObject() const { assert(isObject()); return *obj_; }
		const Array& getArray() const { assert(isArray()); return *arr_; }
		bool getBool() const { assert(isBool()); return b_; }
		double getNumber() const { assert(isNumber()); return num_; }

		Value& operator=(const Value& rhs)
		{
			Value tmp(rhs);
			swap(tmp);
			return *this;
		}
	};
	struct Object : std::map<std::string, Value> {
	};
	struct Array : std::vector<Value> {
	};
};


} // cybozu
