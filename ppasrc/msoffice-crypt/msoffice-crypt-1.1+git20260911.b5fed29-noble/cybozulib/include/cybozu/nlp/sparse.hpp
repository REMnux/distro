#pragma once
/**
	@file
	@brief sparse vector

	@author MITSUNARI Shigeo(@herumi)
	@author MITSUNARI Shigeo
*/
#include <vector>
#include <cybozu/exception.hpp>
#include <cybozu/serializer.hpp>
#include <assert.h>

namespace cybozu { namespace nlp {

namespace option {

class PositionTbl {
	std::vector<unsigned int> v_;
public:
	struct Curr {
		size_t vecPos_;
		Curr(const PositionTbl&)
			: vecPos_(0)
		{
		}
		Curr(size_t vecPos)
			: vecPos_(vecPos)
		{
		}
	};
	void reserve(size_t size)
	{
		v_.reserve(size);
	}
	void set(size_t pos)
	{
		if (!v_.empty() && pos <= v_[v_.size() - 1]) {
			throw cybozu::Exception("SparseException:PositionTbl:set:bad order pos") << pos;
		}
		if (pos > 0xffffffffU) {
			throw cybozu::Exception("SparseException:PositionTbl:set:too large pos") << pos;
		}
		v_.push_back((unsigned int)pos);
	}
	void clear()
	{
		v_.clear();
	}
	void next(Curr& curr) const
	{
		curr.vecPos_++;
	}
	size_t get(const Curr& curr) const
	{
		return v_[curr.vecPos_];
	}
	void swap(PositionTbl& rhs)
	{
		v_.swap(rhs.v_);
	}
};

/*
	max difference between previous position and current position < 0x40000000 = (1 << 30)
	data format
	input x:
	v[0] = (x & 0x3f) | (y << 6) ; len = y + 1 for y = 0, 1, 2, 3
	v[1] = x >> 6
	v[2] = x >> (6 + 8)
	v[3] = x >> (6 + 8 + 8)
*/

class CompressedPositionTbl {
	mutable std::vector<unsigned char> v_;
	size_t lastPos_;
	mutable bool addDummy_; // add last dummy data into v_ to get speed and avoid buffer overrun
	friend struct Curr;
public:
	struct Curr {
		size_t vecPos_;
		size_t val_;
		unsigned int pos_;
		Curr(const CompressedPositionTbl& tbl)
			: vecPos_(0)
			, val_(0)
			, pos_(0)
		{
			if (!tbl.addDummy_) {
				tbl.v_.push_back(0);
				tbl.addDummy_ = true;
			}
			tbl.setup(*this);
		}
		Curr(size_t vecPos)
			: vecPos_(vecPos)
		{
		}
	};
	CompressedPositionTbl()
		: lastPos_(0)
		, addDummy_(false)
	{
	}
	void clear()
	{
		v_.clear();
		lastPos_ = 0;
		addDummy_ = false;
	}
	void reserve(size_t size)
	{
		v_.reserve(size * 2); // ad hoc
	}
	void set(size_t pos)
	{
		if (addDummy_) {
			v_.resize(v_.size() - 1);
			addDummy_ = false;
		}
		if (!v_.empty() && pos <= lastPos_) {
			throw cybozu::Exception("SparseException:CompressedPositionTbl:set:bad order pos") << pos;
		}
		if (pos - lastPos_ >= (1 << 30)) {
			throw cybozu::Exception("SparseException:CompressedPositionTbl:set:too large pos") << pos;
		}
		unsigned int diff = (unsigned int)(pos - lastPos_);
		lastPos_ = pos;
		if (diff < (1 << 6)) {
			v_.push_back((unsigned char)(diff));
		} else if (diff < (1 << 14)) {
			v_.push_back((unsigned char)(diff & 0x3f) | (1 << 6));
			v_.push_back((unsigned char)(diff >> 6));
		} else if (diff < (1 << 22)) {
			v_.push_back((unsigned char)(diff & 0x3f) | (2 << 6));
			v_.push_back((unsigned char)(diff >> 6));
			v_.push_back((unsigned char)(diff >> 14));
		} else {
			assert(diff < (1 << 30));
			v_.push_back((unsigned char)(diff & 0x3f) | (3 << 6));
			v_.push_back((unsigned char)(diff >> 6));
			v_.push_back((unsigned char)(diff >> 14));
			v_.push_back((unsigned char)(diff >> 22));
		}
	}
	void next(Curr& curr) const
	{
		setup(curr);
		curr.vecPos_++;
	}
	size_t get(const Curr& curr) const { return curr.val_; }
	void swap(CompressedPositionTbl& rhs)
	{
		v_.swap(rhs.v_);
		std::swap(lastPos_, rhs.lastPos_);
		std::swap(addDummy_, rhs.addDummy_);
	}
private:
	void setup(Curr& curr) const
	{
		unsigned int diff = v_[curr.pos_];
		unsigned int t = diff >> 6;
		unsigned int pos = curr.pos_;
		if (t > 0) {
			diff &= (1 << 6) - 1;
			if (t == 1) {
				diff |= (v_[pos + 1] << 6);
			} else if (t == 2) {
				diff |= (v_[pos + 1] << 6) | (v_[pos + 2] << 14);
			} else {
				diff |= (v_[pos + 1] << 6) | (v_[pos + 2] << 14) | (v_[pos + 3] << 22);
			}
		}
		curr.val_ += diff;
		curr.pos_ += t + 1;
	}
};

} // cybozu::nlp::option

template<class T, class PosTbl = option::PositionTbl, int dummy = 0>
class SparseVector {
	PosTbl posTbl_;
	std::vector<T> vec_;

	template<class S>
	class ConstIterator {
		typename PosTbl::Curr cur_;
		const SparseVector<S, PosTbl> *self_;
	public:
		// for begin
		ConstIterator(const SparseVector<S, PosTbl>* self)
			: cur_(self->posTbl_)
			, self_(self)
		{
		}
		// for end
		ConstIterator(size_t vecPos)
			: cur_(vecPos)
		{
		}
		size_t pos() const { return self_->posTbl_.get(cur_); }
		S val() const { return (self_->vec_)[cur_.vecPos_]; }

		const ConstIterator *operator->() const { return this; }
		const ConstIterator& operator*() const { return *this; }
		void operator++()
		{
			self_->posTbl_.next(cur_);
		}
		bool operator==(const ConstIterator& rhs) const { return cur_.vecPos_ == rhs.cur_.vecPos_; }
		bool operator!=(const ConstIterator& rhs) const { return !operator==(rhs); }
	};
public:
	typedef ConstIterator<T> const_iterator;
	typedef T value_type;
	SparseVector()
	{
	}
	template<class Map>
	void set(const Map& m)
	{
		reserve(m.size());
		for (typename Map::const_iterator i = m.begin(), ie = m.end(); i != ie; ++i) {
			push_back(i->first, i->second);
		}
	}
	void reserve(size_t size)
	{
		posTbl_.reserve(size);
		vec_.reserve(size);
	}
	void push_back(size_t pos, const T& x)
	{
		posTbl_.set(pos);
		vec_.push_back(x);
	}
	void clear()
	{
		posTbl_.clear();
		vec_.clear();
	}
	const_iterator begin() const { return const_iterator(this); }
	const_iterator end() const { return const_iterator(vec_.size()); }
	size_t size() const { return vec_.size(); }
	bool empty() const { return vec_.empty(); }
	bool operator==(const SparseVector& rhs) const
	{
		if (size() != rhs.size()) return false;
		for (const_iterator i1 = begin(), i2 = rhs.begin(), ie = end(); i1 != ie; ++i1, ++i2) {
			if (i1->pos() != i2->pos()) return false;
			if (i1->val() != i2->val()) return false;
		}
		return true;
	}
	bool operator!=(const SparseVector& rhs) const { return !operator==(rhs); }

	void swap(SparseVector& rhs)
	{
		posTbl_.swap(rhs.posTbl_);
		vec_.swap(rhs.vec_);
	}
	double norm() const
	{
		double ret = 0;
		for (const_iterator i = begin(), ie = end(); i != ie; ++i) {
			double v = i->val();
			ret += v * v;
		}
		return ret;
	}
	template<class InputStream>
	void load(InputStream& is)
	{
		size_t size;
		cybozu::load(size, is);
		clear();
		reserve(size);
		for (size_t i = 0; i < size; i++) {
			size_t pos;
			T val;
			cybozu::load(pos, is);
			cybozu::load(val, is);
			push_back(pos, val);
		}
	}

	template<class OutputStream>
	void save(OutputStream& os) const
	{
		cybozu::save(os, size());
		for (const_iterator i = begin(), ie = end(); i != ie; ++i) {
			cybozu::save(os, i->pos());
			cybozu::save(os, i->val());
		}
	}
};

template<class V1, class V2>
class Intersection {
	Intersection(const Intersection&);
	void operator=(const Intersection&);
	const V1& v1_;
	const V2& v2_;

	template<class S1, class S2>
	class ConstIterator {
		typename S1::const_iterator begin1_;
		typename S1::const_iterator end1_;
		typename S2::const_iterator begin2_;
		typename S2::const_iterator end2_;
		bool isEnd_;
	public:
		ConstIterator(typename S1::const_iterator begin1, typename S1::const_iterator end1, typename S2::const_iterator begin2, typename S2::const_iterator end2, bool isEnd)
			: begin1_(begin1)
			, end1_(end1)
			, begin2_(begin2)
			, end2_(end2)
			, isEnd_(isEnd)
		{
			if (isEnd_) return;
			isEnd_ = begin1_ == end1_ || begin2_ == end2_;
			if (isEnd_) return;
			if (begin1_->pos() != begin2_->pos()) {
				operator++();
			}
		}
		size_t pos() const { return begin1_->pos(); }
		typename S1::value_type val1() const { return begin1_->val(); }
		typename S2::value_type val2() const { return begin2_->val(); }

		const ConstIterator *operator->() const { return this; }
		const ConstIterator& operator*() const { return *this; }
		void operator++()
		{
			if (isEnd_) return;
			if (begin1_->pos() == begin2_->pos()) {
				++begin1_;
				isEnd_ = begin1_ == end1_;
				if (isEnd_) return;
			}
			for (;;) {
				while (begin1_->pos() < begin2_->pos()) {
					++begin1_;
					if (begin1_ == end1_) {
						isEnd_ = true;
						return;
					}
				}
				if (begin1_->pos() == begin2_->pos()) return;

				while (begin1_->pos() > begin2_->pos()) {
					++begin2_;
					if (begin2_ == end2_) {
						isEnd_ = true;
						return;
					}
				}
				if (begin1_->pos() == begin2_->pos()) return;
			}
		}
		bool operator==(const ConstIterator&) const { return isEnd_ == true; }
		bool operator!=(const ConstIterator& rhs) const { return !operator==(rhs); }
	};
public:
	typedef ConstIterator<V1, V2> const_iterator;
	Intersection(const V1& v1, const V2& v2)
		: v1_(v1)
		, v2_(v2)
	{
	}
	const_iterator begin() const { return const_iterator(v1_.begin(), v1_.end(), v2_.begin(), v2_.end(), false); }
	const_iterator end() const { return const_iterator(v1_.begin(), v1_.end(), v2_.begin(), v2_.end(), true); }
};

template<class V1, class V2>
class Union {
	Union(const Union&);
	void operator=(const Union&);
	const V1& v1_;
	const V2& v2_;

	template<class S1, class S2>
	class ConstIterator {
	public:
		/*
				 pos1 pos2 ; next action
			End   x	x   ; end
			Only1 o	x   ; ++p1
			Only2 x	o   ; ++p2
			Small o <  o   ; ++p1
			Equal o =  o   ; ++p1, ++p2
			Large o >  o   ; ++p2
		*/
		enum Mode {
			End,
			Only1,
			Only2,
			Small,
			Equal,
			Large
		};
	private:
		typename S1::const_iterator begin1_;
		typename S1::const_iterator end1_;
		typename S2::const_iterator begin2_;
		typename S2::const_iterator end2_;
		Mode mode_;
		size_t pos_;

		void detectMode()
		{
			if (begin1_ != end1_) {
				const size_t pos1 = begin1_->pos();
				if (begin2_ != end2_) {
					size_t pos2 = begin2_->pos();
					if (pos1 < pos2) {
						mode_ = Small;
						pos_ = pos1;
					} else if (pos1 == pos2) {
						mode_ = Equal;
						pos_ = pos1;
					} else {
						mode_ = Large;
						pos_ = pos2;
					}
				} else {
					mode_ = Only1;
					pos_ = pos1;
				}
			} else {
				if (begin2_ != end2_) {
					mode_ = Only2;
					pos_ = begin2_->pos();
				} else {
					mode_ = End;
				}
			}
		}
	public:
		ConstIterator(typename S1::const_iterator begin1, typename S1::const_iterator end1, typename S2::const_iterator begin2, typename S2::const_iterator end2, bool isEnd)
			: begin1_(begin1)
			, end1_(end1)
			, begin2_(begin2)
			, end2_(end2)
			, mode_(End)
			, pos_(0)
		{
			if (isEnd) return;
			detectMode();
		}
		Mode getMode() const { mode_; }
		size_t pos() const { return pos_; }
		bool hasVal1() const { return mode_ == Only1 || mode_ == Small || mode_ == Equal; }
		bool hasVal2() const { return mode_ == Only2 || mode_ == Equal || mode_ == Large; }

		/**
			return value if exists otherwise 0
		*/
		typename S1::value_type val1() const { return hasVal1() ? begin1_->val() : 0; }
		typename S2::value_type val2() const { return hasVal2() ? begin2_->val() : 0; }

		const ConstIterator *operator->() const { return this; }
		const ConstIterator& operator*() const { return *this; }
		void operator++()
		{
			if (mode_ == End) return;
			switch (mode_) {
			case Only1:
			case Small:
			case Equal:
				++begin1_;
				break;
			default:
				break;
			}
			switch (mode_) {
			case Only2:
			case Equal:
			case Large:
				++begin2_;
				break;
			default:
				break;
			}
			detectMode();
		}
		bool operator==(const ConstIterator& rhs) const { return mode_ == rhs.mode_; }
		bool operator!=(const ConstIterator& rhs) const { return !operator==(rhs); }
	};
public:
	typedef ConstIterator<V1, V2> const_iterator;
	Union(const V1& v1, const V2& v2)
		: v1_(v1)
		, v2_(v2)
	{
	}
	const_iterator begin() const { return const_iterator(v1_.begin(), v1_.end(), v2_.begin(), v2_.end(), false); }
	const_iterator end() const { return const_iterator(v1_.begin(), v1_.end(), v2_.begin(), v2_.end(), true); }
};

/**
	inner product of lhs and rhs
	retval is the type of lhs::value_type or rhs::value_type
*/
template<class Ret, class L, class Ltbl, class R, class Rtbl>
void InnerProduct(Ret *pret, const SparseVector<L, Ltbl>& lhs, const SparseVector<R, Rtbl>& rhs)
{
	typedef SparseVector<L, Ltbl> Lvec;
	typedef SparseVector<R, Rtbl> Rvec;

	Ret ret = 0;
	if ((const void*)&lhs == (const void*)&rhs) {
		for (typename Lvec::const_iterator i = lhs.begin(), ie = lhs.end(); i != ie; ++i) {
			ret += (Ret)i->val() * (Ret)i->val();
		}
	} else {
		typedef Intersection<Lvec, Rvec> Inter;
		Inter inter(lhs, rhs);
		for (typename Inter::const_iterator i = inter.begin(), ie = inter.end(); i != ie; ++i) {
			ret += (Ret)i->val1() * (Ret)i->val2();
		}
	}
	*pret = ret;
}

} // cybozu::nlp

} // cybozu
