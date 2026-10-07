#pragma once
/**
	@file
	@brief a class to get top n score
	@author MITSUNARI Shigeo(@herumi)
*/
#include <vector>

namespace cybozu { namespace nlp {

/*
	T is int, size_t or pointer to object
*/
template<class T, class Double = double>
class TopScore {
public:
	struct Pair {
		Double score;
		T idx;
	};
	typedef std::vector<Pair> Table;
private:
	size_t maxSize_;
	size_t size_;
	mutable Table tbl_;
	TopScore(const TopScore&);
	void operator=(const TopScore&);
public:
	explicit TopScore(size_t maxSize = 10)
		: maxSize_(maxSize)
		, size_(0)
	{
		tbl_.resize(maxSize_);
	}
	void setSize(size_t maxSize)
	{
		maxSize_ = maxSize;
		size_ = 0;
		tbl_.clear();
	}
	void add(Double score, T idx)
	{
		// short cut
		if (size_ == maxSize_ && score <= tbl_[size_ - 1].score) {
			return;
		}
		int pos = -1;
		if (size_ > 0) {
			for (size_t i = 0; i < size_; i++) {
				if (score > tbl_[i].score) {
					int end = (int)std::min(maxSize_ - 2, size_ - 1);
					for (int j = end; j >= (int)i; j--) {
						tbl_[j + 1] = tbl_[j];
					}
					pos = (int)i;
					break;
				}
			}
		}
		if (size_ < maxSize_) {
			if (pos < 0) pos = (int)size_;
			size_++;
		}
		if (pos == -1) return;
		tbl_[pos].score = score;
		tbl_[pos].idx = idx;
	}
	const Table& getTable() const
	{
		tbl_.resize(size_);
		return tbl_;
	}
};

} } // cybozu::nlp
