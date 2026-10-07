#pragma once
/**
	@file
	@brief TF-IDF

	@author MITSUNARI Shigeo(@herumi)
*/
#include <set>
#include <map>
#include <string>
#include <stdio.h>
#include <cybozu/string_operation.hpp>
#include <cybozu/nlp/sparse.hpp>

namespace cybozu { namespace nlp {

struct Str2Int : std::map<std::string, int> {
	void put() const
	{
		for (const_iterator i = begin(), ie = end(); i != ie; ++i) {
			printf("%s:%d\n", i->first.c_str(), i->second);
		}
	}
};
struct Int2Int : std::map<int, int> {
	void put() const
	{
		for (const_iterator i = begin(), ie = end(); i != ie; ++i) {
			printf("%d:%d ", i->first, i->second);
		}
		printf("\n");
	}
};
struct StrVec : std::vector<std::string> {
	void put() const
	{
		for (size_t i = 0, n = size(); i < n; i++) {
			printf("%d:%s\n", (int)i, (*this)[i].c_str());
		}
	}
};
typedef std::vector<double> DoubleVec;
typedef std::vector<Int2Int> Int2IntVec;
typedef std::set<std::string> StrSet;
typedef cybozu::nlp::SparseVector<double> DoubleSvec;
typedef std::vector<DoubleSvec> DoubleSvecVec;
typedef std::vector<int> IntVec;

struct Df {
	struct Pair {
		int id;
		int freq;
		Pair(int _id = 0, int _freq = 0) : id(_id), freq(_freq) { }
		bool operator<(const Pair& rhs) const { return freq < rhs.freq; }
	};
	typedef std::vector<Pair> PairVec;
	int docNum_;
	Str2Int word2id_;
	StrVec id2word_;
	IntVec df_;
	StrSet set_; // for one doc
	PairVec pv_;
	Df()
		: docNum_(0)
	{
	}
	void append(const std::string& word)
	{
		std::string lower;
		cybozu::ToLower(lower, word);
		std::pair<Str2Int::iterator, bool> ret = word2id_.insert(Str2Int::value_type(lower, (int)id2word_.size()));
//printf("word=%s, id=%d, ret=%d\n", ret.first->first.c_str(), ret.first->second, ret.second);
		if (ret.second) {
			id2word_.push_back(lower);
			df_.resize(id2word_.size());
		}
		if (set_.insert(word).second) {
			df_[ret.first->second]++;
		}
	}
	void endDoc()
	{
		docNum_++;
		set_.clear();
	}
	// sort freq order
	void term(int lowerLimit = 3, double upperRateLimit = 0.98)
	{
		fprintf(stderr, "#doc=%d, #word=%d\n", docNum_, (int)df_.size());
		for (size_t i = 0, n = id2word_.size(); i < n; i++) {
			const int freq = df_[i];
			if (freq <= lowerLimit) continue;
			pv_.push_back(Pair(i, freq));
		}
		int pvNum = (int)(pv_.size() * upperRateLimit);
		fprintf(stderr, "shrink %d -> %d\n", (int)pv_.size(), pvNum);
		std::partial_sort(pv_.begin(), pv_.begin() + pvNum, pv_.end());
		pv_.resize(pvNum);
	}
};

inline std::ostream& operator<<(std::ostream& os, const Df& df)
{
	const double logN = log(double(df.docNum_));
	for (size_t i = 0, n = df.pv_.size(); i < n; i++) {
		int freq = df.pv_[i].freq;
		double idf = logN - log(double(freq));
		os << df.id2word_[df.pv_[i].id] << '\t' << freq << '\t' << idf << std::endl;
	}
	return os;
}

struct TfIdf {
	Str2Int word2id_;
	StrVec id2word_;
	IntVec df_;
	Int2IntVec tf_;

	DoubleVec idf_;
	DoubleSvecVec sv_;

	// work area
	Int2Int *curTf_;
	StrSet set_; // for one doc

	TfIdf()
		: curTf_(0)
	{
	}
	bool loadKeywordFile(const std::string& keyFile)
	{
		std::ifstream ifs(keyFile.c_str(), std::ios::binary);
		if (!ifs) return false;
		std::string word;
		while (std::getline(ifs, word)) {
			size_t pos = word.find('\t');
			if (pos == std::string::npos) break;
			word.resize(pos);
			std::pair<Str2Int::iterator, bool> ret = word2id_.insert(Str2Int::value_type(word, (int)id2word_.size()));
			if (ret.second) {
				id2word_.push_back(word);
			} else {
				fprintf(stderr, "ERR already set %s\n", word.c_str());
			}
		}
		df_.resize(id2word_.size());
		fprintf(stderr, "#word = %d\n", (int)df_.size());
		return true;
	}

	void append(const std::string& word)
	{
		std::string lower;
		cybozu::ToLower(lower, word);
		Str2Int::const_iterator i = word2id_.find(lower);
		if (i == word2id_.end()) return;
		const int id = i->second;
		if (curTf_ == 0) {
			tf_.push_back(Int2Int());
			curTf_ = &tf_.back();
		}
		(*curTf_)[id]++;
		if (set_.insert(lower).second) {
			df_[id]++;
		}
	}
	void endDoc()
	{
		curTf_ = 0;
		set_.clear();
	}
	void put() const
	{
		printf("docNum=%d\n", (int)tf_.size());
		for (size_t i = 0, n = tf_.size(); i < n; i++) {
			printf("%d ", (int)i);
			tf_[i].put();
		}
		puts("word:idx");
		word2id_.put();
	}

	void term()
	{
		const double logN = log(double(tf_.size()));
		idf_.resize(df_.size());
		for (size_t i = 0, n = df_.size(); i < n; i++) {
			idf_[i] = logN - log(double(df_[i]));
		}
		for (size_t i = 0, n = df_.size(); i < n; i++) {
			const Int2Int& iv = tf_[i];
			DoubleSvec v;
			for (Int2Int::const_iterator j = iv.begin(), je = iv.end(); j != je; ++j) {
				v.push_back(j->first, j->second * idf_[j->first]);
			}
			sv_.push_back(v);
		}
	}
	void put(int maxNum = 0x7fffffff) const
	{
		printf("docNum=%d, wordNum=%d\n", (int)tf_.size(), (int)df_.size());
		for (int i = 0, n = std::min(maxNum, (int)sv_.size()); i < n; i++) {
			const DoubleSvec& v = sv_[i];
			for (DoubleSvec::const_iterator j = v.begin(), je = v.end(); j != je; ++j) {
				printf("%d:%f ", (int)j->pos(), j->val());
			}
			printf("\n");
		}
	}
};

inline std::ostream& operator<<(std::ostream& os, const TfIdf& /*tfIdf*/)
{
#if 0
	int num = 0;
	for (TfIdf::Rank::const_iterator i = tfIdf.rank_.begin(), ie = tfIdf.rank_.end(); i != ie; ++i) {
		TfIdf::Counter::const_iterator c = tfIdf.counter_.find(i->second);
		assert(c != tfIdf.counter_.end());
		os << i->first << ' ' <<  c->second.tf_ << ' ' << c->second.df_ << ' ' << i->second << std::endl;
		num++;
	}
#endif
	return os;
}

} } // cybozu::nlp
