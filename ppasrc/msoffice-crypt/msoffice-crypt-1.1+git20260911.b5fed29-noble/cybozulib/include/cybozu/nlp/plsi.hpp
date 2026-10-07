#pragma once
/**
	@file
	@brief pLSI
	@author MITSUNARI Shigeo(@herumi)
*/

#include <fstream>
#include <map>
#include <limits>
#include <math.h>
#include <cybozu/string_operation.hpp>
#include <cybozu/time.hpp>
#include <cybozu/nlp/random.hpp>
#include <cybozu/nlp/sparse.hpp>
#include <cybozu/nlp/top_score.hpp>

namespace cybozu { namespace nlp {

namespace local {

template<class os, typename T>
os& dump(os& out, const std::vector<T>& list) {
	out << "{ ";
	for (typename std::vector<T>::const_iterator i = list.begin(), ie = list.end(); i != ie; ++i) {
		out << *i << " ";
	}
	out << "}";
	return out;
}

} // local

//const double NaN = std::numeric_limits<double>::quiet_NaN();

typedef cybozu::nlp::SparseVector<bool> BoolSVec;
typedef cybozu::nlp::SparseVector<double> DoubleSVec;
typedef std::vector<BoolSVec> SMatrix;

template<typename T>
bool hasKey(const std::map<T, size_t>& map, T key) { return map.find(key) != map.end(); }


class Plsi {
public:
	typedef int ITEM_TYPE;
	typedef int USER_TYPE;

	enum SEARCH_TYPE {
		JOINT,
		CONDITIONAL,
		POSTERIOR
	};
private:
	typedef std::vector<double> DoubleVec;
	typedef std::vector<DoubleVec> DoubleVecVec;
	std::map<USER_TYPE, size_t> users_;
	std::vector<USER_TYPE> userlist_;

	std::map<ITEM_TYPE, size_t> items_;
	std::vector<ITEM_TYPE> itemlist_;

	SMatrix matrix_; // item => users

	// probability of p(z), p(x|z), p(y|z)
	DoubleVec z_;
	DoubleVecVec user_z_, item_z_;

	template<class os>
	friend os& dump(os& out, const Plsi& x) {
		out << x.matrix_.size() << std::endl;
		local::dump(out, x.z_) << std::endl;
		return out;
	}

public:
	size_t get_item_id(ITEM_TYPE item) {
		if (hasKey(items_, item)) return items_[item];

		size_t id = items_[item] = itemlist_.size();
		itemlist_.push_back(item);
		matrix_.push_back(BoolSVec());
		return id;
	}

	BoolSVec& getItem(ITEM_TYPE item) {
		return matrix_[get_item_id(item)];
	}

	size_t get_user_id(USER_TYPE user) {
		if (hasKey(users_, user)) return users_[user];

		size_t id = users_[user] = userlist_.size();
		userlist_.push_back(user);
		return id;
	}

	ITEM_TYPE get_item_key(size_t item_id) {
		return itemlist_[item_id];
	}

	/**
		@brief retrieve relevant items for query user
	*/
	cybozu::nlp::TopScore<size_t>::Table search_items(USER_TYPE user, int top = 10) {
		int K = (int)z_.size();
		size_t user_id = get_user_id(user);

		double p_x = 0; // p(x) = sum p(z)p(x|z)
		DoubleVec p_z_x; // p(z|x) = p(z)p(x|z) / p(x)
		for (int k = 0; k < K; k++) {
			double p = z_[k] * user_z_[k][user_id];
			p_x += p;
			p_z_x.push_back(p);
		}

		cybozu::nlp::TopScore<size_t> ranking(top);
		for (size_t item_id = 0; item_id < items_.size(); item_id++) {
			double score = 0; // p(y|x) = sum _z p(y|z) * p(z|x)
			for (int k = 0; k < K; k++) {
				score += item_z_[k][item_id] * p_z_x[k];
			}
			ranking.add(score / p_x, item_id);
		}
		return ranking.getTable();
	}

	/**
		@brief retrieve similar items for query item
	*/
	cybozu::nlp::TopScore<size_t>::Table similar_items(ITEM_TYPE item, SEARCH_TYPE search_type, int top=10) {
		int K = (int)z_.size();
		size_t target_item_id = get_item_id(item);

		cybozu::nlp::TopScore<size_t> ranking(top);
		if (search_type == POSTERIOR) {
			for (size_t item_id = 0; item_id < items_.size(); item_id++) {
				// p(y1=target|y2=item_id) = sum _z p(target|z) * p(item_id|z) * p(z) / p(item_id)
				double score = 0, p_y = 0;
				for(int k=0;k<K;++k) {
					double p = item_z_[k][item_id] * z_[k];
					p_y += p;
					score += item_z_[k][target_item_id] * p;
				}

				ranking.add(score / p_y, item_id);
			}

		} else if (search_type == CONDITIONAL) {
			double p_y = 0;			  // p(y=target) = sum p(z)p(y=target|z)
			DoubleVec p_z_y;   // p(z)p(y=target|z)
			for (int k = 0; k < K; k++) {
				double p = z_[k] * item_z_[k][target_item_id];
				p_y += p;
				p_z_y.push_back(p);
			}
			for (size_t item_id = 0; item_id < items_.size(); item_id++) {
				// p(y1=item_id|y2=target) = sum _z p(y1|z) * p(z|y2) = sum _z p(y1|z) * p(y2|z) * p(z) / p(y2)
				double score = 0;
				for (int k = 0; k < K; k++) {
					score += item_z_[k][item_id] * p_z_y[k];
				}

				ranking.add(score / p_y, item_id);
			}

		} else if (search_type == JOINT) {
			for (size_t item_id = 0; item_id < items_.size(); item_id++) {
				// p(y1=item_id, y2=i) = sum _z p(y1|z) * p(y2|z) * p(z)
				double score = 0;
				for (int k = 0; k < K; k++) {
					score += item_z_[k][item_id] * item_z_[k][target_item_id] * z_[k];
				}
				ranking.add(score, item_id);
			}
		}
		return ranking.getTable();
	}

	/**
		@brief calcurate perplexity
	*/
	double perplexity()
	{
		int K = (int)z_.size();

		// p(x) = sum p(z)p(x|z)
		DoubleVec p_x;
		for (size_t user_id = 0; user_id < users_.size(); user_id++) {
			double p = 0;
			for (int k = 0; k < K; k++) {
				p += z_[k] * user_z_[k][user_id];
			}
			p_x.push_back(p);
		}

		int denom = 0;
		double sum = 0;
		for (size_t item_id = 0; item_id < matrix_.size(); item_id++) {
			BoolSVec& item_users = matrix_[item_id];
			for (BoolSVec::const_iterator i = item_users.begin(), ie = item_users.end(); i != ie; ++i) {
				++denom;
				size_t user_id = i.pos();

				// p(y|x) = sum p(y|z)p(z|x) = sum p(y|z)p(x|z)p(z)/p(x)
				double p = 0;
				for (int k = 0; k < K; k++) {
					p += z_[k] * user_z_[k][user_id] * item_z_[k][item_id];
				}
				sum += log(p / p_x[user_id]);
			}
		}
		return exp(-sum/denom);
	}

	/**
		@brief start learning (initialize learning)
	*/
	void startLearning(int K)
	{
		size_t M = users_.size();
		size_t N = items_.size();
		user_z_.resize(K);
		item_z_.resize(K);
		cybozu::nlp::UniformRandomGenerator rand(0.25, 0.75);
		for (int k = 0; k < K; k++) {
			// initialize p(z=k)
			z_.push_back(1.0/K);

			// initialize p(x=user|z=k)
			DoubleVec& uvec = user_z_[k];
			for (size_t j = 0; j < M; j++) uvec.push_back(1.0/M);

			// initialize p(y=item|z=k)
			DoubleVec& ivec = item_z_[k];
			double s = 0;
			for (size_t j = 0; j < N; j++) {
				double r = rand.getDouble();
				ivec.push_back(r);
				s += r;
			}
			for(size_t j = 0; j < N; j++) ivec[j] /= s;
		}

	}

	/**
		@brief step learning (called repeatedly after initialization learning)
		@param[in] beta  temperature for tempered EM
		@return likelyhood for previous iteration
	*/
	double step(double beta = 1)
	{
		int K = (int)z_.size();

		DoubleVec z_numer;
		DoubleVecVec user_numer, item_numer;
		z_numer.resize(K);
		user_numer.resize(K);
		item_numer.resize(K);
		for (int k = 0; k < K; k++) {
			user_numer[k].resize(users_.size());
			item_numer[k].resize(items_.size());
		}
		int denom = 0;
		double likelihood = 0;
		DoubleVec p_z_xy;
		p_z_xy.resize(K);

		for (size_t item_id = 0; item_id < matrix_.size(); ++item_id) {
			BoolSVec& item_users = matrix_[item_id];
			for (BoolSVec::const_iterator i = item_users.begin(), ie = item_users.end(); i != ie; ++i) {
				// when n(x, y) = 1(true)
				++denom;
				size_t user_id = i.pos();

				// E-step: p(z|x,y)
				double sum = 0;
				for (int k = 0; k < K; k++) {
					// p(z=k)p(x=user_id|z=k)p(y=item_id|z=k)
					double p = pow(z_[k] * user_z_[k][user_id] * item_z_[k][item_id], beta);
					p_z_xy[k] = p;
					sum += p;
				}

				// normalize & M-step
				for (int k = 0; k < K; k++) {
					double p = p_z_xy[k] / sum;

					user_numer[k][user_id] += p;
					item_numer[k][item_id] += p;
					z_numer[k] += p;
				}
				likelihood += log(sum);
			}
		}

		// M-step: update
		for (int k = 0; k < K; k++) {
			double z_num = z_numer[k];
			z_[k] = z_num / denom;
			for (size_t item_id = 0; item_id < items_.size(); ++item_id) {
				item_z_[k][item_id] = item_numer[k][item_id] / z_num;
			}
			for (size_t user_id = 0; user_id < users_.size(); ++user_id) {
				user_z_[k][user_id] = user_numer[k][user_id] / z_num;
			}
		}

		// log-likelihood of previous iteration
		return likelihood;
	}
};

} } // cybozu::nlp
