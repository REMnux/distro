/**
	pLSI(probabilistic latent semantic indexing)
	@author MITSUNARI Shigeo(@herumi)
*/

#include <stdio.h>
#include <map>
#include <cybozu/file.hpp>
#include <cybozu/csv.hpp>
#include <cybozu/nlp/plsi.hpp>
#include <cybozu/string_operation.hpp>
#include <cybozu/time.hpp>
#include <iostream>

void load(cybozu::nlp::Plsi& plsi, const std::string& filepath)
{
	cybozu::CsvReader csv(filepath, ' ');
	std::vector<std::string> line;
	while (csv.read(line)) {
		cybozu::nlp::Plsi::ITEM_TYPE item_key = cybozu::atoi(line[0]);
		size_t size = line.size();
		if (size < 2) continue;
		std::map<size_t, bool> map;
		for (size_t i = 1; i < line.size(); ++i) {
			cybozu::nlp::Plsi::USER_TYPE user_key = cybozu::atoi(line[i]);
			map[plsi.get_user_id(user_key)] = true;
		}
		plsi.getItem(item_key).set(map);
	}
}

void usage()
{
	printf("usage: plsi [option] -f [dataset filename]\n");
	printf("  -k [num] : # of latent classes");
	printf("  -i [num] : # of iterations");
	exit(1);
}

/**
	@brief Atnd Data
*/
struct AtndData {
	std::string date; // for only event
	std::string name; // user or event name
};

/**
	@brief Atnd Information (Users / Events)
*/
struct AtndInfo {
	typedef std::map<int, AtndData> Int2Data;
	typedef std::map<std::string, int> Str2Int;
	Int2Data int2data_;
	Str2Int name2id_;
	/**
		@brief load list of Atnd Users / Events
		@param[in] name	  filename of list
		@param[in] isEvent   Is it an event list?
	*/
	bool loadList(const std::string& name, bool isEvent)
	{
		std::ifstream ifs(name.c_str(), std::ios::binary);
		if (!ifs) return false;
		for (;;) {
			AtndData t;
			int id;
			if (!(ifs >> id)) break;
			if (isEvent) {
				std::string str;
				ifs >> str;
				if (str.empty()) return false;
				if (str.size() < 6) {
					fprintf(stderr, "bad format %s\n", str.c_str());
					return false;
				}
				str = str.substr(0, str.size() - 6); // "+09:00"
				cybozu::Time time(str);
				time.setTime(time.getTime() + 9	* 3600);
				time.toString(t.date, "%Y/%m/%d", false);
			}
			std::getline(ifs, t.name);
			cybozu::Trim(t.name);
			if (!ifs) break;
			int2data_[id] = t;
			name2id_[t.name] = id;
		}
		return true;
	}
	/**
		@brief load list of Atnd Users / Events. (generates filename from isEvent parameter)
		@param[in] dir	   directory name where list exists
		@param[in] isEvent   Is it an event list?
	*/
	bool load(const std::string& dir, bool isEvent)
	{
		const std::string key = isEvent ? "event" : "user";
		std::string name;
		name = dir + "/atnd-" + key + ".txt";
		if (!loadList(name, isEvent)) {
			fprintf(stderr, "can't read %s (%d)\n", name.c_str(), isEvent);
			return false;
		}
		return true;
	}
};

int main(int argc, char** argv)
{
	std::string data_dir = cybozu::GetExePath() + "../sample/data/plsi/";

	int K = 20;
	int Iter = 100;
	argc--, argv++;
	while (argc > 0) {
		if (argc > 1 && strcmp(*argv, "-d") == 0) {
			argc--, argv++;
			data_dir = *argv;
		} else if (argc > 1 && strcmp(*argv, "-k") == 0) {
			argc--, argv++;
			K = cybozu::atoi(*argv);
		} else if (argc > 1 && strcmp(*argv, "-i") == 0) {
			argc--, argv++;
			Iter = cybozu::atoi(*argv);
		} else {
			usage();
		}
		argc--, argv++;
	}
	const std::string name = data_dir + "/atnd-user-matrix.txt";

	cybozu::nlp::Plsi plsi;
	try {
		AtndInfo event_master, user_master;
		event_master.load(data_dir, true);
		user_master.load(data_dir, false);

		load(plsi, name);
		plsi.startLearning(K);
		{
			puts("learning");
			double pre_likelihood = -1e30;
			double beta = 1;
			for (int i = 0; i < Iter; ++i) {
				double likelihood = plsi.step();
				printf("%d : %.3f %.3f %.3f\n", i, beta, likelihood, likelihood - pre_likelihood);
				if (likelihood - pre_likelihood < 1) {
					beta *= 0.9;
					if (beta < 0.01) break;
				}
				pre_likelihood = likelihood;
			}
		}

		int mode = 0;
		cybozu::nlp::Plsi::SEARCH_TYPE search_type = cybozu::nlp::Plsi::JOINT;

		for(;;) {
			std::string st;
			std::cin >> st;
			if (st == "") break;
			if (st == "ui") {
				mode = 0;
				printf("user => items\n");
				continue;
			}
			if (st == "ii") {
				mode = 1;
				printf("item => items\n");
				continue;
			}
			if (st == "sj") {
				search_type = cybozu::nlp::Plsi::JOINT;
				printf("search type: JOINT probability\n");
				continue;
			}
			if (st == "sc") {
				search_type = cybozu::nlp::Plsi::CONDITIONAL;
				printf("search type: CONDITIONAL probability\n");
				continue;
			}
			if (st == "sp") {
				search_type = cybozu::nlp::Plsi::POSTERIOR;
				printf("search type: POSTERIOR probability\n");
				continue;
			}

			cybozu::nlp::TopScore<size_t>::Table tbl;
			switch(mode) {
			case 0:
				tbl = plsi.search_items(cybozu::atoi(st), 10);
				break;
			case 1:
				tbl = plsi.similar_items(cybozu::atoi(st), search_type, 10);
				break;
			}

			for (size_t i = 0; i < tbl.size(); i++) {
				cybozu::nlp::Plsi::ITEM_TYPE key = plsi.get_item_key(tbl[i].idx);
				printf("%1.3f %d:%s\n", log(tbl[i].score), key, event_master.int2data_[key].name.c_str());
			}
		}

	} catch (std::exception& e) {
		printf("error : %s\n", e.what());
	}
}
