#pragma once
/**
	@file
	@brief libbfd class
	@note bfd is GPL
	with -lbfd ; libbfd.a is in binutils-dev
*/
#ifdef _MSC_VER
	#error "not supported"
#endif
#include <unistd.h>
#include <bfd.h>
#include <string>

namespace cybozu {

struct Bfd {
	struct bfd *bfd;
	explicit Bfd(const std::string& fileName = "")
		: bfd(0)
	{
		bfd_init();

		const char *file = fileName.c_str();
#if 0
		if (*file == '\0') {
			file = "/proc/self/exe";
		}
#else
		/*
			/proc/self/exe does not point to self-binary on valgrind,
			so use readlink to get correct self-binary
		*/
		std::string path;
		if (*file == '\0') {
			path.resize(4096);
			int ret = readlink("/proc/self/exe", &path[0], path.size() - 2);
			if (ret <= 0) {
				perror("ERR:cybozu:StackTrace:Bfd:readlink");
				return;
			}
			path.resize(ret);
			file = path.c_str();
		}
#endif
		bfd = bfd_openr(file, 0);
		if (bfd == 0) {
			perror("ERR:cybozu:StackTrace:Bfd:bfd_opener");
			return;
		}
		if (!bfd_check_format(bfd, bfd_object)) {
			perror("ERR:cybozu:StackTrace:Bfd:bfd_check_format");
			return;
		}
	}
	~Bfd()
	{
		if (bfd == 0) return;
		if (!bfd_close(bfd)) {
			fprintf(stderr, "ERR:cybozu:StackTrace:Bfd:bfd_close\n");
		}
	}
	bool getInfo(std::string* pFile, std::string* pFunc, int *pLine, const void *addr)
	{
		if (bfd == 0) return false;
		Data data(addr, pFile, pFunc);
		bfd_map_over_sections(bfd, findAddress, &data);
		*pLine = data.line;
		return data.found;
	}
private:
	struct Data {
		bfd_vma pc;
		std::string *pFile;
		std::string *pFunc;
		unsigned int line;
		bool found;
		Data(const void *addr, std::string *pFile, std::string *pFunc)
			: pc(bfd_vma(addr))
			, pFile(pFile)
			, pFunc(pFunc)
			, line(0)
			, found(false)
		{
		}
	};
	static inline void findAddress(struct bfd *bfd, asection *section, void *self)
	{
		Data *data = (Data*)self;
		if (data->found) return;
		if (section == 0) return;
		bfd_vma vma = bfd_section_vma(section);
		if (data->pc < vma) return;
		bfd_size_type size = bfd_section_size(section);
		if (data->pc >= vma + size) return;
		const char *file;
		const char *func;
		data->found = bfd_find_nearest_line(bfd, section, NULL, data->pc - vma, &file, &func, &data->line);
		if (!data->found) return;
		if (file) *data->pFile = file;
		if (func) *data->pFunc = func;
	}
};

} // cybozu
