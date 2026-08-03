/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "CLI11.hpp"

#include "cli.h"
#include "manalyze_version.h"
#include "hash-library/hash.h"
#include "manacommons/color.h"
#include "yara/yara_wrapper.h"

#if defined WITH_OPENSSL
# include <openssl/opensslv.h>
#endif


namespace {

std::vector<std::string> normalize_args_for_cli11(int argc, char** argv)
{
	std::vector<std::string> normalized;
	normalized.reserve(static_cast<size_t>(argc) * 2);
	normalized.push_back(argv[0]);

	bool end_of_options = false;
	for (int i = 1; i < argc; ++i) {
		std::string arg = argv[i];
		if (end_of_options) {
			normalized.push_back(std::move(arg));
			continue;
		}

		if (arg == "--") {
			normalized.push_back(std::move(arg));
			end_of_options = true;
			continue;
		}

		if (arg.rfind("--", 0) == 0) {
			normalized.push_back(std::move(arg));
			continue;
		}

		if (arg.size() >= 2 && arg[0] == '-' && arg[1] != '-') {
			const char opt = arg[1];
			const bool needs_value = (opt == 'o' || opt == 'd' || opt == 'x' || opt == 'p');
			if (needs_value && arg.size() > 2) {
				normalized.push_back(arg.substr(0, 2));
				normalized.push_back(arg.substr(2));
			}
			else {
				normalized.push_back(std::move(arg));
			}
			continue;
		}

		normalized.push_back(std::move(arg));
	}

	return normalized;
}

std::vector<std::string> split_delimited_values(const std::string& value)
{
	std::vector<std::string> out;
	std::string current;
	for (const char ch : value) {
		if (ch == ',' || ch == '\n') {
			if (!current.empty()) {
				out.push_back(current);
				current.clear();
			}
			continue;
		}
		current.push_back(ch);
	}
	if (!current.empty()) {
		out.push_back(current);
	}
	return out;
}

void print_help_default(const CLI::App& app, const std::string& argv_0)
{
    (void)argv_0;
    std::cout << app.help() << std::endl;
}

} // namespace

bool parse_args(Options& opts, int argc, char**argv, const HelpPrinter& help_printer, const ArgsValidator& validator)
{
	CLI::App app("Usage");
	app.allow_extras(false);
	std::string dump_values;
	std::string plugin_values;
	app.set_help_flag("-h,--help", "Displays this message.");
	app.add_flag("-v,--version", opts.version, "Prints the program's version.");
    app.add_option("pe", opts.pe, "The PE to analyze. Multiple files may be specified.")
        ->expected(-1)
        ->type_name("FILE");
    app.add_flag("-r,--recursive", opts.recursive, "Scan all files in a directory (subdirectories will be ignored).");
    app.add_flag("-q,--quiet", opts.quiet, "Only display errors.");
    auto* output_opt = app.add_option("-o,--output", opts.output, "The output format. May be 'raw' (default) or 'json'.");
	auto* dump_opt = app.add_option("-d,--dump", dump_values,
		"Dump PE information. Available choices are any combination of: "
		"all, summary, dos (dos header), pe (pe header), opt (pe optional header), sections, "
		"imports, exports, resources, version, debug, tls, config (image load configuration), "
		"delay (delay-load table), rich");
		dump_opt->expected(1, 1);
	dump_opt->multi_option_policy(CLI::MultiOptionPolicy::Join);
    app.add_flag("--hashes", opts.hashes, "Calculate various hashes of the file (may slow down the analysis!)");
    auto* extract_opt = app.add_option("-x,--extract", opts.extract, "Extract the PE resources and authenticode certificates "
        "to the target directory.");
	auto* plugins_opt = app.add_option("-p,--plugins", plugin_values,
		"Analyze the binary with additional plugins. (may slow down the analysis!)");
	plugins_opt->expected(1, 1);
	plugins_opt->multi_option_policy(CLI::MultiOptionPolicy::Join);
    auto* log_level_opt = app.add_option("--log-level", opts.log_level,
        "Set log verbosity. Accepted values: off, error, warning, info, debug.");

    if (argc <= 1)
    {
        if (help_printer) {
            help_printer(app, argv[0]);
        } else {
            print_help_default(app, argv[0]);
        }
        return false;
    }

    try
    {
		const std::vector<std::string> normalized = normalize_args_for_cli11(argc, argv);
		std::vector<char*> normalized_argv;
		normalized_argv.reserve(normalized.size());
		for (const auto& arg : normalized) {
			normalized_argv.push_back(const_cast<char*>(arg.c_str()));
		}
		app.parse(static_cast<int>(normalized_argv.size()), normalized_argv.data());
    }
    catch (const CLI::CallForHelp& e)
    {
        (void)e;
        if (help_printer) {
            help_printer(app, argv[0]);
        } else {
            print_help_default(app, argv[0]);
        }
        exit(0);
    }
    catch (const CLI::ParseError& e)
    {
        PRINT_ERROR << "Could not parse the command line (" << e.what() << ")." << std::endl << std::endl;
        return false;
    }

    opts.output_set = output_opt->count() > 0;
    opts.extract_set = extract_opt->count() > 0;
    opts.log_level_set = log_level_opt->count() > 0;
	opts.dump = split_delimited_values(dump_values);
	opts.plugins = split_delimited_values(plugin_values);

    if (opts.quiet && !opts.log_level_set) {
        opts.log_level = "error";
        opts.log_level_set = true;
    }
    if (opts.log_level_set) {
        utils::LogLevel level = utils::LogLevel::WARNING;
        if (!utils::parse_log_level(opts.log_level, level)) {
            PRINT_ERROR << "Invalid log level \"" << opts.log_level
                        << "\". Expected one of: off, error, warning, info, debug." << std::endl;
            return false;
        }
    }

    if (opts.version)
    {
        std::stringstream ss;
        ss << "Manalyze " MANALYZE_VERSION " (Ivan Kwiatkowski, GPLv3 License) compiled with:" << std::endl;
        ss << "* Yara " << YR_MAJOR_VERSION << "." << YR_MINOR_VERSION << "." << YR_MICRO_VERSION << ". (Victor M. Alvarez, Apache 2.0 License)" << std::endl;
        ss << "* hash-library " << HASH_LIBRARY_VERSION << " (Stephan Brumme, ZLib License)." << std::endl;
        #if defined WITH_OPENSSL
            ss << "* " << OPENSSL_VERSION_TEXT << " (OpenSSL Project, OpenSSL License)" << std::endl;
        #endif
        std::cout << ss.str();
        return true;
    }
	else if (opts.pe.empty())
	{
		if (help_printer) {
			help_printer(app, argv[0]);
		} else {
			print_help_default(app, argv[0]);
		}
		exit(0);
	}

    if (validator) {
        return validator(opts, app, argv);
    }
    return true;
}
