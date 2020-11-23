/* Copyright (c) 2012-19, Robert J. Hansen <rob@hansen.engineering>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "common.hpp"
#include <algorithm>
#include <iostream>
#include <iterator>
#include <regex>
#include <vector>

using std::cerr;
using std::cin;
using std::copy;
using std::cout;
using std::ostream_iterator;
using std::regex;
using std::regex_search;
using std::sort;
using std::string;
using std::transform;
using std::unique;
using std::vector;

string SERVER, PORT;
bool SCORE_HITS { false };

int main(int argc, char* argv[])
{
#ifdef WINDOWS
    WSAData wsad;
    if (0 != WSAStartup(MAKEWORD(2, 0), &wsad)) {
        std::cerr << "Error: could not initialize Winsock.\n\n"
                     "You're running a very old version of Windows.  nsrllookup "
                     "won't work\non this system.\n";
        bomb(-1);
    }
#endif
    vector<string> hashes;
    regex valid_line { "^[A-F0-9]{32}",
        std::regex_constants::icase | std::regex_constants::optimize };
    regex valid_port { "^[0-9]{1,5}$" };

    parse_options(argc, argv);

    auto NaN = !regex_search(PORT, valid_port);
    if (NaN) {
        cerr << "Error: '" << PORT << "' is not a valid port.\n";
        bomb(-1);
    }

    auto port = ::strtol(PORT.c_str(), nullptr, 10);
    if (port < 0 || port > 65535) {
        cerr << "Error: '" << PORT << "' is not a valid port.\n";
        bomb(-1);
    }

    string line;
    while (cin) {
        getline(cin, line);
        transform(line.begin(), line.end(), line.begin(), ::toupper);
        if (regex_search(line, valid_line)) {
            hashes.emplace_back(string(line.begin(), line.begin() + 32));
        }
    }

    sort(hashes.begin(), hashes.end());
    hashes.erase(unique(hashes.begin(), hashes.end()), hashes.end());

    auto answers = query_server(hashes);
    copy(answers.cbegin(), answers.cend(), ostream_iterator<string>(cout, "\n"));
#ifdef WINDOWS
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}
