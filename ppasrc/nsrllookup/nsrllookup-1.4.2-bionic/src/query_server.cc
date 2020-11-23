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
#include <boost/asio.hpp>
#include <exception>
#include <iostream>
#include <iterator>
#include <regex>
#include <sstream>

using boost::asio::ip::tcp;
using std::cerr;
using std::copy;
using std::getline;
using std::min;
using std::ostream_iterator;
using std::regex;
using std::regex_search;
using std::sort;
using std::string;
using std::stringstream;
using std::unique;
using std::vector;

namespace {
void trim(string& line)
{
    if (line.size() == 0)
        return;

    auto end_ws = line.find_last_not_of("\t\n\v\f\r ");
    if (end_ws != string::npos) {
        line.erase(end_ws + 1);
    }
    auto front_ws = line.find_first_not_of("\t\n\v\f\r ");
    if (front_ws > 0) {
        line.erase(0, front_ws);
    }
}
}

vector<string> query_server(const vector<string>& hashes)
{
    constexpr size_t MAX_SENT = 512;
    const auto scorechar = SCORE_HITS ? '1' : '0';
    size_t hashidx = 0;
    vector<string> rv;
    auto resprx = regex("^OK [01]+$");
    string response;

    try {
        tcp::iostream stream(SERVER, PORT);
        if (!stream) {
            cerr << "Could not connect to " << SERVER << " " << PORT << ".\n";
            bomb(-1);
        }

        stream << "Version: 2.0\r\n";
        getline(stream, response);
        trim(response);
        if (response != "OK") {
            cerr << "Malformed response from server: " << response << "\n";
            bomb(-1);
        }

        while (hashidx < hashes.size()) {
            stringstream buf;
            auto bufiter = ostream_iterator<string>(buf, " ");
            auto end = hashidx + min(MAX_SENT, (hashes.size() - hashidx));

            // Form and send the query, remembering to trim whitespace.
            buf << "query ";
            copy(hashes.cbegin() + hashidx, hashes.cbegin() + end, bufiter);
            auto query = buf.str();
            trim(query);
            stream << query << "\r\n";

            // Receive and walk down the response.
            getline(stream, response);
            trim(response);
            if (!regex_search(response, resprx)) {
                cerr << "Error: malformed response from server";
                bomb(-1);
            }
            for (size_t respidx = 3; respidx < response.size(); respidx += 1) {
                if (response.at(respidx) == scorechar)
                    rv.emplace_back(hashes.at(hashidx + (respidx - 3)));
            }
            hashidx = end;
        }
        rv.erase(unique(rv.begin(), rv.end()), rv.end());
        sort(rv.begin(), rv.end());
        return rv;
    } catch (std::exception&) {
        cerr << "IO error communicating with " << SERVER << " " << PORT << ".\n";
        bomb(-1);
    }
    // We can't reach this code: we either bail out in the above return or the
    // above exception.
    return vector<string>();
}
