// Copyright 2020-2020 The Hds Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "hex.h"
#include <cassert>

using namespace std;

namespace hds
{
    char* to_hex(char* dst, const void* bytes, size_t size)
    {
        static const char digits[] = "0123456789abcdef";
        char* d = dst;

        const uint8_t* ptr = (const uint8_t*)bytes;
        const uint8_t* end = ptr + size;
        while (ptr < end) {
            uint8_t c = *ptr++;
            *d++ = digits[c >> 4];
            *d++ = digits[c & 0xF];
        }
        *d = '\0';
        return dst;
    }

    std::string to_hex(const void* bytes, size_t size)
    {
        char* buf = (char*)alloca(2 * size + 1);
        return std::string(to_hex(buf, bytes, size));
    }

    std::vector<uint8_t> from_hex(const std::string& str, bool* wholeStringIsNumber)
    {
        size_t bias = (str.size() % 2) == 0 ? 0 : 1;
        assert((str.size() + bias) % 2 == 0);
        std::vector<uint8_t> res((str.size() + bias) >> 1);

        if (wholeStringIsNumber) *wholeStringIsNumber = true;

        for (size_t i = 0; i < str.size(); ++i)
        {
            auto c = str[i];
            size_t j = (i + bias) >> 1;
            res[j] <<= 4;
            if (c >= '0' && c <= '9')
            {
                res[j] += (c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                res[j] += 10 + (c - 'a');
            }
            else if (c >= 'A' && c <= 'F')
            {
                res[j] += 10 + (c - 'A');
            }
            else {
                if (wholeStringIsNumber) *wholeStringIsNumber = false;
                break;
            }
        }

        return res;
    }

} //namespace
