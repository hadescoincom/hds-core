
// Copyright (c) 2010-2020 niXman (i dot nixman dog gmail dot com). All
// rights reserved.
//
// This file is part of YAS(https://github.com/niXman/yas) project.
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
//
//
// Boost Software License - Version 1.0 - August 17th, 2003
//
// Permission is hereby granted, free of charge, to any person or organization
// obtaining a copy of the software and accompanying documentation covered by
// this license (the "Software") to use, reproduce, display, distribute,
// execute, and transmit the Software, and to prepare derivative works of the
// Software, and to permit third-parties to whom the Software is furnished to
// do so, all subject to the following:
//
// The copyright notices in the Software and this entire statement, including
// the above license grant, this restriction and the following disclaimer,
// must be included in all copies of the Software, in whole or in part, and
// all derivative works of the Software, unless such copies or derivative
// works are solely in the form of machine-executable object code generated by
// a source language processor.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
// SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
// FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

#ifndef __yas__types__concepts__keyval_hpp
#define __yas__types__concepts__keyval_hpp

namespace yas {
namespace detail {
namespace concepts {
namespace keyval {

/***************************************************************************/

template<std::size_t F, typename Archive, typename C>
Archive& save(Archive &ar, const C &c) {
    __YAS_CONSTEXPR_IF ( F & yas::json ) {
        if ( c.empty() ) {
            ar.write("{}", 2);

            return ar;
        }

        ar.write("{", 1);
        auto it = c.begin();
        ar & YAS_OBJECT_NVP(
             nullptr
            ,("key", it->first)
            ,("val", it->second)
        );
        for ( ++it; it != c.end(); ++it ) {
            ar.write(",", 1);
            ar & YAS_OBJECT_NVP(
                 nullptr
                ,("key", it->first)
                ,("val", it->second)
            );
        }
        ar.write("}", 1);
    } else {
        ar.write_seq_size(c.size());
        for ( const auto &it: c ) {
            ar & it.first
               & it.second;
        }
    }

    return ar;
}

/***************************************************************************/

template<std::size_t F, typename Archive, typename C>
Archive& load(Archive &ar, C &c) {
    __YAS_CONSTEXPR_IF ( F & yas::json ) {
        __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
            json_skipws(ar);
        }

        __YAS_THROW_IF_BAD_JSON_CHARS(ar, "{");

        __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
            json_skipws(ar);
        }

        // case for empty object
        const char ch = ar.peekch();
        if ( ch == '}' ) {
            ar.getch();

            return ar;
        }

        __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
            json_skipws(ar);
        }

        while ( true ) {
            typename C::key_type k = typename C::key_type();
            typename C::mapped_type v = typename C::mapped_type();
            ar & YAS_OBJECT_NVP(
                 nullptr
                ,("key", k)
                ,("val", v)
            );
            c.emplace(std::move(k), std::move(v));

            __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
                json_skipws(ar);
            }

            const char ch2 = ar.peekch();
            if ( ch2 == '}' ) {
                break;
            } else {
                ar.getch();
            }

            __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
                json_skipws(ar);
            }
        }

        __YAS_THROW_IF_BAD_JSON_CHARS(ar, "}");
    } else {
        auto size = ar.read_seq_size();
        for ( ; size; --size ) {
            typename C::key_type k = typename C::key_type();
            typename C::mapped_type v = typename C::mapped_type();
            ar & k
               & v;
            c.insert(std::make_pair(std::move(k), std::move(v)));
        }
    }

    return ar;
}

/***************************************************************************/

} // ns keyval
} // ns concepts
} // ns detail
} // ns yas

#endif // __yas__types__concepts__keyval_hpp
