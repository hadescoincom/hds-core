
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

#ifndef __yas__types__boost__variant_serializers_hpp
#define __yas__types__boost__variant_serializers_hpp

#if defined(YAS_SERIALIZE_BOOST_TYPES)
#include <yas/detail/type_traits/type_traits.hpp>
#include <yas/detail/type_traits/serializer.hpp>

#include <boost/variant.hpp>

#include <yas/detail/tools/variant_element_switch.hpp>

namespace yas {
namespace detail {

/***************************************************************************/

template<std::size_t F, typename... Types>
struct serializer<
    type_prop::not_a_fundamental,
    ser_method::use_internal_serializer,
    F,
    boost::variant<Types...>
> {
    template<typename Archive>
    static Archive& save(Archive& ar, const boost::variant<Types...> &v) {
        const std::size_t idx = v.which();
        __YAS_CONSTEXPR_IF ( F & yas::json ) {
            ar.write("[", 1);
            ar & YAS_OBJECT(nullptr, idx);
            ar.write(",", 1);
            variant_switch<F>(ar, idx, __YAS_CCAST(boost::variant<Types...> &, v));
            ar.write("]", 1);
        } else {
            ar.write(__YAS_SCAST(std::uint8_t, idx));
            variant_switch<F>(ar, idx, __YAS_CCAST(boost::variant<Types...> &, v));
        }

        return ar;
    }

    template<typename Archive>
    static Archive& load(Archive& ar, boost::variant<Types...> &v) {
        __YAS_CONSTEXPR_IF ( F & yas::json ) {
            __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
                json_skipws(ar);
            }
            __YAS_THROW_IF_BAD_JSON_CHARS(ar, "[");
            std::size_t idx = 0;
            ar & YAS_OBJECT(nullptr, idx);
            __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
                json_skipws(ar);
            }
            __YAS_THROW_IF_BAD_JSON_CHARS(ar, ",");
            variant_switch<F>(ar, idx, v);
            __YAS_CONSTEXPR_IF ( !(F & yas::compacted) ) {
                json_skipws(ar);
            }
            __YAS_THROW_IF_BAD_JSON_CHARS(ar, "]");
        } else {
            std::uint8_t idx = 0;
            ar & idx;
            variant_switch<F>(ar, idx, v);
        }

        return ar;
    }
};

/***************************************************************************/

} // namespace detail
} // namespace yas

#endif // defined(YAS_SERIALIZE_BOOST_TYPES)

#endif // __yas__types__boost__variant_serializers_hpp
