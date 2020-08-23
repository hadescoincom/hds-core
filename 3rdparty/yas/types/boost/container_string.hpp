
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

#ifndef __yas__types__boost__boost_container_string_serializers_hpp
#define __yas__types__boost__boost_container_string_serializers_hpp

#if defined(YAS_SERIALIZE_BOOST_TYPES)
#include <yas/detail/type_traits/type_traits.hpp>
#include <yas/detail/type_traits/serializer.hpp>
#include <yas/detail/tools/cast.hpp>
#include <yas/detail/tools/save_load_string.hpp>

#include <boost/container/string.hpp>

namespace yas {
namespace detail {

/***************************************************************************/

template<std::size_t F>
struct serializer<
	type_prop::not_a_fundamental,
	ser_method::use_internal_serializer,
	F,
	boost::container::string
> {
	template<typename Archive>
	static Archive& save(Archive& ar, const boost::container::string& string) {
		if ( F & yas::json ) {
			ar.write("\"", 1);
			save_string(ar, string);
			ar.write("\"", 1);
		} else {
			ar.write_seq_size(string.length());
			ar.write(string.data(), string.length());
		}

		return ar;
	}

	template<typename Archive>
	static Archive& load(Archive& ar, boost::container::string& string) {
		if ( F & yas::json ) {
			__YAS_THROW_IF_BAD_JSON_CHARS(ar, "\"");
			load_string(string, ar);
			__YAS_THROW_IF_BAD_JSON_CHARS(ar, "\"");
		} else {
			const auto size = ar.read_seq_size();
			string.resize(size);
			ar.read(__YAS_CCAST(char*, string.data()), size);
		}

		return ar;
	}
};

/***************************************************************************/

} // namespace detail
} // namespace yas

#endif // defined(YAS_SERIALIZE_BOOST_TYPES)

#endif // __yas__types__boost__boost_container_string_serializers_hpp
