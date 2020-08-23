
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

#ifndef __yas__detail__io__header_hpp
#define __yas__detail__io__header_hpp

#include <yas/detail/config/config.hpp>

#include <yas/detail/io/io_exceptions.hpp>
#include <yas/detail/io/endian_conv.hpp>

#include <yas/detail/type_traits/type_traits.hpp>

#include <cstring>
#include <limits>

namespace yas {
namespace detail {
namespace header {

/***************************************************************************/

#pragma pack(push, 1)
union archive_header {
    struct {
        std::uint8_t version   :4; // version      : 0...15
        std::uint8_t type      :3; // archive type : 0...7: binary, text, json
        std::uint8_t endian    :1; // endianness   : 0 - LE, 1 - BE
        std::uint8_t compacted :1; // compacted    : 0 - no, 1 - yes
        std::uint8_t reserved  :7; // reserved
    } bits;

    std::uint16_t u;
};
#pragma pack(pop)

static_assert(sizeof(archive_header) == sizeof(std::uint16_t), "alignment error");

/**************************************************************************/

#ifdef YAS_SET_HEADER_BYTES
static_assert(sizeof(YAS_PP_STRINGIZE(YAS_SET_HEADER_BYTES)) >= 4, "header bytes error");
static constexpr std::uint8_t yas_id[] = {
     YAS_PP_STRINGIZE(YAS_SET_HEADER_BYTES)[0]
    ,YAS_PP_STRINGIZE(YAS_SET_HEADER_BYTES)[1]
    ,YAS_PP_STRINGIZE(YAS_SET_HEADER_BYTES)[2]
};
#else
static constexpr std::uint8_t yas_id[] = {'y', 'a', 's'};
#endif // YAS_SET_HEADER_BYTES

enum { k_header_size = sizeof(yas_id) + sizeof(std::uint16_t)*2 };

/**************************************************************************/

template<typename IO>
void read_header(IO &io, archive_header &h) {
    std::uint8_t buf[k_header_size];
    __YAS_THROW_READ_ERROR(k_header_size != io.read(buf, k_header_size));

    if ( 0 != std::memcmp(buf, yas_id, sizeof(yas_id)) )
        __YAS_THROW_BAD_ARCHIVE_INFORMATION();

    constexpr std::uint8_t d = std::numeric_limits<std::uint8_t>::max();
    constexpr std::uint8_t hexmap[256] = {
        d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, d, d
        ,d , d, d, d, d,10,11,12,13,14,15, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d,10,11,12
        ,13,14,15, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
        ,d , d, d, d, d, d, d, d, d, d, d, d, d, d, d, d
    };

    const std::uint8_t p0 = hexmap[buf[3]];
    const std::uint8_t p1 = hexmap[buf[4]];
    const std::uint8_t p2 = hexmap[buf[5]];
    const std::uint8_t p3 = hexmap[buf[6]];

#if __YAS_LITTLE_ENDIAN
    h.u = __YAS_SCAST(std::uint16_t, p0*(1<<12)+p1*(1<<8)+p2*(1<<4)+p3*(1<<0));
#else
    h.u = __YAS_SCAST(std::uint16_t, p0*(1<<0)+p1*(1<<4)+p2*(1<<8)+p3*(1<<12));
#endif
}

template<typename IO>
void write_header(IO &io, const archive_header &h) {
    static const std::uint8_t hexchars[] = "0123456789ABCDEF";
    const std::uint8_t buf[k_header_size] = {
        yas_id[0], yas_id[1], yas_id[2]
#if __YAS_LITTLE_ENDIAN
        ,hexchars[(h.u >> 12) & 0x000F]
        ,hexchars[(h.u >> 8 ) & 0x000F]
        ,hexchars[(h.u >> 4 ) & 0x000F]
        ,hexchars[(h.u      ) & 0x000F]
#else
        ,hexchars[(h.u      ) & 0x000F]
        ,hexchars[(h.u >> 4 ) & 0x000F]
        ,hexchars[(h.u >> 8 ) & 0x000F]
        ,hexchars[(h.u >> 12) & 0x000F]
#endif
    };

    __YAS_THROW_WRITE_ERROR(k_header_size != io.write(buf, k_header_size));
}

/**************************************************************************/

} // ns header

/***************************************************************************/

template<std::size_t F>
struct archive_version;

template<>
struct archive_version<options::binary> {
    enum { value = yas::detail::binary_archive_version };
};

template<>
struct archive_version<options::text> {
    enum { value = yas::detail::text_archive_version };
};

template<>
struct archive_version<options::json> {
    enum { value = yas::detail::json_archive_version };
};

/**************************************************************************/

template<std::size_t F>
struct oarchive_header {
    template<typename IO>
    oarchive_header(IO &io) {
        __YAS_CONSTEXPR_IF( !(F & options::no_header) && !(F & yas::json) ) {
            constexpr std::uint8_t artype = __YAS_SCAST(std::uint8_t
                ,F & (options::binary|options::text|options::json)
            );
            constexpr std::uint8_t endian = __YAS_SCAST(std::uint8_t
                ,((F & options::ehost) ? __YAS_BIG_ENDIAN : (F & options::ebig) ? 1 : 0)
            );
            constexpr bool compacted = __YAS_SCAST(bool, (F & yas::compacted));

            const header::archive_header header = {{
                 __YAS_SCAST(std::uint8_t, version() & 15)
                ,__YAS_SCAST(std::uint8_t, artype)
                ,__YAS_SCAST(std::uint8_t, endian)
                ,__YAS_SCAST(std::uint8_t, compacted)
                ,__YAS_SCAST(std::uint8_t, 0u) // reserved
            }};

            header::write_header(io, header);
        }
    }

    static constexpr std::size_t header_size() { return (F & yas::json) ? 0 : header::k_header_size; }
    static constexpr std::size_t flags() { return F; }

    static constexpr options type() {
        return __YAS_SCAST(options, F & (options::binary|options::text|options::json));
    }

    static constexpr bool is_big_endian() {
        return __YAS_SCAST(bool,
            (F & options::ehost) ? __YAS_SCAST(bool, __YAS_BIG_ENDIAN) : __YAS_SCAST(bool, F & options::ebig)
        );
    }
    static constexpr bool is_little_endian() {
        return __YAS_SCAST(bool,
            (F & options::ehost) ? __YAS_SCAST(bool, __YAS_LITTLE_ENDIAN) : __YAS_SCAST(bool, F & options::elittle)
        );
    }
    static constexpr options host_endian() { return __YAS_BIG_ENDIAN ? options::ebig : options::elittle; }

    static constexpr bool compacted() { return __YAS_SCAST(bool, (F & yas::compacted)); }
    static constexpr std::size_t version() { return archive_version<type()>::value; }

    static constexpr bool is_readable() { return false; }
    static constexpr bool is_writable() { return true; }
};

/***************************************************************************/

#define __YAS_CHECK_IF_HEADER_INITED() \
    if ( !header.bits.version ) __YAS_THROW_ARCHIVE_NO_HEADER()

template<std::size_t F>
struct iarchive_header {
    template<typename IO>
    iarchive_header(IO &io)
        :header{}
    {
        __YAS_CONSTEXPR_IF( !(F & options::no_header) && !(F & yas::json) ) {
            header::read_header(io, header);

            constexpr std::size_t mask = options::binary|options::text|options::json;
            constexpr std::uint8_t artype = __YAS_SCAST(std::uint8_t, F & mask);

            if ( header.bits.type != artype ) {
                __YAS_THROW_BAD_ARCHIVE_TYPE()
            }

            if ( header.bits.version != archive_version<F & mask>::value ) {
                __YAS_THROW_BAD_ARCHIVE_VERSION()
            }

            if ( F & yas::compacted && !header.bits.compacted ) {
                __YAS_THROW_BAD_COMPACTED_MODE()
            }
        }

        __YAS_CONSTEXPR_IF( F & yas::json ) {
            header.bits.version = json_archive_version;
            header.bits.type = yas::json;
        }
    }

    static constexpr std::size_t header_size() { return (F & yas::json) ? 0 : header::k_header_size; }
    static constexpr std::size_t flags() { return F; }

    options type() const {
        __YAS_CHECK_IF_HEADER_INITED()

        return __YAS_SCAST(options, header.bits.type);
    }

    bool is_big_endian() const {
        __YAS_CHECK_IF_HEADER_INITED()

        return header.bits.endian;
    }

    bool is_little_endian() const { return !is_big_endian(); }

    static constexpr options host_endian() {
        return __YAS_BIG_ENDIAN ? options::ebig : options::elittle;
    }

    bool compacted() const {
        __YAS_CHECK_IF_HEADER_INITED()

        return header.bits.compacted;
    }

    std::size_t version() const {
        __YAS_CHECK_IF_HEADER_INITED()

        return header.bits.version;
    }

    static constexpr bool is_readable() { return true; }
    static constexpr bool is_writable() { return false; }

private:
    header::archive_header header;
};

#undef __YAS_CHECK_IF_HEADER_INITED

/***************************************************************************/

} // namespace detail
} // namespace yas

#endif // __yas__detail__io__header_hpp