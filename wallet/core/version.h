// Copyright 2020 The Hds Team
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

#pragma once

#include "utility/serialize_fwd.h"

#include "stdint.h"
#include <string>

namespace hds
{
    struct Version
    {
        uint32_t m_major = 0;
        uint32_t m_minor = 0;
        uint32_t m_revision = 0;

        Version() = default;
        Version(uint32_t major, uint32_t minor, uint32_t rev)
            : m_major(major)
            , m_minor(minor)
            , m_revision(rev)
        {};

        SERIALIZE(m_major, m_minor, m_revision);

        std::string to_string() const;
        bool from_string(const std::string&);
        bool operator==(const Version& other) const;
        bool operator!=(const Version& other) const;
        bool operator<(const Version& other) const;
        bool operator<=(const Version& other) const;
    };
}
