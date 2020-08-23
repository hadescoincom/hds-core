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

#include <memory>
#include "core/uintBig.h"
#include "utility/common.h"

namespace hds::wallet::laser
{
    using ChannelID = uintBig_t<16>;
    using ChannelIDPtr = std::shared_ptr<uintBig_t<16>>;
    using FieldMap = std::map<uint32_t, ByteBuffer>;
}  // namespace hds::wallet::laser
