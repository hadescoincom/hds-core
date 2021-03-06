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

#include "wallet/core/common.h"

namespace hds::wallet
{
constexpr Height kHdsLockTimeInBlocks = 6 * 60;  // 6h
constexpr Height kMaxSentTimeOfHdsRedeemInBlocks = kHdsLockTimeInBlocks - 60;  // 6h - 1h
constexpr Height kHdsLockTxLifetimeMax = 4 * 60;   // 4h

enum SubTxIndex : SubTxID
{
    HDS_LOCK_TX = 2,
    HDS_REFUND_TX = 3,
    HDS_REDEEM_TX = 4,
    LOCK_TX = 5,
    REFUND_TX = 6,
    REDEEM_TX = 7
};

enum class SwapTxState : uint8_t
{
    Initial,
    CreatingTx,
    SigningTx,
    Constructed
};

enum class AtomicSwapCoin : int32_t // explicit signed type for serialization backward compatibility
{
    Bitcoin,
    Litecoin,
    Qtum,
    Unknown
};

enum class SwapOfferStatus : uint32_t
{
    Pending,
    InProgress,
    Completed,
    Canceled,
    Expired,
    Failed
};

AtomicSwapCoin from_string(const std::string& value);
uint64_t UnitsPerCoin(AtomicSwapCoin swapCoin) noexcept;
}  // namespace hds::wallet

namespace std
{
    string to_string(hds::wallet::AtomicSwapCoin value);
    string to_string(hds::wallet::SwapOfferStatus status);
}  // namespace std
