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

#include "wallet/transactions/swaps/common.h"
#include "bitcoin/bitcoin.hpp"

namespace hds::wallet
{
AtomicSwapCoin from_string(const std::string& value)
{
    if (value == "btc")
        return AtomicSwapCoin::Bitcoin;
    else if (value == "ltc")
        return AtomicSwapCoin::Litecoin;
    else if (value == "qtum")
        return AtomicSwapCoin::Qtum;

    return AtomicSwapCoin::Unknown;
}

uint64_t UnitsPerCoin(AtomicSwapCoin swapCoin) noexcept
{
    switch (swapCoin)
    {
    case AtomicSwapCoin::Bitcoin:
    case AtomicSwapCoin::Litecoin:
    case AtomicSwapCoin::Qtum:
        return libbitcoin::satoshi_per_bitcoin;
    default:
    {
        assert("Unsupported swapCoin type.");
        return 0;
    }
    }
}
}  // namespace hds::wallet

namespace std
{
string to_string(hds::wallet::SwapOfferStatus status)
{
    switch (status)
    {
    case hds::wallet::SwapOfferStatus::Pending:
        return "Pending";
    case hds::wallet::SwapOfferStatus::InProgress:
        return "InProgress";
    case hds::wallet::SwapOfferStatus::Completed:
        return "Completed";
    case hds::wallet::SwapOfferStatus::Canceled:
        return "Canceled";
    case hds::wallet::SwapOfferStatus::Expired:
        return "Expired";
    case hds::wallet::SwapOfferStatus::Failed:
        return "Failed";

    default:
        return "";
    }
}

string to_string(hds::wallet::AtomicSwapCoin value)
{
    switch (value)
    {
    case hds::wallet::AtomicSwapCoin::Bitcoin:
        return "BTC";
    case hds::wallet::AtomicSwapCoin::Litecoin:
        return "LTC";
    case hds::wallet::AtomicSwapCoin::Qtum:
        return "QTUM";
    default:
        return "";
    }
}
}  // namespace std 
