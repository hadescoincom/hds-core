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

#include "wallet/transactions/swaps/swap_transaction.h"
#include "wallet/transactions/swaps/common.h"

namespace hds::wallet
{
const char* getSwapTxStatus(AtomicSwapTransaction::State state);

TxParameters InitNewSwap(
    const WalletID& myID, Height minHeight, Amount amount,
    Amount fee, AtomicSwapCoin swapCoin, Amount swapAmount, Amount swapFee,
    bool isHdsSide = true, Height lifetime = kDefaultTxLifetime,
    Height responseTime = kDefaultTxResponseTime);

class Wallet;
void RegisterSwapTxCreators(Wallet& wallet, IWalletDB::Ptr walletDB);

Amount GetSwapFeeRate(IWalletDB::Ptr walletDB, AtomicSwapCoin swapCoin);
bool IsSwapAmountValid(
    AtomicSwapCoin swapCoin, Amount swapAmount, Amount swapFeeRate);
} // namespace hds::wallet
