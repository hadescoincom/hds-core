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

#include "wallet/core/base_transaction.h"

namespace hds::wallet::lelantus
{
    TxParameters CreatePullTransactionParameters(const WalletID& myID, const boost::optional<TxID>& txId = boost::none);

    class PullTxBuilder;

    class PullTransaction : public BaseTransaction
    {
    public:
        class Creator : public BaseTransaction::Creator
        {
        public:
            Creator(bool withAssets): m_withAssets(withAssets) {}

        private:
            BaseTransaction::Ptr Create(INegotiatorGateway& gateway
                                        , IWalletDB::Ptr walletDB
                                        , const TxID& txID) override;

            TxParameters CheckAndCompleteParameters(const TxParameters& parameters) override;
            bool m_withAssets;
        };

    public:
        PullTransaction(INegotiatorGateway& gateway
                        , IWalletDB::Ptr walletDB
                        , const TxID& txID
                        , bool withAssets);

    private:
        TxType GetType() const override;
        bool IsInSafety() const override;
        void UpdateImpl() override;
        void RollbackTx() override;

        bool GetShieldedList();

    private:
        std::shared_ptr<PullTxBuilder> m_TxBuilder;
        bool m_withAssets;
    };
} // namespace hds::wallet::lelantus