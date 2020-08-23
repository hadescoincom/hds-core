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

#include "common.h"
#include "wallet_db.h"
#include "base_transaction.h"

#include <condition_variable>
#include <boost/optional.hpp>
#include "utility/logger.h"

namespace hds::wallet
{
    class BaseTxBuilder;

    TxParameters CreateSimpleTransactionParameters(const boost::optional<TxID>& txId = boost::none);
    TxParameters CreateSplitTransactionParameters(const WalletID& myID, const AmountList& amountList, const boost::optional<TxID>& txId = boost::none);

    class SimpleTransaction : public BaseTransaction
    {
    public:
        enum State : uint8_t
        {
            Initial,
            Invitation,
            PeerConfirmation,
            
            InvitationConfirmation,
            Registration,

            KernelConfirmation,
            OutputsConfirmation,
        };

        class Creator : public BaseTransaction::Creator
        {
        public:
            Creator(IWalletDB::Ptr walletDB, bool withAssets);
        private:
            BaseTransaction::Ptr Create(INegotiatorGateway& gateway
                                      , IWalletDB::Ptr walletDB
                                      , const TxID& txID) override;
            TxParameters CheckAndCompleteParameters(const TxParameters& parameters) override;
        private:
            IWalletDB::Ptr m_WalletDB;
            bool m_withAssets;
        };
    private:
        SimpleTransaction(INegotiatorGateway& gateway
                        , IWalletDB::Ptr walletDB
                        , const TxID& txID
                        , bool withAssets);
    private:
        TxType GetType() const override;
        bool IsInSafety() const override;
        void UpdateImpl() override;
        bool ShouldNotifyAboutChanges(TxParameterID paramID) const override;
        void SendInvitation(const BaseTxBuilder& builder, bool isSender);
        void ConfirmInvitation(const BaseTxBuilder& builder);
        void NotifyTransactionRegistered();
        bool IsSelfTx() const;
        State GetState() const;

    private:
        enum AssetCheckState {
            ACInitial,
            ACConfirmation,
            ACCheck,
        };

        enum AssetCheckResult {
            Fail,
            Async,
            OK,
        };

        AssetCheckResult CheckAsset(const BaseTxBuilder& builder);
        AssetCheckState m_assetCheckState = AssetCheckState::ACInitial;
        bool m_withAssets;

    private:
        std::shared_ptr<BaseTxBuilder> m_TxBuilder;
    };
}
