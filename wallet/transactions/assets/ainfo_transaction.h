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

#include "asset_base_tx.h"
#include "utility/logger.h"

namespace hds::wallet
{
    class AssetInfoTransaction : public AssetTransaction
    {
    public:
        class Creator : public BaseTransaction::Creator
        {
        public:
            explicit Creator() = default;

        private:
            BaseTransaction::Ptr Create(INegotiatorGateway& gateway, IWalletDB::Ptr walletDB, const TxID& txID) override;
            TxParameters CheckAndCompleteParameters(const TxParameters& p) override;

            IWalletDB::Ptr _walletDB;
        };

    private:
        AssetInfoTransaction(INegotiatorGateway& gateway, IWalletDB::Ptr walletDB, const TxID& txID);
        TxType GetType() const override;
        bool IsInSafety() const override;

        void UpdateImpl() override;
        bool ShouldNotifyAboutChanges(TxParameterID paramID) const override;
        void ConfirmAsset();

        enum State : uint8_t
        {
            Initial,
            AssetConfirmation,
            AssetCheck,
            Finalzing
        };

        State GetState() const;
        Asset::ID GetAssetID() const;
        PeerID GetAssetOwnerID() const;
    };
}