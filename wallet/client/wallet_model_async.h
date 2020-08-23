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

#include "wallet/core/wallet.h"
#include "wallet/core/wallet_db.h"
#include "wallet/core/wallet_network.h"

namespace hds::wallet
{

#ifdef HDS_ATOMIC_SWAP_SUPPORT
    struct SwapOffer;
#endif  // HDS_ATOMIC_SWAP_SUPPORT
    struct IWalletModelAsync
    {
        using Ptr = std::shared_ptr<IWalletModelAsync>;

        virtual void sendMoney(const WalletID& receiver, const std::string& comment, Amount amount, Amount fee = 0) = 0;
        virtual void sendMoney(const WalletID& sender, const WalletID& receiver, const std::string& comment, Amount amount, Amount fee = 0) = 0;
        virtual void startTransaction(TxParameters&& parameters) = 0;
        virtual void syncWithNode() = 0;
        virtual void calcChange(Amount amount) = 0;
        virtual void getWalletStatus() = 0;
        virtual void getTransactions() = 0;
        virtual void getUtxosStatus() = 0;
        virtual void getAddresses(bool own) = 0;
        virtual void cancelTx(const TxID& id) = 0;
        virtual void deleteTx(const TxID& id) = 0;
        virtual void getCoinsByTx(const TxID& txId) = 0;
        virtual void saveAddress(const WalletAddress& address, bool bOwn) = 0;
        virtual void generateNewAddress() = 0;
#ifdef HDS_ATOMIC_SWAP_SUPPORT
        virtual void loadSwapParams() = 0;
        virtual void storeSwapParams(const hds::ByteBuffer& params) = 0;
        virtual void getSwapOffers() = 0;
        virtual void publishSwapOffer(const SwapOffer& offer) = 0;
#endif  // HDS_ATOMIC_SWAP_SUPPORT
        virtual void deleteAddress(const WalletID& id) = 0;
        virtual void updateAddress(const WalletID& id, const std::string& name, WalletAddress::ExpirationStatus status) = 0;
        virtual void activateAddress(const WalletID& id) = 0;

        virtual void setNodeAddress(const std::string& addr) = 0;

        virtual void changeWalletPassword(const hds::SecString& password) = 0;

        virtual void getNetworkStatus() = 0;
        virtual void rescan() = 0;
        virtual void exportPaymentProof(const TxID& id) = 0;

        virtual void checkAddress(const std::string& addr) = 0;

        virtual void importRecovery(const std::string& path) = 0;
        virtual void importDataFromJson(const std::string& data) = 0;
        virtual void exportDataToJson() = 0;
        virtual void exportTxHistoryToCsv() = 0;

        virtual void switchOnOffExchangeRates(bool isActive) = 0;
        virtual void switchOnOffNotifications(Notification::Type type, bool isActive) = 0;

        virtual void getNotifications() = 0;
        virtual void markNotificationAsRead(const ECC::uintBig& id) = 0;
        virtual void deleteNotification(const ECC::uintBig& id) = 0;

        virtual void getExchangeRates() = 0;

        virtual ~IWalletModelAsync() {}
    };
}
