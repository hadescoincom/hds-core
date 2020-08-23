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

#include "wallet/client/wallet_client.h"

class WalletModel
    : public hds::wallet::WalletClient
{
public:

    using Ptr = std::shared_ptr<WalletModel>;

    WalletModel(hds::wallet::IWalletDB::Ptr walletDB, const std::string& nodeAddr, hds::io::Reactor::Ptr reactor);
    ~WalletModel() override;

private:
    void onStatus(const hds::wallet::WalletStatus& status) override;
    void onTxStatus(hds::wallet::ChangeAction, const std::vector<hds::wallet::TxDescription>& items) override;
    void onSyncProgressUpdated(int done, int total) override;
    void onChangeCalculated(hds::Amount change) override;
    void onAllUtxoChanged(hds::wallet::ChangeAction, const std::vector<hds::wallet::Coin>& utxos) override;
    void onAddressesChanged(hds::wallet::ChangeAction, const std::vector<hds::wallet::WalletAddress>& addresses) override;
    void onAddresses(bool own, const std::vector<hds::wallet::WalletAddress>& addrs) override;
#ifdef HDS_ATOMIC_SWAP_SUPPORT
    void onSwapOffersChanged(hds::wallet::ChangeAction action, const std::vector<hds::wallet::SwapOffer>& offers) override;
#endif  // HDS_ATOMIC_SWAP_SUPPORT
    void onGeneratedNewAddress(const hds::wallet::WalletAddress& walletAddr) override;
    void onSwapParamsLoaded(const hds::ByteBuffer& params) override;
    void onNewAddressFailed() override;
    void onNodeConnectionChanged(bool isNodeConnected) override;
    void onWalletError(hds::wallet::ErrorType error) override;
    void FailedToStartWallet() override;
    void onSendMoneyVerified() override;
    void onCantSendToExpired() override;
    void onPaymentProofExported(const hds::wallet::TxID& txID, const hds::ByteBuffer& proof) override;
    void onCoinsByTx(const std::vector<hds::wallet::Coin>& coins) override;
    void onAddressChecked(const std::string& addr, bool isValid) override;
    void onImportRecoveryProgress(uint64_t done, uint64_t total) override;
    void onNoDeviceConnected() override {}
    void onImportDataFromJson(bool isOk) override;
    void onExportDataToJson(const std::string& data) override;
    void onShowKeyKeeperMessage() override {}
    void onHideKeyKeeperMessage() override {}
    void onShowKeyKeeperError(const std::string&) override {}
    void onPostFunctionToClientContext(MessageFunction&& func) override {};
    void onExportTxHistoryToCsv(const std::string& data) override {};
    void onNotificationsChanged(hds::wallet::ChangeAction action, const std::vector<hds::wallet::Notification>&) override;
    void onExchangeRates(const std::vector<hds::wallet::ExchangeRate>&) override;
};
