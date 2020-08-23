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
#include "wallet/core/wallet_db.h"
#include "wallet/core/base_transaction.h"
#include "utility/logger.h"

namespace hds::wallet
{
    class BaseTransaction;
    class AssetRegisterTxBuilder: public std::enable_shared_from_this<AssetRegisterTxBuilder>
    {
    public:
        AssetRegisterTxBuilder(BaseTransaction& tx, SubTxID subTxID);

        bool GetInitialTxParams();
        Transaction::Ptr CreateTransaction();

        //
        // Coins, amounts & fees
        //
        Amount GetFee() const;
        Amount GetAmountHds() const;
        const AmountList& GetAmountList() const;
        void AddChange();
        void SelectInputCoins();
        bool GetInputs();
        bool GetOutputs();
        void GenerateHdsCoin(Amount amount, bool change);
        void CreateInputs();
        void CreateOutputs();

        PeerID GetAssetOwnerId() const;

        //
        // Blockchain stuff
        //
        const Merkle::Hash& GetKernelID() const;
        bool LoadKernel();
        void MakeKernel();

        std::string GetKernelIDString() const;
        Height GetMinHeight() const;

    private:
        BaseTransaction& m_Tx;
        SubTxID m_SubTxID;

        PeerID m_assetOwnerId;
        std::string m_Metadata;

        Amount     m_Fee;
        Amount     m_ChangeHds;
        AmountList m_AmountList;
        Height     m_MinHeight;
        Height     m_MaxHeight;

        std::vector<Input::Ptr>  m_Inputs;
        std::vector<Output::Ptr> m_Outputs;
        CoinIDList m_InputCoins;
        CoinIDList m_OutputCoins;

        //
        // Blockchain stuff
        //
        ECC::Scalar::Native m_Offset;
        TxKernelAssetCreate::Ptr m_kernel;
        mutable boost::optional<Merkle::Hash> m_kernelID;
    };
}
