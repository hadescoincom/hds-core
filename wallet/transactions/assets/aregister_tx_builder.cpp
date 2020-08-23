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
#include "aregister_tx_builder.h"
#include "assets_kdf_utils.h"
#include "utility/logger.h"
#include "wallet/core/strings_resources.h"
#include <numeric>
#include <core/block_crypt.h>

namespace hds::wallet
{
    using namespace ECC;
    using namespace std;

    AssetRegisterTxBuilder::AssetRegisterTxBuilder(BaseTransaction& tx, SubTxID subTxID)
        : m_Tx{tx}
        , m_SubTxID(subTxID)
        , m_assetOwnerId(0UL)
        , m_Fee(0)
        , m_ChangeHds(0)
        , m_AmountList{0}
        , m_MinHeight(0)
        , m_MaxHeight(MaxHeight)
        , m_Offset(Zero)
    {
        auto masterKdf = m_Tx.get_MasterKdfStrict(); // can throw

        m_Fee = m_Tx.GetMandatoryParameter<Amount>(TxParameterID::Fee, m_SubTxID);

        if (!m_Tx.GetParameter(TxParameterID::AmountList, m_AmountList, m_SubTxID))
        {
            const auto amount = m_Tx.GetMandatoryParameter<Amount>(TxParameterID::Amount, m_SubTxID);
            if (amount < Rules::get().CA.DepositForList)
            {
                throw TransactionFailedException(!m_Tx.IsInitiator(), TxFailureReason::RegisterAmountTooSmall);
            }
            m_AmountList = AmountList{amount};
            m_Tx.SetParameter(TxParameterID::AmountList, m_AmountList, m_SubTxID);
        }

        m_Metadata = m_Tx.GetMandatoryParameter<std::string>(TxParameterID::AssetMetadata);
        if(m_Metadata.empty())
        {
            throw TransactionFailedException(!m_Tx.IsInitiator(), TxFailureReason::NoAssetMeta);
        }

        m_assetOwnerId = GetAssetOwnerID(masterKdf, m_Metadata);
        if (m_assetOwnerId == Zero)
        {
            throw TransactionFailedException(!m_Tx.IsInitiator(), TxFailureReason::NoAssetId);
        }
    }

    void AssetRegisterTxBuilder::CreateInputs()
    {
        if (GetInputs() || m_InputCoins.empty())
        {
            return;
        }

        auto masterKdf = m_Tx.get_MasterKdfStrict();
        m_Inputs = GenerateAssetInputs(masterKdf, m_InputCoins);
        m_Tx.SetParameter(TxParameterID::Inputs, m_Inputs, false, m_SubTxID);
    }

    bool AssetRegisterTxBuilder::GetInitialTxParams()
    {
        m_MinHeight = m_Tx.GetMandatoryParameter<Height>(TxParameterID::MinHeight, m_SubTxID);
        m_MaxHeight = m_Tx.GetMandatoryParameter<Height>(TxParameterID::MaxHeight, m_SubTxID);

        m_Tx.GetParameter(TxParameterID::Offset, m_Offset, m_SubTxID);
        m_Tx.GetParameter(TxParameterID::Inputs,     m_Inputs,      m_SubTxID);
        m_Tx.GetParameter(TxParameterID::Outputs,    m_Outputs,     m_SubTxID);

        bool hasICoins = m_Tx.GetParameter(TxParameterID::InputCoins, m_InputCoins,  m_SubTxID);
        bool hasOCoins =  m_Tx.GetParameter(TxParameterID::OutputCoins,m_OutputCoins, m_SubTxID);

        return hasICoins || hasOCoins;
    }

    bool AssetRegisterTxBuilder::LoadKernel()
    {
        if (m_Tx.GetParameter(TxParameterID::Kernel, m_kernel, m_SubTxID))
        {
            GetInitialTxParams();
            return true;
        }
        return false;
    }

    Transaction::Ptr AssetRegisterTxBuilder::CreateTransaction()
    {
        // Don't display in log infinite max height
        if (m_kernel->m_Height.m_Max == MaxHeight)
        {
            LOG_INFO() << m_Tx.GetTxID() << "[" << m_SubTxID << "]"
                << " Transaction created. Kernel: " << GetKernelIDString()
                << ", min height: " << m_kernel->m_Height.m_Min;
        }
        else
        {
            LOG_INFO() << m_Tx.GetTxID() << "[" << m_SubTxID << "]"
                << " Transaction created. Kernel: " << GetKernelIDString()
                << ", min height: " << m_kernel->m_Height.m_Min
                << ", max height: " << m_kernel->m_Height.m_Max;
        }

        auto tx = make_shared<Transaction>();

        tx->m_vInputs  = std::move(m_Inputs);
        tx->m_vOutputs = std::move(m_Outputs);
        tx->m_vKernels.push_back(std::move(m_kernel));

        m_Tx.SetParameter(TxParameterID::Offset, m_Offset, false, m_SubTxID);
        tx->m_Offset = m_Offset;
        tx->Normalize();

#ifdef DEBUG
        hds::Transaction::Context::Params pars;
        hds::Transaction::Context ctx(pars);
        ctx.m_Height.m_Min = m_MinHeight;
        assert(tx->IsValid(ctx));
#endif

        return tx;
    }

    Amount AssetRegisterTxBuilder::GetAmountHds() const
    {
        return std::accumulate(m_AmountList.begin(), m_AmountList.end(), 0ULL);
    }

    const AmountList& AssetRegisterTxBuilder::GetAmountList() const
    {
        return m_AmountList;
    }

    Height AssetRegisterTxBuilder::GetMinHeight() const
    {
        return m_MinHeight;
    }

    void AssetRegisterTxBuilder::AddChange()
    {
        if (m_ChangeHds)
        {
            GenerateHdsCoin(m_ChangeHds, true);
        }
    }

    Amount AssetRegisterTxBuilder::GetFee() const
    {
        return m_Fee;
    }

    PeerID AssetRegisterTxBuilder::GetAssetOwnerId() const
    {
        assert(m_assetOwnerId != Zero || !"Asset owner id is still zero");
        return m_assetOwnerId;
    }

    string AssetRegisterTxBuilder::GetKernelIDString() const {
        Merkle::Hash kernelID;
        m_Tx.GetParameter(TxParameterID::KernelID, kernelID, m_SubTxID);
        char sz[Merkle::Hash::nTxtLen + 1];
        kernelID.Print(sz);
        return string(sz);
    }

    bool AssetRegisterTxBuilder::GetInputs()
    {
        return m_Tx.GetParameter(TxParameterID::Inputs, m_Inputs, m_SubTxID);
    }

    bool AssetRegisterTxBuilder::GetOutputs()
    {
        return m_Tx.GetParameter(TxParameterID::Outputs, m_Outputs, m_SubTxID);
    }

    void AssetRegisterTxBuilder::SelectInputCoins()
    {
        CoinIDList preselIDs;
        vector<Coin> coins;

        Amount preselAmount  = 0;
        if (m_Tx.GetParameter(TxParameterID::PreselectedCoins, preselIDs, m_SubTxID))
        {
            if (!preselIDs.empty())
            {
                coins = m_Tx.GetWalletDB()->getCoinsByID(preselIDs);
                for (auto &coin : coins)
                {
                    preselAmount += coin.getAmount();
                    coin.m_spentTxId = m_Tx.GetTxID();
                }
                m_Tx.GetWalletDB()->saveCoins(coins);
            }
        }

        Amount amountWithFee = m_Fee + GetAmountHds();
        if (preselAmount < amountWithFee)
        {
            auto selectedCoins = m_Tx.GetWalletDB()->selectCoins(amountWithFee - preselAmount, Zero);
            if (selectedCoins.empty())
            {
                storage::Totals totals(*m_Tx.GetWalletDB());
                const auto& hdsTotals = totals.GetHdsTotals();
                LOG_ERROR() << m_Tx.GetTxID() << "[" << m_SubTxID << "]"
                            << "You need " << PrintableAmount(amountWithFee) << " for deposit and fees"
                            << " but have only " << PrintableAmount(hdsTotals.Avail);
                throw TransactionFailedException(!m_Tx.IsInitiator(), TxFailureReason::NoInputs);
            }
            copy(selectedCoins.begin(), selectedCoins.end(), back_inserter(coins));
        }

        m_InputCoins.reserve(coins.size());
        Amount totalHds = 0;
        for (auto& coin : coins)
        {
            coin.m_spentTxId = m_Tx.GetTxID();
            totalHds += coin.m_ID.m_Value;
            m_InputCoins.push_back(coin.m_ID);
        }

        m_ChangeHds  = totalHds  - amountWithFee;
        m_Tx.SetParameter(TxParameterID::ChangeHds,  m_ChangeHds,  false, m_SubTxID);
        m_Tx.SetParameter(TxParameterID::InputCoins,  m_InputCoins,  false, m_SubTxID);
        m_Tx.GetWalletDB()->saveCoins(coins);
    }

    void AssetRegisterTxBuilder::GenerateHdsCoin(Amount amount, bool change)
    {
        Coin newUtxo(amount, change ? Key::Type::Change : Key::Type::Regular);
        newUtxo.m_createTxId = m_Tx.GetTxID();

        m_Tx.GetWalletDB()->storeCoin(newUtxo);
        m_OutputCoins.push_back(newUtxo.m_ID);
        m_Tx.SetParameter(TxParameterID::OutputCoins, m_OutputCoins, false, m_SubTxID);

        LOG_INFO() << m_Tx.GetTxID()
                   << " Creating HDS coin" << (change ? " (change):" : ":")
                   << PrintableAmount(amount) << ", id " << newUtxo.toStringID();
    }

    void AssetRegisterTxBuilder::CreateOutputs()
    {
        if (GetOutputs() || m_OutputCoins.empty())
        {
            // if we already have outputs or there are no outputs, nothing to do here
            return;
        }

        auto masterKdf = m_Tx.get_MasterKdfStrict();
        m_Outputs = GenerateAssetOutputs(masterKdf, m_MinHeight, m_OutputCoins);
        m_Tx.SetParameter(TxParameterID::Outputs, m_Outputs, false, m_SubTxID);
    }

    const Merkle::Hash& AssetRegisterTxBuilder::GetKernelID() const
    {
        if (!m_kernelID)
        {
            Merkle::Hash kernelID;
            if (m_Tx.GetParameter(TxParameterID::KernelID, kernelID, m_SubTxID))
            {
                m_kernelID = kernelID;
            }
            else
            {
                assert(!"KernelID is not stored");
            }
        }
        return *m_kernelID;
    }

    void AssetRegisterTxBuilder::MakeKernel()
    {
        if (m_kernel) return; // already created

        m_kernel = make_unique<TxKernelAssetCreate>();
        m_kernel->m_Fee              = m_Fee;
        m_kernel->m_Height.m_Min     = GetMinHeight();
        m_kernel->m_Height.m_Max     = m_MaxHeight;
        m_kernel->m_Commitment       = Zero;
        m_kernel->m_MetaData.m_Value = toByteBuffer(m_Metadata);
        m_kernel->m_MetaData.UpdateHash();

        auto masterKdf = m_Tx.get_MasterKdfStrict();
        m_Offset = SignAssetKernel(masterKdf, m_InputCoins, m_OutputCoins, m_Metadata, *m_kernel);
        const Merkle::Hash& kernelID = m_kernel->m_Internal.m_ID;

        m_Tx.SetParameter(TxParameterID::Offset, m_Offset, m_SubTxID);
        m_Tx.SetParameter(TxParameterID::KernelID, kernelID, m_SubTxID);
        m_Tx.SetParameter(TxParameterID::Kernel, m_kernel, m_SubTxID);
    }
}
