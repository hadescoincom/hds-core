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

#include "base_lelantus_tx_builder.h"
#include "core/shielded.h"

namespace hds::wallet::lelantus
{
    BaseLelantusTxBuilder::BaseLelantusTxBuilder(BaseTransaction& tx, const AmountList& amount, Amount fee, bool withAssets)
        : BaseTxBuilder(tx, kDefaultSubTxID, amount, fee)
        , m_withAssets(withAssets)
    {
    }

    bool BaseLelantusTxBuilder::GetInitialTxParams()
    {
        bool result = BaseTxBuilder::GetInitialTxParams();

        // Initialize MaxHeight, MaxHeight = MinHeight + Lifetime
        if (Height maxHeight = MaxHeight; !m_Tx.GetParameter(TxParameterID::MaxHeight, maxHeight))
        {
            maxHeight = GetMinHeight() + GetLifetime();
            m_Tx.SetParameter(TxParameterID::MaxHeight, maxHeight);
        }

        const bool isAsset = GetAssetId() != Asset::s_InvalidID;
        if (isAsset)
        {
            if (!Rules::get().CA.Enabled)
            {
                throw TransactionFailedException(true, TxFailureReason::AssetsDisabledFork2);
            }

            if (!m_withAssets)
            {
                throw TransactionFailedException(true, TxFailureReason::AssetsDisabled);
            }
        }

        return result;
    }
   
    Height BaseLelantusTxBuilder::GetMaxHeight() const
    {
        return m_Tx.GetMandatoryParameter<Height>(TxParameterID::MaxHeight, m_SubTxID);
    }

    void BaseLelantusTxBuilder::Restore(ShieldedTxo::DataParams& sdp, const ShieldedCoin& sc, const ShieldedTxo::Viewer& viewer)
    {
        sdp.m_Ticket.m_pK[0] = sc.m_Key.m_kSerG;
        sdp.m_Ticket.m_IsCreatedByViewer = sc.m_Key.m_IsCreatedByViewer;
        sdp.m_Ticket.Restore(viewer);

        sdp.m_Output.m_Value = sc.m_value;
        sdp.m_Output.m_AssetID = sc.m_assetID;
        sdp.m_Output.m_User = sc.m_User;

        sdp.m_Output.Restore_kG(sdp.m_Ticket.m_SharedSecret);
    }
} // namespace hds::wallet::lelantus