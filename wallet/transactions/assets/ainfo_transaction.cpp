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

#include "ainfo_transaction.h"
#include "utility/logger.h"
#include "wallet/core/strings_resources.h"
#include "wallet/core/wallet.h"
#include "assets_kdf_utils.h"

namespace hds::wallet
{
    BaseTransaction::Ptr AssetInfoTransaction::Creator::Create(INegotiatorGateway& gateway,
            IWalletDB::Ptr walletDB, const TxID& txID)
    {
        return BaseTransaction::Ptr(new AssetInfoTransaction(gateway, walletDB, txID));
    }

    TxParameters AssetInfoTransaction::Creator::CheckAndCompleteParameters(const TxParameters& params)
    {
        if(params.GetParameter<WalletID>(TxParameterID::PeerID))
        {
            throw InvalidTransactionParametersException("Asset registration: unexpected PeerID");
        }

        if(params.GetParameter<WalletID>(TxParameterID::MyID))
        {
            throw InvalidTransactionParametersException("Asset registration: unexpected MyID");
        }

        const auto isSenderO = params.GetParameter<bool>(TxParameterID::IsSender);
        if (!isSenderO || !isSenderO.get())
        {
            throw InvalidTransactionParametersException("Asset registration: non-sender transaction");
        }

        const auto isInitiatorO = params.GetParameter<bool>(TxParameterID::IsInitiator);
        if (!isInitiatorO || !isInitiatorO.get())
        {
            throw InvalidTransactionParametersException("Asset registration: non-initiator transaction");
        }

        TxParameters result{params};
        result.SetParameter(TxParameterID::IsSelfTx, true);
        result.SetParameter(TxParameterID::MyID, WalletID(Zero)); // Mandatory parameter
        result.SetParameter(TxParameterID::Amount, Amount(0)); // Mandatory parameter
        return result;
    }

    AssetInfoTransaction::AssetInfoTransaction(INegotiatorGateway& gateway
                                        , IWalletDB::Ptr walletDB
                                        , const TxID& txID)
        : AssetTransaction(gateway, std::move(walletDB), txID)
    {
    }

    void AssetInfoTransaction::UpdateImpl()
    {
        if (!AssetTransaction::BaseUpdate())
        {
            return;
        }

        if (GetState() == State::Initial)
        {
            UpdateTxDescription(TxStatus::InProgress);
            SetState(State::AssetConfirmation);
            ConfirmAsset();
            return;
        }

        if (GetState() == State::AssetConfirmation)
        {
            Height auHeight = 0;
            GetParameter(TxParameterID::AssetUnconfirmedHeight, auHeight);
            if (auHeight)
            {
                OnFailed(TxFailureReason::AssetConfirmFailed);
                return;
            }

            Height acHeight = 0;
            GetParameter(TxParameterID::AssetConfirmedHeight, acHeight);
            if (!acHeight)
            {
                ConfirmAsset();
                return;
            }

            SetState(State::AssetCheck);
        }

        if (GetState() == State::AssetCheck)
        {
            Asset::Full info;
            if (!GetParameter(TxParameterID::AssetInfoFull, info) || !info.IsValid())
            {
                OnFailed(TxFailureReason::NoAssetInfo, true);
                return;
            }

            if (GetAssetID() != Asset::s_InvalidID)
            {
                if (GetAssetID() != info.m_ID)
                {
                    OnFailed(TxFailureReason::InvalidAssetId, true);
                    return;
                }
            }

            if (GetAssetOwnerID() != Asset::s_InvalidOwnerID)
            {
                if(GetAssetOwnerID() != info.m_Owner)
                {
                    OnFailed(TxFailureReason::InvalidAssetOwnerId, true);
                    return;
                }
            }

            std::string strMeta;
            fromByteBuffer(info.m_Metadata.m_Value, strMeta);
            SetParameter(TxParameterID::AssetMetadata, strMeta);
            SetParameter(TxParameterID::AssetID, info.m_ID);

            try
            {
                auto masterKdf = get_MasterKdfStrict();
                if (hds::wallet::GetAssetOwnerID(masterKdf, strMeta) == info.m_Owner)
                {
                    m_WalletDB->markAssetOwned(info.m_ID);
                    LOG_INFO() << GetTxID() << " You own this asset";
                }
            }
            catch(const TransactionFailedException& ex)
            {
                if (ex.GetReason() == TxFailureReason::NoMasterKey)
                {
                    LOG_WARNING() << GetTxID() << " Unable to get master key. Asset ownership won't be checked.";
                }
                else
                {
                    throw;
                }
            }
        }

        SetState(State::Finalzing);
        CompleteTx();
    }

    void AssetInfoTransaction::ConfirmAsset()
    {
        if (GetAssetID() != Asset::s_InvalidID)
        {
            GetGateway().confirm_asset(GetTxID(), GetAssetID(), kDefaultSubTxID);
            return;
        }

        if (GetAssetOwnerID() != Asset::s_InvalidOwnerID)
        {
            GetGateway().confirm_asset(GetTxID(), GetAssetOwnerID(), kDefaultSubTxID);
            return;
        }

        throw TransactionFailedException(true, TxFailureReason::NoAssetId);
    }

    bool AssetInfoTransaction::ShouldNotifyAboutChanges(TxParameterID paramID) const
    {
        switch (paramID)
        {
        case TxParameterID::MinHeight:
        case TxParameterID::CreateTime:
        case TxParameterID::IsSender:
        case TxParameterID::Status:
        case TxParameterID::TransactionType:
            return true;
        default:
            return false;
        }
    }

    TxType AssetInfoTransaction::GetType() const
    {
        return TxType::AssetInfo;
    }

    AssetInfoTransaction::State AssetInfoTransaction::GetState() const
    {
        State state = State::Initial;
        GetParameter(TxParameterID::State, state);
        return state;
    }

    bool AssetInfoTransaction::IsInSafety() const
    {
        State txState = GetState();
        return txState >= State::AssetCheck;
    }

    Asset::ID AssetInfoTransaction::GetAssetID() const
    {
        Asset::ID assetId = Asset::s_InvalidID;
        GetParameter(TxParameterID::AssetID, assetId, kDefaultSubTxID);
        return assetId;
    }

    PeerID AssetInfoTransaction::GetAssetOwnerID() const
    {
        std::string strMeta;
        if (GetParameter(TxParameterID::AssetMetadata, strMeta, kDefaultSubTxID))
        {
            const auto masterKdf = get_MasterKdfStrict(); // can throw
            return hds::wallet::GetAssetOwnerID(masterKdf, strMeta);
        }
        return Asset::s_InvalidOwnerID;
    }
}
