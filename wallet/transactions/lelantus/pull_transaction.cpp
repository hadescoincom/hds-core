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

#include "pull_transaction.h"
#include "core/shielded.h"
#include "pull_tx_builder.h"
#include "wallet/core/strings_resources.h"

namespace hds::wallet::lelantus
{
    TxParameters CreatePullTransactionParameters(const WalletID& myID, const boost::optional<TxID>& txId)
    {
        return CreateTransactionParameters(TxType::PullTransaction, txId)
            .SetParameter(TxParameterID::MyID, myID)
            .SetParameter(TxParameterID::IsSender, false);
    }

    BaseTransaction::Ptr PullTransaction::Creator::Create(INegotiatorGateway& gateway
        , IWalletDB::Ptr walletDB
        , const TxID& txID)
    {
        return BaseTransaction::Ptr(new PullTransaction(gateway, walletDB, txID, m_withAssets));
    }

    TxParameters PullTransaction::Creator::CheckAndCompleteParameters(const TxParameters& parameters)
    {
        // TODO roman.strilets implement this
        return parameters;
    }

    PullTransaction::PullTransaction(INegotiatorGateway& gateway
        , IWalletDB::Ptr walletDB
        , const TxID& txID
        , bool withAssets)
        : BaseTransaction(gateway, walletDB, txID)
        , m_withAssets(withAssets)
    {
    }

    TxType PullTransaction::GetType() const
    {
        return TxType::PullTransaction;
    }

    bool PullTransaction::IsInSafety() const
    {
        // TODO roman.strilets implement this
        return true;
    }

    void PullTransaction::UpdateImpl()
    {
        AmountList amoutList;
        if (!GetParameter(TxParameterID::AmountList, amoutList))
        {
            amoutList = AmountList{ GetMandatoryParameter<Amount>(TxParameterID::Amount) };
        }

        if (!m_TxBuilder)
        {
            m_TxBuilder = std::make_shared<PullTxBuilder>(*this, amoutList, GetMandatoryParameter<Amount>(TxParameterID::Fee), m_withAssets);
        }

        if (!m_TxBuilder->GetInitialTxParams())
        {
            UpdateTxDescription(TxStatus::InProgress);

            for (const auto& amount : m_TxBuilder->GetAmountList())
            {
                m_TxBuilder->GenerateUnlinkedCoin(amount);
            }

            TxoID shieldedId = GetMandatoryParameter<TxoID>(TxParameterID::ShieldedOutputId);
            auto shieldedCoin = GetWalletDB()->getShieldedCoin(shieldedId);

            const auto unitName = m_TxBuilder->IsAssetTx() ? kAmountASSET : "";
            const auto nthName  = m_TxBuilder->IsAssetTx() ? kAmountAGROTH : "";

            LOG_INFO() << GetTxID() << " Extracting from shielded pool:"
                << " ID - " << shieldedId << ", amount - " << PrintableAmount(shieldedCoin->m_value, false, unitName, nthName)
                << ", receiving amount - " << PrintableAmount(m_TxBuilder->GetAmount(), false, unitName, nthName)
                << " (fee: " << PrintableAmount(m_TxBuilder->GetFee()) << ")";

            // validate input
            {
                if (!shieldedCoin || !shieldedCoin->IsAvailable())
                {
                    throw TransactionFailedException(false, TxFailureReason::NoInputs);
                }

                // If HDS only we pay fee from shielded input
                // If asset we must have HDS inputs
                if (m_TxBuilder->IsAssetTx())
                {
                    m_TxBuilder->SelectFeeInputsPreferUnlinked();
                    m_TxBuilder->AddChange();
                }
                else
                {
                    Amount requiredAmount = m_TxBuilder->GetAmount() + m_TxBuilder->GetFee();
                    if (shieldedCoin->m_value < requiredAmount)
                    {
                        LOG_ERROR() << GetTxID() << " The ShieldedCoin value("
                                    << PrintableAmount(shieldedCoin->m_value)
                                    << ") is less than the required value(" << PrintableAmount(requiredAmount) << ")";
                        throw TransactionFailedException(false, TxFailureReason::NoInputs, "");
                    }
                }

                // update "m_spentTxId" for shieldedCoin
                shieldedCoin->m_spentTxId = GetTxID();
                GetWalletDB()->saveShieldedCoin(*shieldedCoin);
            }
        }

        if (m_TxBuilder->CreateInputs())
        {
            return;
        }

        if (m_TxBuilder->CreateOutputs())
        {
            return;
        }

        if (m_TxBuilder->GetShieldedList())
        {
            return;
        }

        uint8_t nRegistered = proto::TxStatus::Unspecified;
        if (!GetParameter(TxParameterID::TransactionRegistered, nRegistered))
        {
            if (CheckExpired())
            {
                return;
            }

            // Construct transaction
            auto transaction = m_TxBuilder->CreateTransaction();

            // Verify final transaction
            TxBase::Context::Params pars;
            TxBase::Context ctx(pars);
            ctx.m_Height.m_Min = m_TxBuilder->GetMinHeight();
            if (!transaction->IsValid(ctx))
            {
                OnFailed(TxFailureReason::InvalidTransaction, true);
                return;
            }

            // register TX
            GetGateway().register_tx(GetTxID(), transaction);
            return;
        }

        if (proto::TxStatus::InvalidContext == nRegistered) // we have to ensure that this transaction hasn't already added to blockchain)
        {
            Height lastUnconfirmedHeight = 0;
            if (GetParameter(TxParameterID::KernelUnconfirmedHeight, lastUnconfirmedHeight) && lastUnconfirmedHeight > 0)
            {
                OnFailed(TxFailureReason::FailedToRegister, true);
                return;
            }
        }
        else if (proto::TxStatus::Ok != nRegistered)
        {
            OnFailed(TxFailureReason::FailedToRegister, true);
            return;
        }

        // get Kernel proof
        Height hProof = 0;
        GetParameter(TxParameterID::KernelProofHeight, hProof);
        if (!hProof)
        {
            ConfirmKernel(m_TxBuilder->GetKernelID());
            return;
        }

        // update "m_spentHeight" for shieldedCoin
        auto shieldedCoinModified = GetWalletDB()->getShieldedCoin(GetTxID());
        if (shieldedCoinModified)
        {
            shieldedCoinModified->m_spentHeight = std::min(shieldedCoinModified->m_spentHeight, hProof);
            GetWalletDB()->saveShieldedCoin(shieldedCoinModified.get());
        }

        SetCompletedTxCoinStatuses(hProof);
        CompleteTx();
    }

    void PullTransaction::RollbackTx()
    {
        LOG_INFO() << GetTxID() << " Transaction failed. Rollback...";
        GetWalletDB()->restoreShieldedCoinsSpentByTx(GetTxID());
        GetWalletDB()->deleteCoinsCreatedByTx(GetTxID());
    }
} // namespace hds::wallet::lelantus