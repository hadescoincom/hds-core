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

#include "wallet/transactions/swaps/swap_transaction.h"

#include "bitcoin/bitcoin.hpp"

#include "lock_tx_builder.h"
#include "shared_tx_builder.h"
#include "bridges/bitcoin/bitcoin_side.h"
#include "wallet/core/wallet.h"

using namespace ECC;

namespace hds::wallet
{
    namespace
    {
    template<typename T>
    void copyParameter(TxParameterID id, const TxParameters& source, TxParameters& dest)
    {
        if (auto p = source.GetParameter<T>(id); p)
        {
            dest.SetParameter(id, *p);
        }
    }
    }  // namespace

    void FillSwapTxParams(TxParameters* params,
                          const WalletID& myID,
                          Height minHeight,
                          Amount amount,
                          Amount hdsFee,
                          AtomicSwapCoin swapCoin,
                          Amount swapAmount,
                          Amount swapFeeRate,
                          bool isHdsSide /*= true*/,
                          Height responseTime /*= kDefaultTxResponseTime*/,
                          Height lifetime /*= kDefaultTxLifetime*/)
    {
        params->SetParameter(TxParameterID::MyID, myID);
        params->SetParameter(TxParameterID::MinHeight, minHeight);
        params->SetParameter(TxParameterID::Amount, amount);
        params->SetParameter(TxParameterID::AtomicSwapCoin, swapCoin);
        params->SetParameter(TxParameterID::AtomicSwapAmount, swapAmount);
        params->SetParameter(TxParameterID::AtomicSwapIsHdsSide, isHdsSide);
        params->SetParameter(TxParameterID::IsSender, isHdsSide);
        params->SetParameter(TxParameterID::IsInitiator, false);

        FillSwapFee(params, hdsFee, swapFeeRate, isHdsSide);

        params->SetParameter(TxParameterID::Lifetime, lifetime);
        params->SetParameter(TxParameterID::PeerResponseTime, responseTime);

#ifdef HDS_LIB_VERSION
        params->SetParameter(hds::wallet::TxParameterID::LibraryVersion, std::string(HDS_LIB_VERSION));
#endif // HDS_LIB_VERSION
    }

    void FillSwapFee(
        TxParameters* params, Amount hdsFee,
        Amount swapFeeRate, bool isHdsSide/* = true*/)
    {
        if (isHdsSide)
        {
            params->SetParameter(
                TxParameterID::Fee, hdsFee, SubTxIndex::HDS_LOCK_TX);
            params->SetParameter(
                TxParameterID::Fee, hdsFee, SubTxIndex::HDS_REFUND_TX);
            params->SetParameter(
                TxParameterID::Fee, swapFeeRate, SubTxIndex::REDEEM_TX);
        }
        else
        {
            params->SetParameter(
                TxParameterID::Fee, hdsFee, SubTxIndex::HDS_REDEEM_TX);
            params->SetParameter(
                TxParameterID::Fee, swapFeeRate, SubTxIndex::LOCK_TX);
            params->SetParameter(
                TxParameterID::Fee, swapFeeRate, SubTxIndex::REFUND_TX);
        }
    }

    TxParameters MirrorSwapTxParams(const TxParameters& original,
                                    bool isOwn  /* = true */)
    {
        auto res = CreateSwapTransactionParameters(original.GetTxID());

        copyParameter<Height>(TxParameterID::MinHeight, original, res);
        copyParameter<Height>(TxParameterID::PeerResponseTime, original, res);
        copyParameter<Timestamp>(TxParameterID::CreateTime, original, res);
        copyParameter<Height>(TxParameterID::Lifetime, original, res);

        copyParameter<Amount>(TxParameterID::Amount, original, res);
        copyParameter<Amount>(TxParameterID::AtomicSwapAmount, original, res);
        copyParameter<AtomicSwapCoin>(
            TxParameterID::AtomicSwapCoin, original, res);

        copyParameter<std::string>(TxParameterID::ClientVersion, original, res);
        copyParameter<std::string>(TxParameterID::LibraryVersion, original, res);

        if (isOwn)
        {
            auto myId = *original.GetParameter<WalletID>(TxParameterID::MyID);
            res.SetParameter(TxParameterID::PeerID, myId);
            res.DeleteParameter(TxParameterID::MyID);
        }
        else
        {
            auto myId = *original.GetParameter<WalletID>(TxParameterID::PeerID);
            res.SetParameter(TxParameterID::MyID, myId);
            res.DeleteParameter(TxParameterID::PeerID);
        }
        

        bool isInitiator =
            *original.GetParameter<bool>(TxParameterID::IsInitiator);
        res.SetParameter(TxParameterID::IsInitiator, !isInitiator);

        bool isHdsSide =
            *original.GetParameter<bool>(TxParameterID::AtomicSwapIsHdsSide);

        res.SetParameter(TxParameterID::AtomicSwapIsHdsSide, !isHdsSide);
        res.SetParameter(TxParameterID::IsSender, !isHdsSide);

        return res;
    }

    TxParameters PrepareSwapTxParamsForTokenization(
        const TxParameters& original)
    {
        auto res = CreateSwapTransactionParameters(original.GetTxID());
        copyParameter<Height>(TxParameterID::MinHeight, original, res);
        copyParameter<Height>(TxParameterID::PeerResponseTime, original, res);
        copyParameter<Timestamp>(TxParameterID::CreateTime, original, res);
        copyParameter<Height>(TxParameterID::Lifetime, original, res);

        copyParameter<Amount>(TxParameterID::Amount, original, res);
        copyParameter<Amount>(TxParameterID::AtomicSwapAmount, original, res);
        copyParameter<AtomicSwapCoin>(
            TxParameterID::AtomicSwapCoin, original, res);

        copyParameter<WalletID>(TxParameterID::PeerID, original, res);
        copyParameter<bool>(TxParameterID::IsInitiator, original, res);
        copyParameter<bool>(TxParameterID::AtomicSwapIsHdsSide, original, res);
        copyParameter<bool>(TxParameterID::IsSender, original, res);

        copyParameter<std::string>(TxParameterID::ClientVersion, original, res);
        copyParameter<std::string>(TxParameterID::LibraryVersion, original, res);

        return res;
    }

    TxParameters CreateSwapTransactionParameters(
        const boost::optional<TxID>& oTxId /*= boost::none*/)
    {
        const auto txID = oTxId ? *oTxId : GenerateTxID();
        return TxParameters(txID)
            .SetParameter(TxParameterID::TransactionType, TxType::AtomicSwap)
            .SetParameter(TxParameterID::IsInitiator, false)
            .SetParameter(TxParameterID::CreateTime, getTimestamp());
    }

    template <typename T>
    boost::optional<T> GetTxParameterAsOptional(const BaseTransaction& tx, TxParameterID paramID, SubTxID subTxID = kDefaultSubTxID)
    {
        if (T value{}; tx.GetParameter(paramID, value, subTxID))
        {
            return value;
        }
        return boost::optional<T>();
    }

    bool IsCommonTxParameterExternalSettable(TxParameterID paramID, const boost::optional<bool>& isInitiator)
    {
        switch (paramID)
        {
            case TxParameterID::AtomicSwapExternalLockTime:
                return isInitiator && !*isInitiator;
            case TxParameterID::PeerProtoVersion:
            case TxParameterID::AtomicSwapPeerPublicKey:
            case TxParameterID::FailureReason:
            case TxParameterID::AtomicSwapPeerPrivateKey:
                return true;
            default:
                return false;
        }
    }

    bool IsHdsLockTxParameterExternalSettable(TxParameterID paramID, const boost::optional<bool>& isHdsSide, const boost::optional<bool>& isInitiator)
    {
        switch (paramID)
        {
            case TxParameterID::MinHeight:
                return isInitiator && !isInitiator.get();
            case TxParameterID::Fee:
                return isHdsSide && !isHdsSide.get();
            case TxParameterID::PeerSignature:
            case TxParameterID::PeerOffset:
            case TxParameterID::PeerSharedBulletProofPart3:
                return isHdsSide && isHdsSide.get();
            case TxParameterID::PeerMaxHeight:
            case TxParameterID::PeerPublicNonce:
            case TxParameterID::PeerPublicExcess:
            case TxParameterID::PeerSharedBulletProofPart2:
            case TxParameterID::PeerPublicSharedBlindingFactor:
                return true;
            default:
                return false;
        }
    }

    bool IsHdsWithdrawTxParameterExternalSettable(TxParameterID paramID, SubTxID subTxID, const boost::optional<bool>& isHdsSide)
    {
        boost::optional<bool> isTxOwner;
        if (isHdsSide)
        {
            isTxOwner = (isHdsSide.get() && (SubTxIndex::HDS_REFUND_TX == subTxID)) || (!isHdsSide.get() && (SubTxIndex::HDS_REDEEM_TX == subTxID));
        }

        switch (paramID)
        {
            case TxParameterID::Amount:
            case TxParameterID::Fee:
            case TxParameterID::MinHeight:
                return isTxOwner && !isTxOwner.get();
            case TxParameterID::PeerOffset:
                return isTxOwner && isTxOwner.get();
            case TxParameterID::PeerPublicExcess:
            case TxParameterID::PeerPublicNonce:
            case TxParameterID::PeerSignature:
                return true;
            default:
                return false;
        }
    }

    ///
    AtomicSwapTransaction::WrapperSecondSide::WrapperSecondSide(ISecondSideProvider& gateway, BaseTransaction& tx)
        : m_gateway(gateway)
        , m_tx(tx)
    {
    }

    SecondSide::Ptr AtomicSwapTransaction::WrapperSecondSide::operator -> ()
    {
        return GetSecondSide();
    }

    SecondSide::Ptr AtomicSwapTransaction::WrapperSecondSide::GetSecondSide()
    {
        if (!m_secondSide)
        {
            m_secondSide = m_gateway.GetSecondSide(m_tx);

            if (!m_secondSide)
            {
                throw UninitilizedSecondSide();
            }
        }

        return m_secondSide;
    }

    ////////////
    // Creator
    AtomicSwapTransaction::Creator::Creator(IWalletDB::Ptr walletDB)
        : m_walletDB(walletDB)
    {

    }

    void AtomicSwapTransaction::Creator::RegisterFactory(AtomicSwapCoin coinType, ISecondSideFactory::Ptr factory)
    {
        m_factories.emplace(coinType, factory);
    }

    BaseTransaction::Ptr AtomicSwapTransaction::Creator::Create(INegotiatorGateway& gateway
                                                              , IWalletDB::Ptr walletDB
                                                              , const TxID& txID)
    {
        return BaseTransaction::Ptr(new AtomicSwapTransaction(gateway, walletDB, txID, *this));
    }

    SecondSide::Ptr AtomicSwapTransaction::Creator::GetSecondSide(BaseTransaction& tx)
    {
        AtomicSwapCoin coinType = tx.GetMandatoryParameter<AtomicSwapCoin>(TxParameterID::AtomicSwapCoin);
        auto it = m_factories.find(coinType);
        if (it == m_factories.end())
        {
            throw SecondSideFactoryNotRegisteredException();
        }
        bool isHdsSide = tx.GetMandatoryParameter<bool>(TxParameterID::AtomicSwapIsHdsSide);
        return it->second->CreateSecondSide(tx, isHdsSide);
    }

    TxParameters AtomicSwapTransaction::Creator::CheckAndCompleteParameters(const TxParameters& parameters)
    {
        auto peerID = parameters.GetParameter<WalletID>(TxParameterID::PeerID);
        if (peerID)
        {
            auto receiverAddr = m_walletDB->getAddress(*peerID);
            if (receiverAddr && receiverAddr->isOwn())
            {
                LOG_INFO() << "Failed to initiate the atomic swap. Not able to use own address as receiver's.";
                throw FailToStartSwapException();
            }
        }
        return parameters;
    }

    AtomicSwapTransaction::AtomicSwapTransaction(INegotiatorGateway& gateway
                                               , IWalletDB::Ptr walletDB
                                               , const TxID& txID
                                               , ISecondSideProvider& secondSideProvider)
        : BaseTransaction(gateway, walletDB, txID)
        , m_secondSide(secondSideProvider, *this)
    {
    }

    bool AtomicSwapTransaction::CanCancel() const
    {
        State state = GetState(kDefaultSubTxID);

        switch (state)
        {
        case State::HandlingContractTX:
            if (!IsHdsSide())
            {
                break;
            }
        case State::Initial:
        case State::BuildingHdsLockTX:
        case State::BuildingHdsRedeemTX:
        case State::BuildingHdsRefundTX:
        {
            return true;
        }
        default:
            break;
        }

        return false;
    }

    void AtomicSwapTransaction::Cancel()
    {
        if (CanCancel())
        {
            SetNextState(State::Canceled);
            return;
        }

        LOG_INFO() << GetTxID() << " You cannot cancel transaction in state: " << static_cast<int>(GetState(kDefaultSubTxID));
    }

    bool AtomicSwapTransaction::Rollback(Height height)
    {
        Height proofHeight = 0;
        bool isRolledback = false;

        if (IsHdsSide())
        {
            if (GetParameter(TxParameterID::KernelProofHeight, proofHeight, SubTxIndex::HDS_REFUND_TX)
                && proofHeight > height)
            {
                SetParameter(TxParameterID::KernelProofHeight, Height(0), false, SubTxIndex::HDS_REFUND_TX);
                SetParameter(TxParameterID::KernelUnconfirmedHeight, Height(0), false, SubTxIndex::HDS_REFUND_TX);

                SetState(State::SendingHdsRefundTX);
                isRolledback = true;
            }

            if (GetParameter(TxParameterID::KernelProofHeight, proofHeight, SubTxIndex::HDS_LOCK_TX)
                && proofHeight > height)
            {
                SetParameter(TxParameterID::KernelProofHeight, Height(0), false, SubTxIndex::HDS_LOCK_TX);
                SetParameter(TxParameterID::KernelUnconfirmedHeight, Height(0), false, SubTxIndex::HDS_LOCK_TX);

                SetState(State::SendingHdsLockTX);
                isRolledback = true;
            }
        }
        else
        {
            if (GetParameter(TxParameterID::KernelProofHeight, proofHeight, SubTxIndex::HDS_REDEEM_TX)
                && proofHeight > height)
            {
                SetParameter(TxParameterID::KernelProofHeight, Height(0), false, SubTxIndex::HDS_REDEEM_TX);
                SetParameter(TxParameterID::KernelUnconfirmedHeight, Height(0), false, SubTxIndex::HDS_REDEEM_TX);

                SetState(State::SendingHdsRedeemTX);
                isRolledback = true;
            }
        }

        if (isRolledback)
        {
            UpdateTxDescription(TxStatus::InProgress);
        }

        return isRolledback;
    }

    bool AtomicSwapTransaction::IsTxParameterExternalSettable(TxParameterID paramID, SubTxID subTxID) const
    {
        switch (subTxID)
        {
            case kDefaultSubTxID:
            {
                auto isInitiator = GetTxParameterAsOptional<bool>(*this, TxParameterID::IsInitiator);
                return IsCommonTxParameterExternalSettable(paramID, isInitiator);
            }
            case SubTxIndex::HDS_LOCK_TX:
            {
                auto isHdsSide = GetTxParameterAsOptional<bool>(*this, TxParameterID::AtomicSwapIsHdsSide);
                auto isInitiator = GetTxParameterAsOptional<bool>(*this, TxParameterID::IsInitiator);
                return IsHdsLockTxParameterExternalSettable(paramID, isHdsSide, isInitiator);
            }
            case SubTxIndex::HDS_REDEEM_TX:
            case SubTxIndex::HDS_REFUND_TX:
            {
                auto isHdsSide = GetTxParameterAsOptional<bool>(*this, TxParameterID::AtomicSwapIsHdsSide);
                return IsHdsWithdrawTxParameterExternalSettable(paramID, subTxID, isHdsSide);
            }
            case SubTxIndex::LOCK_TX:
            {
                if (bool isHdsSide = false; GetParameter(TxParameterID::AtomicSwapIsHdsSide, isHdsSide) && isHdsSide)
                {
                    return TxParameterID::AtomicSwapExternalTxID == paramID
                        || TxParameterID::AtomicSwapExternalTxOutputIndex == paramID;
                }
                return false;
            }
            case SubTxIndex::REDEEM_TX:
                return false;
            case SubTxIndex::REFUND_TX:
                return false;
            default:
                assert(false && "unexpected subTxID!");
                return false;
        }
    }

    void AtomicSwapTransaction::SetNextState(State state)
    {
        SetState(state);
        UpdateAsync();
    }

    TxType AtomicSwapTransaction::GetType() const
    {
        return TxType::AtomicSwap;
    }

    bool AtomicSwapTransaction::IsInSafety() const
    {
        auto isRegistered = [this](SubTxID hdsSubTxID, SubTxID coinSubTxID)
        {
            bool isHdsSide = GetMandatoryParameter<bool>(TxParameterID::AtomicSwapIsHdsSide);
            uint8_t status = proto::TxStatus::Unspecified;
            if (GetParameter(TxParameterID::TransactionRegistered, status, isHdsSide ? coinSubTxID : hdsSubTxID))
            {
                return status == proto::TxStatus::Ok;
            }
            return false;
        };

        State state = GetState(kDefaultSubTxID);
        switch (state)
        {
        case State::Initial:
        case State::Failed:
        case State::Canceled:
        case State::Refunded:
        case State::CompleteSwap:
            return true;
        case State::SendingRedeemTX:
        case State::SendingHdsRedeemTX:
            return isRegistered(HDS_REDEEM_TX, REDEEM_TX);
        case State::SendingRefundTX:
        case State::SendingHdsRefundTX:
            return isRegistered(HDS_REFUND_TX, REFUND_TX);
        default:
            return false;
        }
    }

    AtomicSwapTransaction::State AtomicSwapTransaction::GetState(SubTxID subTxID) const
    {
        State state = State::Initial;
        GetParameter(TxParameterID::State, state, subTxID);
        return state;
    }

    AtomicSwapTransaction::SubTxState AtomicSwapTransaction::GetSubTxState(SubTxID subTxID) const
    {
        SubTxState state = SubTxState::Initial;
        GetParameter(TxParameterID::State, state, subTxID);
        return state;
    }

    Amount AtomicSwapTransaction::GetWithdrawFee() const
    {
        // TODO(alex.starun): implement fee calculation
        return kMinFeeInGroth;
    }

    void AtomicSwapTransaction::UpdateImpl()
    {
        try
        {
            CheckSubTxFailures();

            State state = GetState(kDefaultSubTxID);
            bool isHdsOwner = IsHdsSide();

            switch (state)
            {
            case State::Initial:
            {
                if (Height responseHeight = MaxHeight; !GetParameter(TxParameterID::PeerResponseHeight, responseHeight))
                {
                    Height minHeight = GetMandatoryParameter<Height>(TxParameterID::MinHeight);
                    Height responseTime = GetMandatoryParameter<Height>(TxParameterID::PeerResponseTime);
                    SetParameter(TxParameterID::PeerResponseHeight, minHeight + responseTime);
                }

                // validate Lifetime
                Height lifeTime = GetMandatoryParameter<Height>(TxParameterID::Lifetime);
                if (lifeTime > kHdsLockTxLifetimeMax)
                {
                    LOG_ERROR() << GetTxID() << "[" << static_cast<SubTxID>(SubTxIndex::HDS_LOCK_TX) << "] " << "Transaction's lifetime is unacceptable.";
                    OnSubTxFailed(TxFailureReason::InvalidTransaction, SubTxIndex::HDS_LOCK_TX, true);
                    break;
                }

                if (IsInitiator())
                {
                    if (!m_secondSide->Initialize())
                    {
                        break;
                    }

                    m_secondSide->InitLockTime();

                    // Init HDS_LOCK_TX MinHeight
                    auto currentHeight = GetWalletDB()->getCurrentHeight();
                    SetParameter(TxParameterID::MinHeight, currentHeight, false, SubTxIndex::HDS_LOCK_TX);

                    SendInvitation();
                    LOG_INFO() << GetTxID() << " Invitation sent.";
                }
                else
                {
                    // TODO: refactor this
                    // hack, used for increase refCount!
                    auto secondSide = m_secondSide.GetSecondSide();

                    Height lockTime = 0;
                    if (!GetParameter(TxParameterID::AtomicSwapExternalLockTime, lockTime))
                    {
                        //we doesn't have an answer from other participant
                        UpdateOnNextTip();
                        break;
                    }

                    if (!secondSide->Initialize())
                    {
                        break;
                    }

                    if (!secondSide->ValidateLockTime())
                    {
                        LOG_ERROR() << GetTxID() << "[" << static_cast<SubTxID>(SubTxIndex::LOCK_TX) << "] " << "Lock height is unacceptable.";
                        OnSubTxFailed(TxFailureReason::InvalidTransaction, SubTxIndex::LOCK_TX, true);
                        break;
                    }

                    // validate HDS_LOCK_TX MinHeight
                    // mainMinHeight < minHeight < mainPeerResponseHeight
                    Height mainMinHeight = GetMandatoryParameter<Height>(TxParameterID::MinHeight);
                    Height mainPeerResponseHeight = GetMandatoryParameter<Height>(TxParameterID::PeerResponseHeight);
                    auto minHeight = GetMandatoryParameter<Height>(TxParameterID::MinHeight, SubTxIndex::HDS_LOCK_TX);
                    if (minHeight < mainMinHeight || minHeight >= mainPeerResponseHeight)
                    {
                        OnSubTxFailed(TxFailureReason::MinHeightIsUnacceptable, SubTxIndex::HDS_LOCK_TX, true);
                        break;
                    }
                }

                // save LifeTime & MaxHeight for HDS_LOCK_TX
                Height hdsLockTxMaxHeight = GetMandatoryParameter<Height>(TxParameterID::MinHeight, SubTxIndex::HDS_LOCK_TX) + lifeTime;
                SetParameter(TxParameterID::Lifetime, lifeTime, false, SubTxIndex::HDS_LOCK_TX);
                SetParameter(TxParameterID::MaxHeight, hdsLockTxMaxHeight, false, SubTxIndex::HDS_LOCK_TX);

                SetNextState(State::BuildingHdsLockTX);
                break;
            }
            case State::BuildingHdsLockTX:
            {
                auto lockTxState = BuildHdsLockTx();
                if (lockTxState != SubTxState::Constructed)
                {
                    UpdateOnNextTip();
                    break;
                }
                LOG_INFO() << GetTxID() << " Hds LockTX constructed.";
                SetNextState(State::BuildingHdsRefundTX);
                break;
            }
            case State::BuildingHdsRefundTX:
            {
                auto subTxState = BuildHdsWithdrawTx(SubTxIndex::HDS_REFUND_TX, m_WithdrawTx);
                if (subTxState != SubTxState::Constructed)
                    break;

                m_WithdrawTx.reset();
                LOG_INFO() << GetTxID() << " Hds RefundTX constructed.";
                SetNextState(State::BuildingHdsRedeemTX);
                break;
            }
            case State::BuildingHdsRedeemTX:
            {
                auto subTxState = BuildHdsWithdrawTx(SubTxIndex::HDS_REDEEM_TX, m_WithdrawTx);
                if (subTxState != SubTxState::Constructed)
                    break;

                m_WithdrawTx.reset();
                LOG_INFO() << GetTxID() << " Hds RedeemTX constructed.";
                SetNextState(State::HandlingContractTX);
                break;
            }
            case State::HandlingContractTX:
            {
                if (!isHdsOwner)
                {
                    if (!m_secondSide->HasEnoughTimeToProcessLockTx())
                    {
                        OnFailed(NotEnoughTimeToFinishBtcTx, true);
                        break;
                    }
                    
                    if (!m_secondSide->SendLockTx())
                        break;

                    SendExternalTxDetails();

                    // Hds LockTx: switch to the state of awaiting for proofs
                    uint8_t nCode = proto::TxStatus::Ok; // compiler workaround (ref to static const)
                    SetParameter(TxParameterID::TransactionRegistered, nCode, false, SubTxIndex::HDS_LOCK_TX);
                }
                else
                {
                    if (!m_secondSide->ConfirmLockTx())
                    {
                        UpdateOnNextTip();
                        break;
                    }
                }

                LOG_INFO() << GetTxID() << " LockTX completed.";
                SetNextState(State::SendingHdsLockTX);
                break;
            }
            case State::SendingRefundTX:
            {
                assert(!isHdsOwner);

                m_WalletDB->deleteCoinsCreatedByTx(GetTxID());

                if (!m_secondSide->IsLockTimeExpired() && !m_secondSide->IsQuickRefundAvailable())
                {
                    UpdateOnNextTip();
                    break;
                }

                if (!m_secondSide->SendRefund())
                    break;

                if (!m_secondSide->ConfirmRefundTx())
                {
                    UpdateOnNextTip();
                    break;
                }

                LOG_INFO() << GetTxID() << " RefundTX completed!";
                SetNextState(State::Refunded);
                break;
            }
            case State::SendingRedeemTX:
            {
                assert(isHdsOwner);
                if (!m_secondSide->SendRedeem())
                    break;

                if (!m_secondSide->ConfirmRedeemTx())
                {
                    UpdateOnNextTip();
                    break;
                }

                LOG_INFO() << GetTxID() << " RedeemTX completed!";
                SetNextState(State::CompleteSwap);
                break;
            }
            case State::SendingHdsLockTX:
            {
                if (!m_LockTx && isHdsOwner)
                {
                    BuildHdsLockTx();
                }

                if (m_LockTx && !SendSubTx(m_LockTx, SubTxIndex::HDS_LOCK_TX))
                    break;

                if (!isHdsOwner && m_secondSide->IsLockTimeExpired())
                {
                    LOG_INFO() << GetTxID() << " Locktime is expired.";
                    SetNextState(State::SendingRefundTX);
                    break;
                }

                if (!CompleteSubTx(SubTxIndex::HDS_LOCK_TX))
                    break;

                LOG_INFO() << GetTxID() << " Hds LockTX completed.";
                SetNextState(State::SendingHdsRedeemTX);
                break;
            }
            case State::SendingHdsRedeemTX:
            {
                if (isHdsOwner)
                {
                    UpdateOnNextTip();

                    if (IsHdsLockTimeExpired())
                    {
                        // If we already got SecretPrivateKey for RedeemTx, don't send refundTx,
                        // because it looks like we got rollback and we just should rerun TX's.
                        NoLeak<uintBig> secretPrivateKey;
                        if (!GetParameter(TxParameterID::AtomicSwapSecretPrivateKey, secretPrivateKey.V, SubTxIndex::HDS_REDEEM_TX))
                        {
                            Height kernelUnconfirmedHeight = 0;
                            GetParameter(TxParameterID::KernelUnconfirmedHeight, kernelUnconfirmedHeight, SubTxIndex::HDS_REDEEM_TX);
                            Height refundMinHeight = MaxHeight;
                            GetParameter(TxParameterID::MinHeight, refundMinHeight, SubTxIndex::HDS_REFUND_TX);

                            if (kernelUnconfirmedHeight > refundMinHeight)
                            {
                                LOG_INFO() << GetTxID() << " Hds locktime expired.";
                                SetNextState(State::SendingHdsRefundTX);
                                break;
                            }
                        }
                    }

                    // request kernel body for getting secretPrivateKey
                    if (!GetKernelFromChain(SubTxIndex::HDS_REDEEM_TX))
                        break;

                    ExtractSecretPrivateKey();

                    // Redeem second Coin
                    SetNextState(State::SendingRedeemTX);
                }
                else
                {
                    if (!IsHdsRedeemTxRegistered() && !IsSafeToSendHdsRedeemTx())
                    {
                        LOG_INFO() << GetTxID() << " Not enough time to finish Hds redeem transaction.";
                        SetNextState(State::SendingRefundTX);
                        break;
                    }

                    if (!CompleteHdsWithdrawTx(SubTxIndex::HDS_REDEEM_TX))
                        break;

                    LOG_INFO() << GetTxID() << " Hds RedeemTX completed!";
                    SetNextState(State::CompleteSwap);
                }
                break;
            }
            case State::SendingHdsRefundTX:
            {
                assert(isHdsOwner);
                if (!IsHdsLockTimeExpired())
                {
                    UpdateOnNextTip();
                    break;
                }

                if (!CompleteHdsWithdrawTx(SubTxIndex::HDS_REFUND_TX))
                    break;

                LOG_INFO() << GetTxID() << " Hds Refund TX completed!";

                SendQuickRefundPrivateKey();
                SetNextState(State::Refunded);
                break;
            }
            case State::CompleteSwap:
            {
                LOG_INFO() << GetTxID() << " Swap completed.";
                UpdateTxDescription(TxStatus::Completed);
                GetGateway().on_tx_completed(GetTxID());
                break;
            }
            case State::Canceled:
            {
                LOG_INFO() << GetTxID() << " Transaction cancelled.";
                NotifyFailure(TxFailureReason::Canceled);
                UpdateTxDescription(TxStatus::Canceled);

                RollbackTx();

                GetGateway().on_tx_completed(GetTxID());
                break;
            }
            case State::Failed:
            {
                if (isHdsOwner)
                {
                    m_WalletDB->deleteCoinsCreatedByTx(GetTxID());
                }

                TxFailureReason reason = TxFailureReason::Unknown;
                if (GetParameter(TxParameterID::FailureReason, reason))
                {
                    if (reason == TxFailureReason::Canceled)
                    {
                        LOG_ERROR() << GetTxID() << " Swap cancelled. The other side has cancelled the transaction.";
                    }
                    else
                    {
                        LOG_ERROR() << GetTxID() << " The other side has failed the transaction. Reason: " << GetFailureMessage(reason);
                    }
                }
                else
                {
                    LOG_ERROR() << GetTxID() << " Transaction failed.";
                }
                UpdateTxDescription(TxStatus::Failed);
                GetGateway().on_tx_completed(GetTxID());
                break;
            }

            case State::Refunded:
            {
                LOG_INFO() << GetTxID() << " Swap has not succeeded.";
                UpdateTxDescription(TxStatus::Failed);
                GetGateway().on_tx_completed(GetTxID());
                break;
            }

            default:
                break;
            }
        }
        catch (const UninitilizedSecondSide&)
        {
        }
    }

    void AtomicSwapTransaction::RollbackTx()
    {
        LOG_INFO() << GetTxID() << " Rollback...";

        GetWalletDB()->rollbackTx(GetTxID());
    }

    void AtomicSwapTransaction::NotifyFailure(TxFailureReason reason)
    {
        SetTxParameter msg;
        msg.AddParameter(TxParameterID::FailureReason, reason);

        if (IsHdsSide())
        {
            State state = GetState(kDefaultSubTxID);

            switch (state)
            {
            case State::BuildingHdsLockTX:
            case State::BuildingHdsRedeemTX:
            case State::BuildingHdsRefundTX:
            case State::HandlingContractTX:
            case State::Canceled:
            {
                NoLeak<uintBig> secretPrivateKey;

                if (GetParameter(TxParameterID::AtomicSwapPrivateKey, secretPrivateKey.V))
                {
                    LOG_DEBUG() << GetTxID() << " send additional info for quick refund";

                    // send our private key of redeem tx. we are good :)
                    msg.AddParameter(TxParameterID::AtomicSwapPeerPrivateKey, secretPrivateKey.V);
                }
                break;
            }            
            default:
                break;
            }
        }
        SendTxParameters(std::move(msg));
    }

    void AtomicSwapTransaction::OnFailed(TxFailureReason reason, bool notify)
    {
        LOG_ERROR() << GetTxID() << " Failed. " << GetFailureMessage(reason);

        if (reason == TxFailureReason::NoInputs)
        {
            NotifyFailure(TxFailureReason::Canceled);
        }
        else if (notify)
        {
            NotifyFailure(reason);
        }

        SetParameter(TxParameterID::InternalFailureReason, reason, false);

        State state = GetState(kDefaultSubTxID);
        bool isHdsSide = IsHdsSide();

        switch (state)
        {
        case State::Initial:
        {
            break;
        }
        case State::BuildingHdsLockTX:
        case State::BuildingHdsRedeemTX:
        case State::BuildingHdsRefundTX:
        {
            RollbackTx();

            break;
        }
        case State::HandlingContractTX:
        {
            RollbackTx();
            
            break;
        }
        case State::SendingHdsLockTX:
        {
            if (isHdsSide)
            {
                RollbackTx();
                break;
            }
            else
            {
                SetNextState(State::SendingRefundTX);
                return;
            }
        }
        case State::SendingHdsRedeemTX:
        {
            if (isHdsSide)
            {
                assert(false && "Impossible case!");
                return;
            }
            else
            {
                SetNextState(State::SendingRefundTX);
                return;
            }
        }
        case State::SendingRedeemTX:
        {            
            if (isHdsSide)
            {
                LOG_ERROR() << GetTxID() << " Unexpected error.";
                return;
            }
            else
            {
                assert(false && "Impossible case!");
                return;
            }
            break;
        }
        default:
            return;
        }

        SetNextState(State::Failed);
    }

    bool AtomicSwapTransaction::CheckExpired()
    {
        TxFailureReason reason = TxFailureReason::Unknown;
        if (GetParameter(TxParameterID::InternalFailureReason, reason))
        {
            return false;
        }

        TxStatus s = TxStatus::Failed;
        if (GetParameter(TxParameterID::Status, s)
            && (s == TxStatus::Failed
                || s == TxStatus::Canceled
                || s == TxStatus::Completed))
        {
            return false;
        }

        Height lockTxMaxHeight = MaxHeight;
        if (!GetParameter(TxParameterID::MaxHeight, lockTxMaxHeight, SubTxIndex::HDS_LOCK_TX)
            && !GetParameter(TxParameterID::PeerResponseHeight, lockTxMaxHeight))
        {
            return false;
        }

        uint8_t nRegistered = proto::TxStatus::Unspecified;
        Merkle::Hash kernelID;
        if (!GetParameter(TxParameterID::TransactionRegistered, nRegistered, SubTxIndex::HDS_LOCK_TX)
            || !GetParameter(TxParameterID::KernelID, kernelID, SubTxIndex::HDS_LOCK_TX))
        {
            Block::SystemState::Full state;
            if (GetTip(state) && state.m_Height > lockTxMaxHeight)
            {
                LOG_INFO() << GetTxID() << " Transaction expired. Current height: " << state.m_Height << ", max kernel height: " << lockTxMaxHeight;
                OnFailed(TxFailureReason::TransactionExpired, false);
                return true;
            }
        }
        else
        {
            Height lastUnconfirmedHeight = 0;
            if (GetParameter(TxParameterID::KernelUnconfirmedHeight, lastUnconfirmedHeight, SubTxIndex::HDS_LOCK_TX) && lastUnconfirmedHeight > 0)
            {
                if (lastUnconfirmedHeight >= lockTxMaxHeight)
                {
                    LOG_INFO() << GetTxID() << " Transaction expired. Last unconfirmed height: " << lastUnconfirmedHeight << ", max kernel height: " << lockTxMaxHeight;
                    OnFailed(TxFailureReason::TransactionExpired, false);
                    return true;
                }
            }
        }
        return false;
    }

    bool AtomicSwapTransaction::CheckExternalFailures()
    {
        TxFailureReason reason = TxFailureReason::Unknown;
        if (GetParameter(TxParameterID::FailureReason, reason))
        {
            State state = GetState(kDefaultSubTxID);

            switch (state)
            {
            case State::Initial:
            {
                SetState(State::Failed);
                break;
            }
            case State::BuildingHdsLockTX:
            case State::BuildingHdsRedeemTX:
            case State::BuildingHdsRefundTX:
            {
                RollbackTx();
                SetState(State::Failed);
                break;
            }
            case State::HandlingContractTX:
            {
                if (IsHdsSide())
                {
                    RollbackTx();
                    SetState(State::Failed);
                }

                break;
            }
            case State::SendingHdsLockTX:
            {
                if (!IsHdsSide() && m_secondSide->IsQuickRefundAvailable())
                {
                    if (reason == TxFailureReason::Canceled)
                    {
                        LOG_ERROR() << GetTxID() << " Swap cancelled. The other side has cancelled the transaction.";
                    }
                    else
                    {
                        LOG_ERROR() << GetTxID() << " The other side has failed the transaction. Reason: " << GetFailureMessage(reason);
                    }

                    SetState(State::SendingRefundTX);
                }

                break;
            }
            case State::SendingHdsRedeemTX:
            case State::SendingRedeemTX:
            {
                // nothing
                break;
            }
            default:
                break;
            }
        }
        return false;
    }

    bool AtomicSwapTransaction::CompleteHdsWithdrawTx(SubTxID subTxID)
    {
        if (!m_WithdrawTx)
        {
            BuildHdsWithdrawTx(subTxID, m_WithdrawTx);
        }

        if (m_WithdrawTx && !SendSubTx(m_WithdrawTx, subTxID))
        {
            return false;
        }

        if (!CompleteSubTx(subTxID))
        {
            return false;
        }

        return true;
    }

    AtomicSwapTransaction::SubTxState AtomicSwapTransaction::BuildHdsLockTx()
    {
        // load state
        SubTxState lockTxState = SubTxState::Initial;
        GetParameter(TxParameterID::State, lockTxState, SubTxIndex::HDS_LOCK_TX);

        bool isHdsOwner = IsHdsSide();
        Amount fee = 0;
        // Receiver must get fee along with LockTX invitation, hds owner should have fee
        if (!GetParameter<Amount>(TxParameterID::Fee, fee, SubTxIndex::HDS_LOCK_TX))
        {
            if (isHdsOwner)
            {
                OnSubTxFailed(TxFailureReason::FailedToGetParameter, SubTxIndex::HDS_LOCK_TX, true);
            }
            // else receiver don't have invitation from Hds side
            return lockTxState;
        }

        if (!m_pLockBuiler)
            m_pLockBuiler = std::make_shared<LockTxBuilder>(*this, GetAmount(), fee);
        LockTxBuilder* lockTxBuilder = m_pLockBuiler.get();

        if (!lockTxBuilder->GetInitialTxParams() && lockTxState == SubTxState::Initial)
        {
            if (isHdsOwner)
            {
                lockTxBuilder->SelectInputs();
                lockTxBuilder->AddChange();
            }
        }

        bool bI = lockTxBuilder->CreateInputs();
        bool bO = (isHdsOwner && lockTxBuilder->CreateOutputs());
        if (bI || bO)
            return lockTxState;

        lockTxBuilder->GenerateNonce();
        lockTxBuilder->LoadSharedParameters();

        if (!lockTxBuilder->GetPeerPublicExcessAndNonce())
        {
            if (lockTxState == SubTxState::Initial && isHdsOwner)
            {
                if (lockTxBuilder->SignSender(true, false))
                    return lockTxState;
                SendLockTxInvitation(*lockTxBuilder);
                SetState(SubTxState::Invitation, SubTxIndex::HDS_LOCK_TX);
                lockTxState = SubTxState::Invitation;
            }
            return lockTxState;
        }

        assert(fee);
        lockTxBuilder->CreateKernel();

        if (isHdsOwner)
        {
            if (lockTxBuilder->SignSender(false, false))
                return lockTxState;
        }
        else
        {
            if (lockTxBuilder->SignReceiver(false))
                return lockTxState;
        }

        if (lockTxState == SubTxState::Initial || lockTxState == SubTxState::Invitation)
        {
            if (!lockTxBuilder->CreateSharedUTXOProofPart2(isHdsOwner))
            {
                OnSubTxFailed(TxFailureReason::FailedToCreateMultiSig, SubTxIndex::HDS_LOCK_TX, true);
                return lockTxState;
            }

            if (!lockTxBuilder->CreateSharedUTXOProofPart3(isHdsOwner))
            {
                OnSubTxFailed(TxFailureReason::FailedToCreateMultiSig, SubTxIndex::HDS_LOCK_TX, true);
                return lockTxState;
            }

            SetState(SubTxState::Constructed, SubTxIndex::HDS_LOCK_TX);
            lockTxState = SubTxState::Constructed;

            UpdateTxDescription(TxStatus::InProgress);

            if (!isHdsOwner)
            {
                // send part2/part3!
                SendLockTxConfirmation(*lockTxBuilder);
                return lockTxState;
            }
        }

        if (!lockTxBuilder->GetPeerSignature())
        {
            return lockTxState;
        }

        if (!lockTxBuilder->IsPeerSignatureValid())
        {
            OnSubTxFailed(TxFailureReason::InvalidPeerSignature, SubTxIndex::HDS_LOCK_TX, true);
            return lockTxState;
        }

        lockTxBuilder->FinalizeSignature();

        if (isHdsOwner)
        {
            assert(lockTxState == SubTxState::Constructed);
            // Create TX
            auto transaction = lockTxBuilder->CreateTransaction();
            TxBase::Context::Params pars;
            TxBase::Context context(pars);
            context.m_Height.m_Min = lockTxBuilder->GetMinHeight();
            if (!transaction->IsValid(context))
            {
                OnSubTxFailed(TxFailureReason::InvalidTransaction, SubTxIndex::HDS_LOCK_TX, true);
                return lockTxState;
            }

            m_LockTx = transaction;
        }

        return lockTxState;
    }

    AtomicSwapTransaction::SubTxState AtomicSwapTransaction::BuildHdsWithdrawTx(SubTxID subTxID, Transaction::Ptr& resultTx)
    {
        SubTxState subTxState = GetSubTxState(subTxID);
        bool isTxOwner = (IsHdsSide() && (SubTxIndex::HDS_REFUND_TX == subTxID)) || (!IsHdsSide() && (SubTxIndex::HDS_REDEEM_TX == subTxID));

        Amount withdrawAmount = 0;
        Amount withdrawFee = 0;
        // Peer must get fee and amount along with WithdrawTX invitation, txOwner should have fee
        if (!GetParameter(TxParameterID::Fee, withdrawFee, subTxID))
        {
            if (isTxOwner)
            {
                OnSubTxFailed(TxFailureReason::FailedToGetParameter, subTxID, true);
            }
            return subTxState;
        }

        if (!GetParameter(TxParameterID::Amount, withdrawAmount, subTxID))
        {
            if (!isTxOwner)
            {
                // we don't have invitation from other side
                return subTxState;
            }
            // initialize withdrawAmount
            withdrawAmount = GetAmount() - withdrawFee;
            SetParameter(TxParameterID::Amount, withdrawAmount, subTxID);
        }

        if (!m_pSharedBuiler || (m_pSharedBuiler->GetSubTxID() != subTxID))
            m_pSharedBuiler = std::make_shared<SharedTxBuilder>(*this, subTxID, withdrawAmount, withdrawFee);
        SharedTxBuilder* builder = m_pSharedBuiler.get();

        if (!builder->GetSharedParameters())
        {
            return subTxState;
        }

        bool hasInputs = builder->GetInputs();
        bool hasOutputs = builder->GetOutputs();
        // send invite to get 
        if ((!builder->GetInitialTxParams() || !(hasInputs || hasOutputs)) && subTxState == SubTxState::Initial)
        {
            builder->InitTx(isTxOwner);
            {
                // validate minHeight
                auto minHeightLockTx = GetMandatoryParameter<Height>(TxParameterID::MinHeight, SubTxIndex::HDS_LOCK_TX);
                auto minHeight = builder->GetMinHeight();
                if ((SubTxIndex::HDS_REFUND_TX == subTxID && minHeight != minHeightLockTx + kHdsLockTimeInBlocks) ||
                    (SubTxIndex::HDS_REDEEM_TX == subTxID && minHeight != minHeightLockTx))
                {
                    OnSubTxFailed(TxFailureReason::MinHeightIsUnacceptable, subTxID, true);
                    return subTxState;
                }
            }
        }

        builder->GenerateNonce();
        builder->CreateKernel();

        if (!builder->GetPeerPublicExcessAndNonce())
        {
            if (subTxState == SubTxState::Initial && isTxOwner)
            {
                if (builder->SignSender(true, false))
                    return subTxState;
                SendSharedTxInvitation(*builder);
                SetState(SubTxState::Invitation, subTxID);
                subTxState = SubTxState::Invitation;
            }
            return subTxState;
        }


        if (!builder->GetPeerSignature())
        {
            if (subTxState == SubTxState::Initial && !isTxOwner)
            {
                if (builder->SignReceiver(false))
                    return subTxState;
                // invited participant
                ConfirmSharedTxInvitation(*builder);

                if (subTxID == SubTxIndex::HDS_REFUND_TX)
                {
                    SetState(SubTxState::Constructed, subTxID);
                    subTxState = SubTxState::Constructed;
                }
            }
            return subTxState;
        }

        if (builder->SignSender(false, false))
            return subTxState;

        if (subTxID == SubTxIndex::HDS_REDEEM_TX)
        {
            if (IsHdsSide())
            {
                // save SecretPublicKey
                {
                    auto peerPublicNonce = GetMandatoryParameter<Point::Native>(TxParameterID::PeerPublicNonce, subTxID);
                    Scalar::Native challenge;
                    {
                        Point::Native publicNonceNative = builder->GetPublicNonce() + peerPublicNonce;

                        // Signature::get_Challenge(e, m_NoncePub, msg);
						ECC::Signature sig;
						sig.m_NoncePub = publicNonceNative;
						sig.get_Challenge(challenge, builder->GetKernel().m_Internal.m_ID);
                    }

                    Scalar::Native peerSignature = GetMandatoryParameter<Scalar::Native>(TxParameterID::PeerSignature, subTxID);
                    auto peerPublicExcess = GetMandatoryParameter<Point::Native>(TxParameterID::PeerPublicExcess, subTxID);

                    Point::Native pt = Context::get().G * peerSignature;

                    pt += peerPublicExcess * challenge;
                    pt += peerPublicNonce;
                    assert(!(pt == Zero));

                    Point secretPublicKey;
                    pt.Export(secretPublicKey);

                    SetParameter(TxParameterID::AtomicSwapSecretPublicKey, secretPublicKey, subTxID);
                }

                SetState(SubTxState::Constructed, subTxID);
                return SubTxState::Constructed;
            }
            else
            {
                // Send BTC side partial sign with secret
                auto partialSign = builder->GetPartialSignature();
                Scalar secretPrivateKey;
                GetParameter(TxParameterID::AtomicSwapSecretPrivateKey, secretPrivateKey.m_Value, SubTxIndex::HDS_REDEEM_TX);
                partialSign += secretPrivateKey;

                SetTxParameter msg;
                msg.AddParameter(TxParameterID::SubTxIndex, builder->GetSubTxID())
                    .AddParameter(TxParameterID::PeerSignature, partialSign);

                if (!SendTxParameters(std::move(msg)))
                {
                    OnFailed(TxFailureReason::FailedToSendParameters, false);
                    return subTxState;
                }
            }
        }

        if (!builder->IsPeerSignatureValid())
        {
            OnSubTxFailed(TxFailureReason::InvalidPeerSignature, subTxID, true);
            return subTxState;
        }

        builder->FinalizeSignature();

        SetState(SubTxState::Constructed, subTxID);
        subTxState = SubTxState::Constructed;

        if (isTxOwner)
        {
            auto transaction = builder->CreateTransaction();
            TxBase::Context::Params pars;
            TxBase::Context context(pars);
            context.m_Height.m_Min = builder->GetMinHeight();
            if (!transaction->IsValid(context))
            {
                OnSubTxFailed(TxFailureReason::InvalidTransaction, subTxID, true);
                return subTxState;
            }
            resultTx = transaction;
        }

        return subTxState;
    }

    bool AtomicSwapTransaction::SendSubTx(Transaction::Ptr transaction, SubTxID subTxID)
    {
    	uint8_t nRegistered = proto::TxStatus::Unspecified;
        if (!GetParameter(TxParameterID::TransactionRegistered, nRegistered, subTxID))
        {
            GetGateway().register_tx(GetTxID(), transaction, subTxID);
            return false;
        }

        if (proto::TxStatus::Ok != nRegistered) // we have to ensure that this transaction hasn't already added to blockchain)
        {
            Height lastUnconfirmedHeight = 0;
            if (GetParameter(TxParameterID::KernelUnconfirmedHeight, lastUnconfirmedHeight, subTxID) && lastUnconfirmedHeight > 0)
            {
                OnSubTxFailed(TxFailureReason::FailedToRegister, subTxID, subTxID == SubTxIndex::HDS_LOCK_TX);
                return false;
            }
        }

        return true;
    }

    bool AtomicSwapTransaction::IsHdsLockTimeExpired() const
    {
        Height refundMinHeight = MaxHeight;
        GetParameter(TxParameterID::MinHeight, refundMinHeight, SubTxIndex::HDS_REFUND_TX);

        Block::SystemState::Full state;

        return GetTip(state) && state.m_Height > refundMinHeight;
    }

    bool AtomicSwapTransaction::IsHdsRedeemTxRegistered() const
    {
        uint8_t nRegistered = proto::TxStatus::Unspecified;
        return GetParameter(TxParameterID::TransactionRegistered, nRegistered, SubTxIndex::HDS_REDEEM_TX);
    }

    bool AtomicSwapTransaction::IsSafeToSendHdsRedeemTx() const
    {
        Height minHeight = MaxHeight;
        GetParameter(TxParameterID::MinHeight, minHeight, SubTxIndex::HDS_LOCK_TX);

        Block::SystemState::Full state;

        return GetTip(state) && state.m_Height < (minHeight + kMaxSentTimeOfHdsRedeemInBlocks);
    }

    bool AtomicSwapTransaction::CompleteSubTx(SubTxID subTxID)
    {
        Height hProof = 0;
        GetParameter(TxParameterID::KernelProofHeight, hProof, subTxID);
        if (!hProof)
        {
            Merkle::Hash kernelID = GetMandatoryParameter<Merkle::Hash>(TxParameterID::KernelID, subTxID);
            GetGateway().confirm_kernel(GetTxID(), kernelID, subTxID);
            return false;
        }

        if (SubTxIndex::HDS_REFUND_TX == subTxID)
        {
            // store Coin in DB
            auto amount = GetMandatoryParameter<Amount>(TxParameterID::Amount, subTxID);
            Coin withdrawUtxo(amount);

            withdrawUtxo.m_createTxId = GetTxID();
            withdrawUtxo.m_ID = GetMandatoryParameter<Coin::ID>(TxParameterID::SharedCoinID, subTxID);

            GetWalletDB()->saveCoin(withdrawUtxo);
        }

        SetCompletedTxCoinStatuses(hProof);

        return true;
    }

    bool AtomicSwapTransaction::GetKernelFromChain(SubTxID subTxID) const
    {
        Height hProof = 0;
        GetParameter(TxParameterID::KernelProofHeight, hProof, subTxID);

        if (!hProof)
        {
            Merkle::Hash kernelID = GetMandatoryParameter<Merkle::Hash>(TxParameterID::KernelID, SubTxIndex::HDS_REDEEM_TX);
            GetGateway().get_kernel(GetTxID(), kernelID, subTxID);
            return false;
        }

        return true;
    }

    Amount AtomicSwapTransaction::GetAmount() const
    {
        if (!m_Amount.is_initialized())
        {
            m_Amount = GetMandatoryParameter<Amount>(TxParameterID::Amount);
        }
        return *m_Amount;
    }

    bool AtomicSwapTransaction::IsSender() const
    {
        if (!m_IsSender.is_initialized())
        {
            m_IsSender = GetMandatoryParameter<bool>(TxParameterID::IsSender);
        }
        return *m_IsSender;
    }

    bool AtomicSwapTransaction::IsHdsSide() const
    {
        if (!m_IsHdsSide.is_initialized())
        {
            bool isHdsSide = false;
            GetParameter(TxParameterID::AtomicSwapIsHdsSide, isHdsSide);
            m_IsHdsSide = isHdsSide;
        }
        return *m_IsHdsSide;
    }

    void AtomicSwapTransaction::SendInvitation()
    {
        auto swapPublicKey = GetMandatoryParameter<std::string>(TxParameterID::AtomicSwapPublicKey);
        auto swapLockTime = GetMandatoryParameter<Timestamp>(TxParameterID::AtomicSwapExternalLockTime);
        Height hdsLockTxMinHeight = GetMandatoryParameter<Height>(TxParameterID::MinHeight, SubTxIndex::HDS_LOCK_TX);

        // send invitation
        SetTxParameter msg;
        msg.AddParameter(TxParameterID::PeerProtoVersion, s_ProtoVersion)
            .AddParameter(TxParameterID::AtomicSwapPeerPublicKey, swapPublicKey)
            .AddParameter(TxParameterID::AtomicSwapExternalLockTime, swapLockTime)
            .AddParameter(TxParameterID::SubTxIndex, SubTxIndex::HDS_LOCK_TX)
            .AddParameter(TxParameterID::MinHeight, hdsLockTxMinHeight);

        if (!SendTxParameters(std::move(msg)))
        {
            OnFailed(TxFailureReason::FailedToSendParameters, false);
        }
    }

    void AtomicSwapTransaction::SendExternalTxDetails()
    {
        SetTxParameter msg;
        m_secondSide->AddTxDetails(msg);

        if (!SendTxParameters(std::move(msg)))
        {
            OnFailed(TxFailureReason::FailedToSendParameters, false);
        }
    }

    void AtomicSwapTransaction::SendLockTxInvitation(const LockTxBuilder& lockBuilder)
    {
        auto swapPublicKey = GetMandatoryParameter<std::string>(TxParameterID::AtomicSwapPublicKey);

        SetTxParameter msg;
        msg.AddParameter(TxParameterID::PeerProtoVersion, s_ProtoVersion)
            .AddParameter(TxParameterID::AtomicSwapPeerPublicKey, swapPublicKey)
            .AddParameter(TxParameterID::SubTxIndex, SubTxIndex::HDS_LOCK_TX)
            .AddParameter(TxParameterID::Fee, lockBuilder.GetFee())
            .AddParameter(TxParameterID::PeerPublicExcess, lockBuilder.GetPublicExcess())
            .AddParameter(TxParameterID::PeerPublicNonce, lockBuilder.GetPublicNonce())
            .AddParameter(TxParameterID::PeerSharedBulletProofPart2, lockBuilder.GetRangeProofInitialPart2())
            .AddParameter(TxParameterID::PeerPublicSharedBlindingFactor, lockBuilder.GetPublicSharedBlindingFactor());

        if (!SendTxParameters(std::move(msg)))
        {
            OnFailed(TxFailureReason::FailedToSendParameters, false);
        }
    }

    void AtomicSwapTransaction::SendLockTxConfirmation(const LockTxBuilder& lockBuilder)
    {
        auto bulletProof = lockBuilder.GetSharedProof();

        SetTxParameter msg;
        msg.AddParameter(TxParameterID::PeerProtoVersion, s_ProtoVersion)
            .AddParameter(TxParameterID::SubTxIndex, SubTxIndex::HDS_LOCK_TX)
            .AddParameter(TxParameterID::PeerPublicExcess, lockBuilder.GetPublicExcess())
            .AddParameter(TxParameterID::PeerPublicNonce, lockBuilder.GetPublicNonce())
            .AddParameter(TxParameterID::PeerSignature, lockBuilder.GetPartialSignature())
            .AddParameter(TxParameterID::PeerOffset, lockBuilder.GetOffset())
            .AddParameter(TxParameterID::PeerSharedBulletProofPart2, lockBuilder.GetRangeProofInitialPart2())
            .AddParameter(TxParameterID::PeerSharedBulletProofPart3, bulletProof.m_Part3)
            .AddParameter(TxParameterID::PeerPublicSharedBlindingFactor, lockBuilder.GetPublicSharedBlindingFactor());

        if (!SendTxParameters(std::move(msg)))
        {
            OnFailed(TxFailureReason::FailedToSendParameters, false);
        }
    }

    void AtomicSwapTransaction::SendSharedTxInvitation(const BaseTxBuilder& builder)
    {
        SetTxParameter msg;
        msg.AddParameter(TxParameterID::SubTxIndex, builder.GetSubTxID())
            .AddParameter(TxParameterID::Amount, builder.GetAmount())
            .AddParameter(TxParameterID::Fee, builder.GetFee())
            .AddParameter(TxParameterID::MinHeight, builder.GetMinHeight())
            .AddParameter(TxParameterID::PeerPublicExcess, builder.GetPublicExcess())
            .AddParameter(TxParameterID::PeerPublicNonce, builder.GetPublicNonce());
    
        if (!SendTxParameters(std::move(msg)))
        {
            OnFailed(TxFailureReason::FailedToSendParameters, false);
        }
    }

    void AtomicSwapTransaction::ConfirmSharedTxInvitation(const BaseTxBuilder& builder)
    {
        SetTxParameter msg;
        msg.AddParameter(TxParameterID::SubTxIndex, builder.GetSubTxID())
            .AddParameter(TxParameterID::PeerPublicExcess, builder.GetPublicExcess())
            .AddParameter(TxParameterID::PeerSignature, builder.GetPartialSignature())
            .AddParameter(TxParameterID::PeerPublicNonce, builder.GetPublicNonce())
            .AddParameter(TxParameterID::PeerOffset, builder.GetOffset());

        if (!SendTxParameters(std::move(msg)))
        {
            OnFailed(TxFailureReason::FailedToSendParameters, false);
        }
    }

    void AtomicSwapTransaction::SendQuickRefundPrivateKey()
    {
        NoLeak<uintBig> secretPrivateKey;

        if (GetParameter(TxParameterID::AtomicSwapPrivateKey, secretPrivateKey.V))
        {
            LOG_DEBUG() << GetTxID() << " send additional info for quick refund";

            SetTxParameter msg;

            // send our private key of redeem tx. we are good :)
            msg.AddParameter(TxParameterID::AtomicSwapPeerPrivateKey, secretPrivateKey.V);
            SendTxParameters(std::move(msg));
        }
    }

    void AtomicSwapTransaction::OnSubTxFailed(TxFailureReason reason, SubTxID subTxID, bool notify)
    {
        TxFailureReason previousReason;

        if (GetParameter(TxParameterID::InternalFailureReason, previousReason, subTxID) && previousReason == reason)
        {
            return;
        }

        LOG_ERROR() << GetTxID() << "[" << subTxID << "]" << " Failed. " << GetFailureMessage(reason);

        SetParameter(TxParameterID::InternalFailureReason, reason, false, subTxID);
        OnFailed(TxFailureReason::SubTxFailed, notify);
    }

    void AtomicSwapTransaction::CheckSubTxFailures()
    {
        State state = GetState(kDefaultSubTxID);
        TxFailureReason reason = TxFailureReason::Unknown;

        if ((state == State::Initial ||
            state == State::HandlingContractTX) && GetParameter(TxParameterID::InternalFailureReason, reason, SubTxIndex::LOCK_TX))
        {
            OnFailed(reason, true);
        }
    }

    void AtomicSwapTransaction::ExtractSecretPrivateKey()
    {
        auto subTxID = SubTxIndex::HDS_REDEEM_TX;
        TxKernelStd::Ptr kernel = GetMandatoryParameter<TxKernelStd::Ptr>(TxParameterID::Kernel, subTxID);

        SharedTxBuilder builder{ *this, subTxID };
        builder.GetSharedParameters();
        builder.GetInitialTxParams();
        builder.GetPeerPublicExcessAndNonce();
        builder.GenerateNonce();
        builder.CreateKernel();
        if (builder.SignSender(false, false))
            return;

        Scalar::Native peerSignature = GetMandatoryParameter<Scalar::Native>(TxParameterID::PeerSignature, subTxID);
        Scalar::Native partialSignature = builder.GetPartialSignature();

        Scalar::Native fullSignature;
        fullSignature.Import(kernel->m_Signature.m_k);
        fullSignature = -fullSignature;
        Scalar::Native secretPrivateKeyNative = peerSignature + partialSignature;
        secretPrivateKeyNative += fullSignature;

        Scalar secretPrivateKey;
        secretPrivateKeyNative.Export(secretPrivateKey);

        SetParameter(TxParameterID::AtomicSwapSecretPrivateKey, secretPrivateKey.m_Value, false, HDS_REDEEM_TX);
    }

} // namespace