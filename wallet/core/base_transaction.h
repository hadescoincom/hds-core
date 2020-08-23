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

#include <boost/optional.hpp>
#include "utility/logger.h"
#include "private_key_keeper.h"

#include <condition_variable>
#include <memory>

namespace hds::wallet
{
    TxID GenerateTxID();
    TxParameters CreateTransactionParameters(TxType type, const boost::optional<TxID>& oTxId = boost::optional<TxID>());
    //
    // Interface for all possible transaction types in active state
    //
    struct ITransaction
    {
        using Ptr = std::shared_ptr<ITransaction>;
        
        // Type of transaction
        virtual TxType GetType() const = 0;

        // Updates state of transation. 
        virtual void Update() = 0;

        virtual bool CanCancel() const = 0;

        // Cancel active transaction
        virtual void Cancel() = 0;
        
        // Rollback transation state up to give height
        virtual bool Rollback(Height height) = 0;

        // Returns true if negotiation is finished and all needed data is sent
        virtual bool IsInSafety() const = 0;
    };

    std::string GetFailureMessage(TxFailureReason reason);

    class TransactionFailedException : public std::runtime_error
    {
    public:
        TransactionFailedException(bool notify, TxFailureReason reason, const char* message = "");
        bool ShouldNofify() const;
        TxFailureReason GetReason() const;
    private:
        bool m_Notify;
        TxFailureReason m_Reason;
    };


    //
    // State machine for managing per transaction negotiations between wallets
    // 
    class BaseTransaction : public ITransaction
                          , public std::enable_shared_from_this<ITransaction>
    {
    public:
        using Ptr = std::shared_ptr<BaseTransaction>;

        class Creator
        {
        public:
            using Ptr = std::shared_ptr<Creator>;

            virtual ~Creator() = default;
            
            // �reates new instance of transaction (virtual constructor)
            virtual BaseTransaction::Ptr Create(INegotiatorGateway& gateway, WalletDB::Ptr, const TxID&) = 0;
            
            // Allows to add any additional user's checks and enhancements of parameters. Should throw exceptions if something is wrong
            virtual TxParameters CheckAndCompleteParameters(const TxParameters& p) { return p; } // TODO: find better solution without redundant copies
        };

        BaseTransaction(INegotiatorGateway& gateway
                      , IWalletDB::Ptr walletDB
                      , const TxID& txID);
        virtual ~BaseTransaction(){}

        const TxID& GetTxID() const;
        void Update() override;
        bool CanCancel() const override;
        void Cancel() override;

        bool Rollback(Height height) override;

        static const uint32_t s_ProtoVersion;

        virtual bool IsTxParameterExternalSettable(TxParameterID paramID, SubTxID subTxID) const
        {
            return true;
        }

        template <typename T>
        bool GetParameter(TxParameterID paramID, T& value, SubTxID subTxID = kDefaultSubTxID) const
        {
            return storage::getTxParameter(*m_WalletDB, GetTxID(), subTxID, paramID, value);
        }

        template <typename T>
        T GetMandatoryParameter(TxParameterID paramID, SubTxID subTxID = kDefaultSubTxID) const
        {
            T value{};
			
            if (!GetParameter(paramID, value, subTxID))
            {
                LOG_ERROR() << GetTxID() << " Failed to get parameter: " << (int)paramID;
                throw TransactionFailedException(true, TxFailureReason::FailedToGetParameter);
            }
            return value;
        }

        template <typename T>
        bool SetParameter(TxParameterID paramID, const T& value, SubTxID subTxID = kDefaultSubTxID)
        {
            bool shouldNotifyAboutChanges = ShouldNotifyAboutChanges(paramID);
            return SetParameter(paramID, value, shouldNotifyAboutChanges, subTxID);
        }

        template <typename T>
        bool SetParameter(TxParameterID paramID, const T& value, bool shouldNotifyAboutChanges, SubTxID subTxID = kDefaultSubTxID)
        {
            return storage::setTxParameter(*m_WalletDB, GetTxID(), subTxID, paramID, value, shouldNotifyAboutChanges);
        }

        template <typename T>
        void SetState(T state, SubTxID subTxID = kDefaultSubTxID)
        {
            SetParameter(TxParameterID::State, state, true, subTxID);
        }

        IWalletDB::Ptr GetWalletDB();
        IPrivateKeyKeeper2::Ptr get_KeyKeeperStrict(); // throws TxFailureReason::NoKeyKeeper if no key keeper (read-only mode)
        Key::IKdf::Ptr get_MasterKdfStrict() const; // throws TxFailureReason::NoMasterKey if no master key
        static void TestKeyKeeperRet(IPrivateKeyKeeper2::Status::Type); // throws TxFailureReason::KeyKeeperError on error
        static TxFailureReason KeyKeeperErrorToFailureReason(IPrivateKeyKeeper2::Status::Type);
        IAsyncContext& GetAsyncAcontext() const;
        bool IsInitiator() const;
        uint32_t get_PeerVersion() const;
        bool GetTip(Block::SystemState::Full& state) const;
        void UpdateAsync();
        void UpdateOnNextTip();
        INegotiatorGateway& GetGateway() const;

        IPrivateKeyKeeper2::Slot::Type GetSlotSafe(bool bAllocateIfAbsent);
        void FreeSlotSafe();

        virtual void FreeResources();
        virtual void OnFailed(TxFailureReason reason, bool notify = false);

    protected:
        
        virtual bool CheckExpired();
        virtual bool CheckExternalFailures();
        void ConfirmKernel(const Merkle::Hash& kernelID);
        void CompleteTx();
        virtual void RollbackTx();
        virtual void NotifyFailure(TxFailureReason);
        void UpdateTxDescription(TxStatus s);

        bool SendTxParameters(SetTxParameter&& msg) const;
        virtual void UpdateImpl() = 0;

        virtual bool ShouldNotifyAboutChanges(TxParameterID paramID) const { return true; };
        void SetCompletedTxCoinStatuses(Height proofHeight);
    protected:

        INegotiatorGateway& m_Gateway;
        IWalletDB::Ptr m_WalletDB;

        TxID m_ID;
        mutable boost::optional<bool> m_IsInitiator;
        io::AsyncEvent::Ptr m_EventToUpdate;
    };
}