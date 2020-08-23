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

#include "utility/logger.h"
#include "core/proto.h"
#include "utility/io/timer.h"
#include "bbs_miner.h"
#include <boost/intrusive/set.hpp>
#include <boost/intrusive/list.hpp>
#include "wallet_request_bbs_msg.h"
#include "wallet.h"

namespace hds::wallet
{
    namespace bi = boost::intrusive;

    class BaseMessageEndpoint
        : public IWalletMessageEndpoint
    {
        struct Addr
        {
            struct Wid :public boost::intrusive::set_base_hook<> {
                uint64_t m_OwnID;
                bool operator < (const Wid& x) const { return m_OwnID < x.m_OwnID; }
                IMPLEMENT_GET_PARENT_OBJ(Addr, m_Wid)
            } m_Wid;

            struct Channel :public boost::intrusive::set_base_hook<> {
                BbsChannel m_Value;
                bool operator < (const Channel& x) const { return m_Value < x.m_Value; }
                IMPLEMENT_GET_PARENT_OBJ(Addr, m_Channel)
            } m_Channel;

            bool IsExpired() const
            {
                return getTimestamp() > m_ExpirationTime;
            }

            ECC::Scalar::Native m_sk; // private addr
            PeerID m_Pk; // self public addr
            Timestamp m_ExpirationTime;
        };
    public:
        BaseMessageEndpoint(IWalletMessageConsumer&, const IWalletDB::Ptr&);
        virtual ~BaseMessageEndpoint();
        void AddOwnAddress(const WalletAddress& address);
        void DeleteOwnAddress(uint64_t ownID);
    protected:
        void ProcessMessage(BbsChannel channel, const ByteBuffer& msg);
        void Subscribe();
        void Unsubscribe();
        virtual void OnChannelAdded(BbsChannel channel) {};
        virtual void OnChannelDeleted(BbsChannel channel) {};
        virtual void OnIncomingMessage() {};
    private:
        void DeleteAddr(const Addr&);
        bool IsSingleChannelUser(const Addr::Channel&);

        // IWalletMessageEndpoint
        void Send(const WalletID& peerID, const SetTxParameter& msg) override;
        void OnAddressTimer();
        
    private:
        typedef bi::multiset<Addr::Wid> WidSet;
        WidSet m_Addresses;

        typedef  bi::multiset<Addr::Channel> ChannelSet;
        ChannelSet m_Channels;

        IWalletMessageConsumer& m_Wallet;
        IWalletDB::Ptr m_WalletDB;
        Key::IKdf::Ptr m_pKdfSbbs;
        io::Timer::Ptr m_AddressExpirationTimer;
    };

    class BbsSender
    {
    public:
        BbsSender(proto::FlyClient::INetwork::Ptr nodeEndpoint);
        bool m_MineOutgoing = true; // can be turned-off for testing
        virtual ~BbsSender();
        void Send(const WalletID& peerID, const ByteBuffer& msg, uint64_t messageID);
        proto::FlyClient::IBbsReceiver* get_BbsReceiver();

        virtual void OnMessageSent(uint64_t messageID) {}
        virtual void OnMsg(const proto::BbsMsg&) {};
    private:
        void DeleteReq(WalletRequestBbsMsg& r);
        void OnMined();
        void OnMined(BbsMiner::Task::Ptr);
    private:
        proto::FlyClient::INetwork::Ptr m_NodeEndpoint;
        BbsMsgList m_PendingBbsMsgs;

        struct BbsSentEvt
            :public proto::FlyClient::Request::IHandler
            , public proto::FlyClient::IBbsReceiver
        {
            virtual void OnComplete(proto::FlyClient::Request&) override;
            virtual void OnMsg(proto::BbsMsg&&) override;

            IMPLEMENT_GET_PARENT_OBJ(BbsSender, m_BbsSentEvt)
        } m_BbsSentEvt;

        BbsMiner m_Miner;
    };

    class WalletNetworkViaBbs
        : public BaseMessageEndpoint
        , private IWalletDbObserver
        , public BbsSender
    {
        std::shared_ptr<proto::FlyClient::INetwork> m_NodeEndpoint;
        IWalletDB::Ptr m_WalletDB;

        void OnMsg(const proto::BbsMsg&) override;

        std::unordered_map<BbsChannel, Timestamp> m_BbsTimestamps;
        io::Timer::Ptr m_pTimerBbsTmSave;
        void OnTimerBbsTmSave();
        void SaveBbsTimestamps();
    public:
        WalletNetworkViaBbs(IWalletMessageConsumer&, proto::FlyClient::INetwork::Ptr, const IWalletDB::Ptr&);
        virtual ~WalletNetworkViaBbs();
    private:
        void OnChannelAdded(BbsChannel channel) override;
        void OnChannelDeleted(BbsChannel channel) override;
        void OnMessageSent(uint64_t messageID) override;
        // IWalletMessageEndpoint
        void SendRawMessage(const WalletID& peerID, const ByteBuffer& msg) override;
        void onAddressChanged(ChangeAction action, const std::vector<WalletAddress>& items) override;
    };
}
