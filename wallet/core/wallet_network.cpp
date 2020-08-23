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

#include "wallet_network.h"

using namespace std;

namespace
{
    const char* BBS_TIMESTAMPS = "BbsTimestamps";
    const unsigned AddressUpdateInterval_ms = 60 * 1000; // check addresses every minute

    hds::BbsChannel channel_from_wallet_id(const hds::wallet::WalletID& walletID)
    {
        hds::BbsChannel ret;
        walletID.m_Channel.Export(ret);
        return ret;
    }
}


namespace hds::wallet {

    ///////////////////////////

    BaseMessageEndpoint::BaseMessageEndpoint(IWalletMessageConsumer& w, const IWalletDB::Ptr& pWalletDB)
        : m_Wallet(w)
        , m_WalletDB(pWalletDB)
        , m_AddressExpirationTimer(io::Timer::create(io::Reactor::get_Current()))
    {
        m_pKdfSbbs = pWalletDB->get_SbbsKdf();

    }

    BaseMessageEndpoint::~BaseMessageEndpoint()
    {
        
    }

    void BaseMessageEndpoint::Subscribe()
    {
        auto myAddresses = m_WalletDB->getAddresses(true);
        for (const auto& address : myAddresses)
            if (!address.isExpired())
                AddOwnAddress(address);

        m_AddressExpirationTimer->start(AddressUpdateInterval_ms, false, [this] { OnAddressTimer(); });
    }

    void BaseMessageEndpoint::Unsubscribe()
    {
        while (!m_Addresses.empty())
            DeleteAddr(m_Addresses.begin()->get_ParentObj());
    }

    void BaseMessageEndpoint::ProcessMessage(BbsChannel channel, const ByteBuffer& msg)
    {
        Addr::Channel key;
        key.m_Value = channel;

        for (ChannelSet::iterator it = m_Channels.lower_bound(key); ; ++it)
        {
            if (m_Channels.end() == it)
                break;
            if (it->m_Value != channel)
                break; // as well


            if (!m_pKdfSbbs)
            {
                // read-only wallet
                m_WalletDB->saveIncomingWalletMessage(channel, msg);
                OnIncomingMessage();
                return;
            }

            ByteBuffer buf = msg; // duplicate
            uint8_t* pMsg = &buf.front();
            uint32_t nSize = static_cast<uint32_t>(buf.size());

            if (!proto::Bbs::Decrypt(pMsg, nSize, it->get_ParentObj().m_sk))
                continue;

            SetTxParameter msgWallet;
            bool bValid = false;

            try {
                Deserializer der;
                der.reset(pMsg, nSize);
                der& msgWallet;
                bValid = true;
            }
            catch (const std::exception&) {
                LOG_WARNING() << "BBS deserialization failed";
            }

            if (bValid)
            {
                WalletID wid;
                wid.m_Pk = it->get_ParentObj().m_Pk;
                wid.m_Channel = it->m_Value;
                m_Wallet.OnWalletMessage(wid, msgWallet);
                break;
            }
        }
    }

    void BaseMessageEndpoint::AddOwnAddress(const WalletAddress& address)
    {
        if (!m_pKdfSbbs)
            return;

        Addr::Wid key;
        key.m_OwnID = address.m_OwnID;

        Addr* pAddr = nullptr;
        auto itW = m_Addresses.find(key);

        if (m_Addresses.end() == itW)
        {
            pAddr = new Addr;
            pAddr->m_ExpirationTime = address.getExpirationTime();
            pAddr->m_Wid.m_OwnID = address.m_OwnID;

            m_WalletDB->get_SbbsPeerID(pAddr->m_sk, pAddr->m_Pk, address.m_OwnID);

            pAddr->m_Channel.m_Value = channel_from_wallet_id(address.m_walletID);

            m_Addresses.insert(pAddr->m_Wid);
            m_Channels.insert(pAddr->m_Channel);
        }
        else
        {
            pAddr = &(itW->get_ParentObj());
            pAddr->m_ExpirationTime = address.getExpirationTime();
        }

        if (pAddr && IsSingleChannelUser(pAddr->m_Channel))
        {
            OnChannelAdded(pAddr->m_Channel.m_Value);
        }

        LOG_INFO() << "WalletID " << to_string(address.m_walletID) << " subscribes to BBS channel " << pAddr->m_Channel.m_Value;
    }

    void BaseMessageEndpoint::DeleteOwnAddress(uint64_t ownID)
    {
        Addr::Wid key;
        key.m_OwnID = ownID;

        auto it = m_Addresses.find(key);
        if (m_Addresses.end() != it)
            DeleteAddr(it->get_ParentObj());
    }

    void BaseMessageEndpoint::DeleteAddr(const Addr& v)
    {
        if (IsSingleChannelUser(v.m_Channel))
        {
            OnChannelDeleted(v.m_Channel.m_Value);
        }

        m_Addresses.erase(WidSet::s_iterator_to(v.m_Wid));
        m_Channels.erase(ChannelSet::s_iterator_to(v.m_Channel));
        delete& v;
    }

    bool BaseMessageEndpoint::IsSingleChannelUser(const Addr::Channel& c)
    {
        ChannelSet::const_iterator it = ChannelSet::s_iterator_to(c);
        ChannelSet::const_iterator it2 = it;
        if (((++it2) != m_Channels.end()) && (it2->m_Value == c.m_Value))
            return false;

        if (it != m_Channels.begin())
        {
            it2 = it;
            if ((--it2)->m_Value == it->m_Value)
                return false;
        }

        return true;
    }

    void BaseMessageEndpoint::Send(const WalletID& peerID, const SetTxParameter& msg)
    {
        if (!m_pKdfSbbs)
            return;

        Serializer ser;
        ser& msg;
        SerializeBuffer sb = ser.buffer();

        ECC::NoLeak<ECC::Hash::Value> hvRandom;
        ECC::GenRandom(hvRandom.V);

        ECC::Scalar::Native nonce;
        m_pKdfSbbs->DeriveKey(nonce, hvRandom.V);

        ByteBuffer encryptedMessage;
        if (proto::Bbs::Encrypt(encryptedMessage, peerID.m_Pk, nonce, sb.first, static_cast<uint32_t>(sb.second)))
        {
            SendRawMessage(peerID, encryptedMessage);
        }
        else
        {
            LOG_WARNING() << "BBS serialization failed (bad peerID?)";
        }
    }

    void BaseMessageEndpoint::OnAddressTimer()
    {
        vector<Addr*> addressesToDelete;
        for (const auto& address : m_Addresses)
        {
            if (address.get_ParentObj().IsExpired())
            {
                addressesToDelete.push_back(&address.get_ParentObj());
            }
        }
        for (const auto& address : addressesToDelete)
        {
            DeleteAddr(*address);
        }
        m_AddressExpirationTimer->start(AddressUpdateInterval_ms, false, [this] { OnAddressTimer(); });
    }

    ///////////////////////////

    BbsSender::BbsSender(proto::FlyClient::INetwork::Ptr nodeEndpoint)
        : m_NodeEndpoint(nodeEndpoint)
    {

    }

    BbsSender::~BbsSender()
    {
        try
        {
            m_Miner.Stop();
            while (!m_PendingBbsMsgs.empty())
                DeleteReq(m_PendingBbsMsgs.front());
        }
        catch (const std::exception & e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...)
        {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void BbsSender::Send(const WalletID& peerID, const ByteBuffer& msg, uint64_t messageID)
    {
        BbsMiner::Task::Ptr pTask = std::make_shared<BbsMiner::Task>();
        pTask->m_Msg.m_Message = msg;

        pTask->m_Done = false;
        pTask->m_Msg.m_Channel = channel_from_wallet_id(peerID);

        pTask->m_StoredMessageID = messageID; // store id to be able to remove if send succeeded

        if (m_MineOutgoing)
        {
            proto::Bbs::get_HashPartial(pTask->m_hpPartial, pTask->m_Msg);

            if (!m_Miner.m_pEvt)
            {
                m_Miner.m_pEvt = io::AsyncEvent::create(io::Reactor::get_Current(), [this]() { OnMined(); });
                m_Miner.m_Shutdown = false;

                uint32_t nThreads = std::thread::hardware_concurrency();
                nThreads = (nThreads > 1) ? (nThreads - 1) : 1; // leave at least 1 vacant core for other things
                m_Miner.m_vThreads.resize(nThreads);

                for (uint32_t i = 0; i < nThreads; i++)
                    m_Miner.m_vThreads[i] = std::thread(&BbsMiner::Thread, &m_Miner, i);
            }

            std::unique_lock<std::mutex> scope(m_Miner.m_Mutex);

            m_Miner.m_Pending.push_back(std::move(pTask));
            m_Miner.m_NewTask.notify_all();
        }
        else
        {
            pTask->m_Msg.m_TimePosted = getTimestamp();
            OnMined(pTask);
        }
    }

    proto::FlyClient::IBbsReceiver* BbsSender::get_BbsReceiver()
    {
        return &m_BbsSentEvt;
    }

    ///////////////////////////

    WalletNetworkViaBbs::WalletNetworkViaBbs(IWalletMessageConsumer& w, proto::FlyClient::INetwork::Ptr net, const IWalletDB::Ptr& pWalletDB)
        : BaseMessageEndpoint(w, pWalletDB)
        , BbsSender(net)
        , m_NodeEndpoint(net)
        , m_WalletDB(pWalletDB)
    {
		ByteBuffer buffer;
		m_WalletDB->getBlob(BBS_TIMESTAMPS, buffer);
		if (!buffer.empty())
		{
			Deserializer d;
			d.reset(buffer.data(), buffer.size());

			d & m_BbsTimestamps;
		}

        Subscribe();
        m_WalletDB->Subscribe(this);
	}

	WalletNetworkViaBbs::~WalletNetworkViaBbs()
	{
        try 
        {
            m_WalletDB->Unsubscribe(this);

            Unsubscribe();
		
			SaveBbsTimestamps();
		} 
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...)
        {
            LOG_UNHANDLED_EXCEPTION();
		}
	}

	void WalletNetworkViaBbs::SaveBbsTimestamps()
	{
		Timestamp tsThreshold = getTimestamp() - 3600 * 24 * 3;

		for (auto it = m_BbsTimestamps.begin(); m_BbsTimestamps.end() != it; )
		{
			auto it2 = it++;
			if (it2->second < tsThreshold)
				m_BbsTimestamps.erase(it2);
		}

		Serializer s;
		s & m_BbsTimestamps;

		ByteBuffer buffer;
		s.swap_buf(buffer);

		m_WalletDB->setVarRaw(BBS_TIMESTAMPS, buffer.data(), buffer.size());
	}

	void BbsSender::DeleteReq(WalletRequestBbsMsg& r)
	{
		m_PendingBbsMsgs.erase(BbsMsgList::s_iterator_to(r));
		r.m_pTrg = NULL;
        OnMessageSent(r.m_MessageID);
		r.Release();
	}

	void WalletNetworkViaBbs::OnTimerBbsTmSave()
	{
		m_pTimerBbsTmSave.reset();
		SaveBbsTimestamps();
	}

	void BbsSender::BbsSentEvt::OnComplete(proto::FlyClient::Request& r)
	{
		assert(r.get_Type() == proto::FlyClient::Request::Type::BbsMsg);
		get_ParentObj().DeleteReq(static_cast<WalletRequestBbsMsg&>(r));
	}

	void BbsSender::BbsSentEvt::OnMsg(proto::BbsMsg&& msg)
	{
		get_ParentObj().OnMsg(msg);
	}

	void WalletNetworkViaBbs::OnMsg(const proto::BbsMsg& msg)
	{
		if (msg.m_Message.empty())
			return;

		auto itBbs = m_BbsTimestamps.find(msg.m_Channel);
		if (m_BbsTimestamps.end() != itBbs)
        {
			std::setmax(itBbs->second, msg.m_TimePosted);
        }
		else
        {
			m_BbsTimestamps[msg.m_Channel] = msg.m_TimePosted;
        }

		if (!m_pTimerBbsTmSave)
		{
			m_pTimerBbsTmSave = io::Timer::create(io::Reactor::get_Current());
			m_pTimerBbsTmSave->start(60*1000, false, [this]() { OnTimerBbsTmSave(); });
		}

        ProcessMessage(msg.m_Channel, msg.m_Message);
	}

    void WalletNetworkViaBbs::SendRawMessage(const WalletID& peerID, const ByteBuffer& msg)
    {
        // first store message for accidental app close
        auto messageID = m_WalletDB->saveWalletMessage(OutgoingWalletMessage{ 0, peerID, msg });
        BbsSender::Send(peerID, msg, messageID);
    }

    void WalletNetworkViaBbs::OnChannelAdded(BbsChannel channel)
	{
        Timestamp ts = 0;
        auto it = m_BbsTimestamps.find(channel);
        if (m_BbsTimestamps.end() != it)
            ts = it->second;

        m_NodeEndpoint->BbsSubscribe(channel, ts, get_BbsReceiver());
	}

    void WalletNetworkViaBbs::OnChannelDeleted(BbsChannel channel)
    {
        m_NodeEndpoint->BbsSubscribe(channel, 0, nullptr);
	}

    void WalletNetworkViaBbs::OnMessageSent(uint64_t messageID)
    {
        m_WalletDB->deleteWalletMessage(messageID);
    }

	void BbsSender::OnMined()
	{
		while (true)
		{
			BbsMiner::Task::Ptr pTask;
			{
				std::unique_lock<std::mutex> scope(m_Miner.m_Mutex);

				if (!m_Miner.m_Done.empty())
				{
					pTask = std::move(m_Miner.m_Done.front());
					m_Miner.m_Done.pop_front();
				}
			}

			if (!pTask)
				break;

			OnMined(pTask);
		}
	}

	void BbsSender::OnMined(BbsMiner::Task::Ptr task)
	{
		WalletRequestBbsMsg::Ptr pReq(new WalletRequestBbsMsg);

		pReq->m_Msg = std::move(task->m_Msg);
                pReq->m_MessageID = task->m_StoredMessageID;

		m_PendingBbsMsgs.push_back(*pReq);
		pReq->AddRef();

        m_NodeEndpoint->PostRequest(*pReq, m_BbsSentEvt);
	}

    void WalletNetworkViaBbs::onAddressChanged(ChangeAction action, const vector<WalletAddress>& items)
    {
        switch (action)
        {
        case ChangeAction::Added:
        case ChangeAction::Updated:
            for (const auto& address : items)
            {
                if (!address.isOwn())
                {
                    continue;
                }
                else if (!address.isExpired())
                {
                    AddOwnAddress(address);
                }
                else
                {
                    DeleteOwnAddress(address.m_OwnID);
                }
            }
            break;
        case ChangeAction::Removed:
            for (const auto& address : items)
            {
                DeleteOwnAddress(address.m_OwnID);
            }
            break;
        case ChangeAction::Reset:
            assert(false && "invalid address change action");
            break;
        }
    }
}
