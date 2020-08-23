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

#include "node_network.h"

namespace hds::wallet
{
    void NodeNetwork::tryToConnect()
    {
        // if user changed address to correct (using of setNodeAddress)
        if (m_Cfg.m_vNodes.size() > 0)
            return;

        if (!m_timer)
        {
            m_timer = io::Timer::create(io::Reactor::get_Current());
        }

        if (m_attemptToConnect < MAX_ATTEMPT_TO_CONNECT)
        {
            ++m_attemptToConnect;
        }
        else if (m_attemptToConnect == MAX_ATTEMPT_TO_CONNECT)
        {
            proto::NodeConnection::DisconnectReason reason;
            reason.m_Type = proto::NodeConnection::DisconnectReason::Io;
            reason.m_IoError = io::EC_HOST_RESOLVED_ERROR;
            for (const auto observer : m_observers)
            {
                    observer->onNodeConnectionFailed(reason);
            }
        }

        m_timer->start(RECONNECTION_TIMEOUT, false, [this]() {
            io::Address nodeAddr;
            if (nodeAddr.resolve(m_nodeAddress.c_str()))
            {
                m_Cfg.m_vNodes.push_back(nodeAddr);
                Connect();
            }
            else
            {
                tryToConnect();
            }
        });
    }

    void NodeNetwork::OnNodeConnected(bool bConnected)
    {
        for (const auto observer : m_observers)
        {
            observer->onNodeConnectedStatusChanged(bConnected);
        }
    }

    void NodeNetwork::OnConnectionFailed(const proto::NodeConnection::DisconnectReason& reason)
    {
        for (const auto observer : m_observers)
        {
            observer->onNodeConnectionFailed(reason);
        }
    }

    std::string NodeNetwork::getNodeAddress() const
    {
        return m_nodeAddress;
    }

    bool NodeNetwork::setNodeAddress(const std::string& nodeAddr)
    {
        io::Address address;

        if (address.resolve(nodeAddr.c_str()))
        {
            Disconnect();

            m_Cfg.m_vNodes.clear();
            m_Cfg.m_vNodes.push_back(address);

            Connect();

            m_nodeAddress = nodeAddr;
            return true;
        }
        return false;
    }

    void NodeNetwork::Subscribe(INodeConnectionObserver* observer)
    {
        auto it = std::find(std::cbegin(m_observers),
                            std::cend(m_observers),
                            observer);
        assert(it == m_observers.end());
        if (it == m_observers.end()) m_observers.push_back(observer);
    }

    void NodeNetwork::Unsubscribe(INodeConnectionObserver* observer)
    {
        auto it = std::find(std::cbegin(m_observers),
                            std::cend(m_observers),
                            observer);
        assert(it != m_observers.end());
        m_observers.erase(it);
    }
    
} // namespace hds::wallet
