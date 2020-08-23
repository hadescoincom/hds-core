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

#include "core/fly_client.h"
#include "wallet/core/node_connection_observer.h"

namespace hds::wallet
{

    class NodeNetwork final: public proto::FlyClient::NetworkStd
    {
    public:
        using Ptr = std::shared_ptr<NodeNetwork>;

        NodeNetwork(proto::FlyClient& fc, const std::string& nodeAddress)
            : proto::FlyClient::NetworkStd(fc)
            , m_nodeAddress(nodeAddress)
        {
        }

        void tryToConnect();

        void Subscribe(INodeConnectionObserver* observer);
        void Unsubscribe(INodeConnectionObserver* observer);

        std::string getNodeAddress() const;
        bool setNodeAddress(const std::string&);

    private:
        void OnNodeConnected(bool bConnected) override;
        void OnConnectionFailed(const proto::NodeConnection::DisconnectReason& reason) override;
        
        const uint8_t MAX_ATTEMPT_TO_CONNECT = 5;
        const uint16_t RECONNECTION_TIMEOUT = 1000;
        io::Timer::Ptr m_timer;
        uint8_t m_attemptToConnect = 0;
        std::vector<INodeConnectionObserver*> m_observers;
        std::string m_nodeAddress;

    };

} // namespace hds::wallet
