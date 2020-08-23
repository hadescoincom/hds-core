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

#include "wallet/core/private_key_keeper.h"

class Client;
class DeviceManager;

namespace hds::wallet
{
    class HWWallet
    {
    public:
        HWWallet();

        using Ptr = std::shared_ptr<HWWallet>;

        std::vector<std::string> getDevices() const;
        bool isConnected() const;
        IPrivateKeyKeeper2::Ptr getKeyKeeper(const std::string& device);

        template<typename T> using Result = std::function<void(const T& key)>;

    private:
        std::shared_ptr<Client> m_client;
    };
}