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

#include "default_peers.h"

namespace hds
{
    std::vector<std::string> getDefaultPeers()
    {
        std::vector<std::string> result
        {
#ifdef HDS_TESTNET
            "tokyo-nodes.testnet.hadescoin.com:16668"
#elif defined(HDS_MAINNET)
            "tokyo-nodes.mainnet.hadescoin.com:16668"
#else
            "tokyo-nodes.masternet.hadescoin.com:16668"
#endif
        };

        return result;
    }

    std::vector<std::string> getOutdatedDefaultPeers()
    {
        std::vector<std::string> result
        {
#if defined(HDS_TESTNET)
            "tokyo-nodes.testnet.hadescoin.com:16668"
#elif defined(HDS_MAINNET)
            "tokyo-nodes.mainnet.hadescoin.com:16668"
#else
            // "tokyo-nodes.masternet.hadescoin.com:16668"
#endif
        };

        return result;
    }
}
