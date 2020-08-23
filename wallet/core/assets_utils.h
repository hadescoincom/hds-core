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

#include <core/block_crypt.h>
#include "common.h"

namespace hds::wallet {
    class WalletAssetMeta
    {
    public:
        explicit WalletAssetMeta(std::string meta);
        explicit WalletAssetMeta(const Asset::Full& info);

        bool isStd() const;
        void LogInfo(const std::string& prefix = "\t") const;

        std::string GetUnitName() const;
        std::string GetNthUnitName() const;
        std::string GetName() const;
        std::string GetShortName() const;

    private:
        void Parse();

        typedef std::map<std::string, std::string> SMap;
        SMap _values;
        bool _std;
        std::string _meta;
    };

    class WalletAsset: public Asset::Full
    {
    public:
        WalletAsset() = default;
        WalletAsset(const Asset::Full& full, Height refreshHeight);
        bool CanRollback(Height from) const;
        void LogInfo(const std::string& prefix = std::string()) const;
        void LogInfo(const TxID& txId, const SubTxID& subTxId) const;

        Height  m_RefreshHeight = 0;
        int32_t m_IsOwned = 0;
    };
}
