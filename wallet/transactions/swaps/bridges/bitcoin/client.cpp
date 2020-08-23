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

#include "wallet/transactions/swaps/bridges/bitcoin/client.h"
#include "client.h"

#include "bitcoin_core_017.h"
#include "utility/logger.h"
#include "utility/bridge.h"

namespace hds::bitcoin
{
    namespace
    {
        bool IsChangedConnectionSettings(const Settings& currentSettings, const Settings& newSettings)
        {
            bool isConnectionTypeChanged = currentSettings.GetCurrentConnectionType() != newSettings.GetCurrentConnectionType();

            if (isConnectionTypeChanged)
            {
                return true;
            }

            switch (currentSettings.GetCurrentConnectionType())
            {
            case Settings::ConnectionType::Electrum:
                return currentSettings.GetElectrumConnectionOptions() != newSettings.GetElectrumConnectionOptions();
            case Settings::ConnectionType::Core:
                return currentSettings.GetConnectionOptions() != newSettings.GetConnectionOptions();
            default:
                return false;
            }
        }
    }

    struct BitcoinClientBridge : public Bridge<IClientAsync>
    {
        BRIDGE_INIT(BitcoinClientBridge);

        void GetStatus()
        {
            call_async(&IClientAsync::GetStatus);
        }

        void GetBalance()
        {
            call_async(&IClientAsync::GetBalance);
        }

        void ChangeSettings(const Settings& settings)
        {
            call_async(&IClientAsync::ChangeSettings, settings);
        }
    };
    
    Client::Client(IBridgeHolder::Ptr bridgeHolder, std::unique_ptr<SettingsProvider> settingsProvider, io::Reactor& reactor)
        : m_status(settingsProvider->GetSettings().IsActivated() ? Status::Connecting : Status::Uninitialized)
        , m_reactor(reactor)
        , m_async{ std::make_shared<BitcoinClientBridge>(*(static_cast<IClientAsync*>(this)), reactor) }
        , m_settingsProvider{ std::move(settingsProvider) }
        , m_bridgeHolder(bridgeHolder)
    {
    }

    IClientAsync::Ptr Client::GetAsync()
    {
        return m_async;
    }

    Settings Client::GetSettings() const
    {
        Lock lock(m_mutex);
        return m_settingsProvider->GetSettings();
    }

    void Client::SetSettings(const Settings& settings)
    {
        GetAsync()->ChangeSettings(settings);
    }

    void Client::GetStatus()
    {
        Status status = Status::Unknown;
        {
            Lock lock(m_mutex);
            status = m_status;
        }
        OnStatus(status);
    }

    void Client::GetBalance()
    {
        auto bridge = GetBridge();

        if (!bridge)
        {
            return;
        }

        bridge->getDetailedBalance([this, weak = this->weak_from_this()] (const IBridge::Error& error, Amount confirmed, Amount unconfirmed, Amount immature)
        {
            if (weak.expired())
            {
                return;
            }

            // TODO: check error and update status
            SetConnectionError(error.m_type);
            SetStatus((error.m_type != IBridge::None) ? Status::Failed : Status::Connected);

            Balance balance;
            balance.m_available = confirmed;
            balance.m_unconfirmed = unconfirmed;
            balance.m_immature = immature;

            OnBalance(balance);
        });
    }

    void Client::ChangeSettings(const Settings& settings)
    {
        {
            Lock lock(m_mutex);
            auto currentSettings = m_settingsProvider->GetSettings();
            bool shouldReconnect = IsChangedConnectionSettings(currentSettings, settings);

            m_settingsProvider->SetSettings(settings);

            if (shouldReconnect)
            {
                m_bridgeHolder->Reset();

                if (m_settingsProvider->GetSettings().IsActivated())
                {
                    SetStatus(Status::Connecting);
                }
                else
                {
                    SetStatus(Status::Uninitialized);
                }
            }
        }

        OnChangedSettings();
    }

    void Client::SetStatus(const Status& status)
    {
        if (m_status != status)
        {
            m_status = status;
            OnStatus(m_status);
        }
    }

    hds::bitcoin::IBridge::Ptr Client::GetBridge()
    {
        return m_bridgeHolder->Get(m_reactor, *this);
    }

    bool Client::CanModify() const
    {
        return m_refCount == 0;
    }

    void Client::AddRef()
    {
        ++m_refCount;
        OnCanModifySettingsChanged(CanModify());
    }

    void Client::ReleaseRef()
    {
        if (m_refCount)
        {
            --m_refCount;
            OnCanModifySettingsChanged(CanModify());
        }
    }

    void Client::SetConnectionError(const IBridge::ErrorType& error)
    {
        if (m_connectionError != error)
        {
            m_connectionError = error;
            OnConnectionError(m_connectionError);
        }
    }

} // namespace hds::bitcoin