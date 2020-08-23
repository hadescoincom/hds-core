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

#include "wallet_client.h"
#include "wallet/core/simple_transaction.h"
#include "utility/log_rotation.h"
#include "core/block_rw.h"
//#include "keykeeper/trezor_key_keeper.h"
#include "extensions/broadcast_gateway/broadcast_router.h"
#include "extensions/news_channels/wallet_updates_provider.h"
#include "extensions/news_channels/exchange_rate_provider.h"

using namespace std;

namespace
{
using namespace hds;
using namespace hds::wallet;

const size_t kCollectorBufferSize = 50;

#if defined(HDS_TESTNET)
const char kBroadcastValidatorPublicKey[] = "dc3df1d8cd489c3fe990eb8b4b8a58089a7706a5fc3b61b9c098047aac2c2812";
#elif defined(HDS_MAINNET)
const char kBroadcastValidatorPublicKey[] = "8ea783eced5d65139bbdf432814a6ed91ebefe8079395f63a13beed1dfce39da";
#else
const char kBroadcastValidatorPublicKey[] = "db617cedb17543375b602036ab223b67b06f8648de2bb04de047f485e7a9daec";
#endif

using WalletSubscriber = ScopedSubscriber<wallet::IWalletObserver, wallet::Wallet>;

struct WalletModelBridge : public Bridge<IWalletModelAsync>
{
    BRIDGE_INIT(WalletModelBridge);

    void sendMoney(const wallet::WalletID& receiverID, const std::string& comment, Amount amount, Amount fee) override
    {
        typedef void(IWalletModelAsync::*SendMoneyType)(const wallet::WalletID&, const std::string&, Amount, Amount);
        call_async((SendMoneyType)&IWalletModelAsync::sendMoney, receiverID, comment, amount, fee);
    }

    void sendMoney(const wallet::WalletID& senderID, const wallet::WalletID& receiverID, const std::string& comment, Amount amount, Amount fee) override
    {
        typedef void(IWalletModelAsync::*SendMoneyType)(const wallet::WalletID &, const wallet::WalletID &, const std::string &, Amount, Amount);
        call_async((SendMoneyType)&IWalletModelAsync::sendMoney, senderID, receiverID, comment, amount, fee);
    }

    void startTransaction(TxParameters&& parameters) override
    {
        call_async(&IWalletModelAsync::startTransaction, move(parameters));
    }

    void syncWithNode() override
    {
        call_async(&IWalletModelAsync::syncWithNode);
    }

    void calcChange(Amount amount) override
    {
        call_async(&IWalletModelAsync::calcChange, amount);
    }

    void getWalletStatus() override
    {
        call_async(&IWalletModelAsync::getWalletStatus);
    }

    void getTransactions() override
    {
        call_async(&IWalletModelAsync::getTransactions);
    }

    void getUtxosStatus() override
    {
        call_async(&IWalletModelAsync::getUtxosStatus);
    }

    void getAddresses(bool own) override
    {
        call_async(&IWalletModelAsync::getAddresses, own);
    }
    
#ifdef HDS_ATOMIC_SWAP_SUPPORT
    void getSwapOffers() override
    {
		call_async(&IWalletModelAsync::getSwapOffers);
    }

    void publishSwapOffer(const wallet::SwapOffer& offer) override
    {
		call_async(&IWalletModelAsync::publishSwapOffer, offer);
    }

    void loadSwapParams() override
    {
        call_async(&IWalletModelAsync::loadSwapParams);
    }

    void storeSwapParams(const hds::ByteBuffer& params) override
    {
        call_async(&IWalletModelAsync::storeSwapParams, params);
    }
#endif
    void cancelTx(const wallet::TxID& id) override
    {
        call_async(&IWalletModelAsync::cancelTx, id);
    }

    void deleteTx(const wallet::TxID& id) override
    {
        call_async(&IWalletModelAsync::deleteTx, id);
    }

    void getCoinsByTx(const wallet::TxID& id) override
    {
        call_async(&IWalletModelAsync::getCoinsByTx, id);
    }

    void saveAddress(const wallet::WalletAddress& address, bool bOwn) override
    {
        call_async(&IWalletModelAsync::saveAddress, address, bOwn);
    }

    void generateNewAddress() override
    {
        call_async(&IWalletModelAsync::generateNewAddress);
    }

    void deleteAddress(const wallet::WalletID& id) override
    {
        call_async(&IWalletModelAsync::deleteAddress, id);
    }

    void updateAddress(const wallet::WalletID& id, const std::string& name, WalletAddress::ExpirationStatus status) override
    {
        call_async(&IWalletModelAsync::updateAddress, id, name, status);
    }

    void activateAddress(const wallet::WalletID& id) override
    {
        call_async(&IWalletModelAsync::activateAddress, id);
    }

    void setNodeAddress(const std::string& addr) override
    {
        call_async(&IWalletModelAsync::setNodeAddress, addr);
    }

    void changeWalletPassword(const SecString& pass) override
    {
        // TODO: should be investigated, don't know how to "move" SecString into lambda
        std::string passStr(pass.data(), pass.size());

        call_async(&IWalletModelAsync::changeWalletPassword, passStr);
    }

    void getNetworkStatus() override
    {
        call_async(&IWalletModelAsync::getNetworkStatus);
    }

    void rescan() override
    {
        call_async(&IWalletModelAsync::rescan);
    }

    void exportPaymentProof(const wallet::TxID& id) override
    {
        call_async(&IWalletModelAsync::exportPaymentProof, id);
    }

    void checkAddress(const std::string& addr) override
    {
        call_async(&IWalletModelAsync::checkAddress, addr);
    }

    void importRecovery(const std::string& path) override
    {
        call_async(&IWalletModelAsync::importRecovery, path);
    }

    void importDataFromJson(const std::string& data) override
    {
        call_async(&IWalletModelAsync::importDataFromJson, data);
    }

    void exportDataToJson() override
    {
        call_async(&IWalletModelAsync::exportDataToJson);
    }

    void exportTxHistoryToCsv() override
    {
        call_async(&IWalletModelAsync::exportTxHistoryToCsv);
    }

    void switchOnOffExchangeRates(bool isActive) override
    {
        call_async(&IWalletModelAsync::switchOnOffExchangeRates, isActive);
    }

    void switchOnOffNotifications(Notification::Type type, bool isActive) override
    {
        call_async(&IWalletModelAsync::switchOnOffNotifications, type, isActive);
    }
        
    void getNotifications() override
    {
        call_async(&IWalletModelAsync::getNotifications);
    }

    void markNotificationAsRead(const ECC::uintBig& id) override
    {
        call_async(&IWalletModelAsync::markNotificationAsRead, id);
    }

    void deleteNotification(const ECC::uintBig& id) override
    {
        call_async(&IWalletModelAsync::deleteNotification, id);
    }

    void getExchangeRates() override
    {
        call_async(&IWalletModelAsync::getExchangeRates);
    }
};
}

namespace hds::wallet
{
    WalletClient::WalletClient(IWalletDB::Ptr walletDB, const std::string& nodeAddr, io::Reactor::Ptr reactor)
        : m_walletDB(walletDB)
        , m_reactor{ reactor ? reactor : io::Reactor::create() }
        , m_async{ make_shared<WalletModelBridge>(*(static_cast<IWalletModelAsync*>(this)), *m_reactor) }
        , m_connectedNodesCount(0)
        , m_trustedConnectionCount(0)
        , m_initialNodeAddrStr(nodeAddr)
        , m_CoinChangesCollector(kCollectorBufferSize, m_reactor, [this](auto action, const auto& items) { onAllUtxoChanged(action, items); })
        , m_AddressChangesCollector(kCollectorBufferSize, m_reactor, [this](auto action, const auto& items) { onAddressesChanged(action, items); })
        , m_TransactionChangesCollector(kCollectorBufferSize, m_reactor, [this](auto action, const auto& items) { onTxStatus(action, items); })
    {
        //m_keyKeeper->subscribe(this);
    }

    WalletClient::~WalletClient()
    {
        // reactor should be already stopped here, but just in case
        // this call is unsafe and may result in crash if reactor is not stopped
        assert(!m_thread && !m_reactor);
        stopReactor();
    }

    void WalletClient::stopReactor()
    {
        try
        {
            if (m_reactor)
            {
                if (m_thread)
                {
                    m_reactor->stop();
                    m_thread->join();
                    m_thread.reset();
                }
                m_reactor.reset();
            }
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::postFunctionToClientContext(MessageFunction&& func)
    {
        onPostFunctionToClientContext(move(func));
    }

    Version WalletClient::getLibVersion() const
    {
        // TODO: replace with current wallet library version
        return hds::Version
        {
            0,
            0,
            0
        };
    }

    uint32_t WalletClient::getClientRevision() const
    {
        return 0;
    }

    void WalletClient::start( std::map<Notification::Type,bool> activeNotifications,
                              bool withAssets,
                              bool isSecondCurrencyEnabled,
                              std::shared_ptr<std::unordered_map<TxType, BaseTransaction::Creator::Ptr>> txCreators)
    {
        m_thread = std::make_shared<std::thread>([this, isSecondCurrencyEnabled, withAssets, txCreators, activeNotifications]()
        {
            try
            {
                io::Reactor::Scope scope(*m_reactor);
                io::Reactor::GracefulIntHandler gih(*m_reactor);

                static const unsigned LOG_ROTATION_PERIOD_SEC = 3 * 3600; // 3 hours
                static const unsigned LOG_CLEANUP_PERIOD_SEC = 120 * 3600; // 5 days
                LogRotation logRotation(*m_reactor, LOG_ROTATION_PERIOD_SEC, LOG_CLEANUP_PERIOD_SEC);

                auto wallet = make_shared<Wallet>(m_walletDB, withAssets);
                m_wallet = wallet;

                if (txCreators)
                {
                    for (auto&[txType, creator] : *txCreators)
                    {
                        wallet->RegisterTransactionType(txType, creator);
                    }
                }

                wallet->ResumeAllTransactions();

                updateClientState();

                auto nodeNetwork = make_shared<NodeNetwork>(*wallet, m_initialNodeAddrStr);
                m_nodeNetwork = nodeNetwork;

                using NodeNetworkSubscriber = ScopedSubscriber<INodeConnectionObserver, NodeNetwork>;
                auto nodeNetworkSubscriber =
                    std::make_unique<NodeNetworkSubscriber>(static_cast<INodeConnectionObserver*>(this), nodeNetwork);

                auto walletNetwork = make_shared<WalletNetworkViaBbs>(*wallet, nodeNetwork, m_walletDB);
                m_walletNetwork = walletNetwork;
                wallet->SetNodeEndpoint(nodeNetwork);
                wallet->AddMessageEndpoint(walletNetwork);

                auto wallet_subscriber = make_unique<WalletSubscriber>(static_cast<IWalletObserver*>(this), wallet);

                // Notification center initialization
                m_notificationCenter =
                    make_shared<NotificationCenter>(*m_walletDB, activeNotifications, m_reactor->shared_from_this());
                using NotificationsSubscriber = ScopedSubscriber<INotificationsObserver, NotificationCenter>;

                struct MyNotificationsObserver : INotificationsObserver
                {
                    WalletClient& m_client;
                    MyNotificationsObserver(WalletClient& client) : m_client(client) {}
                    void onNotificationsChanged(ChangeAction action, const std::vector<Notification>& items) override
                    {
                        m_client.updateNotifications();
                        static_cast<INotificationsObserver&>(m_client).onNotificationsChanged(action, items);
                    }
                } notificationObserver(*this);

                auto notificationsSubscriber =
                    make_unique<NotificationsSubscriber>(&notificationObserver, m_notificationCenter);
                updateNotifications();
                // Broadcast router and broadcast message consumers initialization
                auto broadcastRouter = make_shared<BroadcastRouter>(*nodeNetwork, *walletNetwork);
                m_broadcastRouter = broadcastRouter;


                using WalletDbSubscriber = ScopedSubscriber<IWalletDbObserver, IWalletDB>;
                // Swap offer board uses broadcasting messages
#ifdef HDS_ATOMIC_SWAP_SUPPORT
                OfferBoardProtocolHandler protocolHandler(m_walletDB->get_SbbsKdf());

                auto offersBulletinBoard = make_shared<SwapOffersBoard>(*broadcastRouter, protocolHandler, m_walletDB);
                m_offersBulletinBoard = offersBulletinBoard;

                using SwapOffersBoardSubscriber = ScopedSubscriber<ISwapOffersObserver, SwapOffersBoard>;

                auto walletDbSubscriber = make_unique<WalletDbSubscriber>(
                    static_cast<IWalletDbObserver*>(offersBulletinBoard.get()), m_walletDB);
                auto swapOffersBoardSubscriber = make_unique<SwapOffersBoardSubscriber>(
                    static_cast<ISwapOffersObserver*>(this), offersBulletinBoard);
#endif
                // Broadcast validator initialization. It verifies messages signatures.
                auto broadcastValidator = make_shared<BroadcastMsgValidator>();
                {
                    PeerID key;
                    if (BroadcastMsgValidator::stringToPublicKey(kBroadcastValidatorPublicKey, key))
                    {
                        broadcastValidator->setPublisherKeys( { key } );
                    }
                }

                // Other content providers using broadcast messages
                auto walletUpdatesProvider = make_shared<WalletUpdatesProvider>(*broadcastRouter, *broadcastValidator);
                auto exchangeRateProvider = make_shared<ExchangeRateProvider>(
                    *broadcastRouter, *broadcastValidator, *m_walletDB, isSecondCurrencyEnabled);
                m_exchangeRateProvider = exchangeRateProvider;
                m_walletUpdatesProvider = walletUpdatesProvider;
                using WalletUpdatesSubscriber = ScopedSubscriber<INewsObserver, WalletUpdatesProvider>;
                using ExchangeRatesSubscriber = ScopedSubscriber<IExchangeRateObserver, ExchangeRateProvider>;
                auto walletUpdatesSubscriber = make_unique<WalletUpdatesSubscriber>(static_cast<INewsObserver*>(
                    m_notificationCenter.get()), walletUpdatesProvider);
                auto ratesSubscriber = make_unique<ExchangeRatesSubscriber>(
                    static_cast<IExchangeRateObserver*>(this), exchangeRateProvider);
                auto notificationsDbSubscriber = make_unique<WalletDbSubscriber>(
                    static_cast<IWalletDbObserver*>(m_notificationCenter.get()), m_walletDB);

                nodeNetwork->tryToConnect();
                m_reactor->run_ex([&wallet, &nodeNetwork](){
                    wallet->CleanupNetwork();
                    nodeNetwork->Disconnect();
                });

                assert(walletNetwork.use_count() == 1);
                walletNetwork.reset();

                nodeNetworkSubscriber.reset();
                assert(nodeNetwork.use_count() == 1);
                nodeNetwork.reset();

                m_DeferredBalanceUpdate.cancel(); // for more safety, while we see the same reactor
            }
            catch (const runtime_error& ex)
            {
                LOG_ERROR() << ex.what();
                FailedToStartWallet();
            }
            catch (...) {
                LOG_UNHANDLED_EXCEPTION();
            }
        });
    }

    IWalletModelAsync::Ptr WalletClient::getAsync()
    {
        return m_async;
    }

    std::string WalletClient::getNodeAddress() const
    {
        if (auto s = m_nodeNetwork.lock())
        {
            return s->getNodeAddress();
        }
        else
        {
            return m_initialNodeAddrStr;
        }
    }

    std::string WalletClient::exportOwnerKey(const hds::SecString& pass) const
    {
        Key::IPKdf::Ptr pOwner = m_walletDB->get_OwnerKdf();

        KeyString ks;
        ks.SetPassword(Blob(pass.data(), static_cast<uint32_t>(pass.size())));
        ks.m_sMeta = std::to_string(0);

        ks.ExportP(*pOwner);

        return ks.m_sRes;
    }

    bool WalletClient::isRunning() const
    {
        return m_thread && m_thread->joinable();
    }

    bool WalletClient::isFork1() const
    {
        return m_currentHeight >= Rules::get().pForks[1].m_Height;
    }

    size_t WalletClient::getUnsafeActiveTransactionsCount() const
    {
        return m_unsafeActiveTxCount;
    }

    size_t WalletClient::getUnreadNotificationsCount() const
    {
        return m_unreadNotificationsCount;
    }

    bool WalletClient::isConnectionTrusted() const
    {
        return m_isConnectionTrusted;
    }

    void WalletClient::onCoinsChanged(ChangeAction action, const std::vector<Coin>& items)
    {
        m_CoinChangesCollector.CollectItems(action, items);
        m_DeferredBalanceUpdate.start();
    }

    void WalletClient::DeferredBalanceUpdate::OnSchedule()
    {
        cancel();
        get_ParentObj().onStatus(get_ParentObj().getStatus());
    }

    void WalletClient::onTransactionChanged(ChangeAction action, const std::vector<TxDescription>& items)
    {
        if (action == ChangeAction::Added)
        {
            for (const auto& tx : items)
            {
                if (tx.m_txType == TxType::Simple)
                {
                    assert(!m_exchangeRateProvider.expired());
                    if (auto p = m_exchangeRateProvider.lock())
                    {
                        m_walletDB->setTxParameter( tx.m_txId,
                                                    kDefaultSubTxID,
                                                    TxParameterID::ExchangeRates,
                                                    toByteBuffer(p->getRates()),
                                                    false);
                    }
                }
            }
        }

        m_TransactionChangesCollector.CollectItems(action, items);
        updateClientTxState();
    }

    void WalletClient::onSystemStateChanged(const Block::SystemState::ID& stateID)
    {
        onStatus(getStatus());
        updateClientState();
    }

    void WalletClient::onAddressChanged(ChangeAction action, const std::vector<WalletAddress>& items)
    {
        m_AddressChangesCollector.CollectItems(action, items);
    }

    void WalletClient::onSyncProgress(int done, int total)
    {
        onSyncProgressUpdated(done, total);
    }

    void WalletClient::onOwnedNode(const PeerID& id, bool connected)
    {
        updateConnectionTrust(connected);
        onNodeConnectionChanged(isConnected());
    }

    void WalletClient::sendMoney(const WalletID& receiver, const std::string& comment, Amount amount, Amount fee)
    {
        try
        {
            assert(!m_wallet.expired());
            auto s = m_wallet.lock();
            if (s)
            {
                WalletAddress senderAddress;
                m_walletDB->createAddress(senderAddress);
                saveAddress(senderAddress, true); // should update the wallet_network
                ByteBuffer message(comment.begin(), comment.end());

                TxParameters txParameters = CreateSimpleTransactionParameters()
                    .SetParameter(TxParameterID::MyID, senderAddress.m_walletID)
                    .SetParameter(TxParameterID::PeerID, receiver)
                    .SetParameter(TxParameterID::Amount, amount)
                    .SetParameter(TxParameterID::Fee, fee)
                    .SetParameter(TxParameterID::Message, message);

                s->StartTransaction(txParameters);
            }

            onSendMoneyVerified();
        }
        catch (const CannotGenerateSecretException&)
        {
            onNewAddressFailed();
            return;
        }
        catch (const AddressExpiredException&)
        {
            onCantSendToExpired();
            return;
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::sendMoney(const WalletID& sender, const WalletID& receiver, const std::string& comment, Amount amount, Amount fee)
    {
        try
        {
            assert(!m_wallet.expired());
            auto s = m_wallet.lock();
            if (s)
            {
                ByteBuffer message(comment.begin(), comment.end());
                TxParameters txParameters = CreateSimpleTransactionParameters()
                    .SetParameter(TxParameterID::MyID, sender)
                    .SetParameter(TxParameterID::PeerID, receiver)
                    .SetParameter(TxParameterID::Amount, amount)
                    .SetParameter(TxParameterID::Fee, fee)
                    .SetParameter(TxParameterID::Message, message);
                
                s->StartTransaction(txParameters);
            }

            onSendMoneyVerified();
        }
        catch (const CannotGenerateSecretException&)
        {
            onNewAddressFailed();
            return;
        }
        catch (const AddressExpiredException&)
        {
            onCantSendToExpired();
            return;
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::startTransaction(TxParameters&& parameters)
    {
        try
        {
            assert(!m_wallet.expired());
            auto s = m_wallet.lock();
            if (s)
            {
                auto myID = parameters.GetParameter<WalletID>(TxParameterID::MyID);
                if (!myID)
                {
                    WalletAddress senderAddress;
                    m_walletDB->createAddress(senderAddress);
                    saveAddress(senderAddress, true); // should update the wallet_network
                
                    parameters.SetParameter(TxParameterID::MyID, senderAddress.m_walletID);
                }

                s->StartTransaction(parameters);
            }

            onSendMoneyVerified();
        }
        catch (const CannotGenerateSecretException&)
        {
            onNewAddressFailed();
            return;
        }
        catch (const AddressExpiredException&)
        {
            onCantSendToExpired();
            return;
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::syncWithNode()
    {
        assert(!m_nodeNetwork.expired());
        if (auto s = m_nodeNetwork.lock())
        {
            s->Connect();
    }
    }

    void WalletClient::calcChange(Amount amount)
    {
        auto coins = m_walletDB->selectCoins(amount, Zero);
        Amount sum = 0;
        for (auto& c : coins)
        {
            sum += c.m_ID.m_Value;
        }
        if (sum < amount)
        {
            onChangeCalculated(0);
        }
        else
        {
            onChangeCalculated(sum - amount);
        }
    }

    void WalletClient::getWalletStatus()
    {
        onStatus(getStatus());
    }

    void WalletClient::getTransactions()
    {
        onTxStatus(ChangeAction::Reset, m_walletDB->getTxHistory(wallet::TxType::ALL));
    }

    void WalletClient::getUtxosStatus()
    {
        onAllUtxoChanged(ChangeAction::Reset, getUtxos());
    }

    void WalletClient::getAddresses(bool own)
    {
        onAddresses(own, m_walletDB->getAddresses(own));
    }

#ifdef HDS_ATOMIC_SWAP_SUPPORT
    void WalletClient::getSwapOffers()
    {
        if (auto p = m_offersBulletinBoard.lock())
        {
            onSwapOffersChanged(ChangeAction::Reset, p->getOffersList());
        }
    }

    void WalletClient::publishSwapOffer(const SwapOffer& offer)
    {
        if (auto p = m_offersBulletinBoard.lock())
        {
            try
            {
                p->publishOffer(offer);
            }
            catch (const std::runtime_error& e)
            {
                LOG_ERROR() << offer.m_txId << e.what();
            }
        }
    }

    namespace {
        const char* SWAP_PARAMS_NAME = "LastSwapParams";
    }

    void WalletClient::loadSwapParams()
    {
        ByteBuffer params;
        m_walletDB->getBlob(SWAP_PARAMS_NAME, params);
        onSwapParamsLoaded(params);
    }

    void WalletClient::storeSwapParams(const ByteBuffer& params)
    {
        m_walletDB->setVarRaw(SWAP_PARAMS_NAME, params.data(), params.size());
    }
#endif  // HDS_ATOMIC_SWAP_SUPPORT

    void WalletClient::cancelTx(const TxID& id)
    {
        auto w = m_wallet.lock();
        if (w)
        {
            w->CancelTransaction(id);
        }
    }

    void WalletClient::deleteTx(const TxID& id)
    {
        auto w = m_wallet.lock();
        if (w)
        {
            w->DeleteTransaction(id);
        }
    }

    void WalletClient::getCoinsByTx(const TxID& id)
    {
        onCoinsByTx(m_walletDB->getCoinsByTx(id));
    }

    void WalletClient::saveAddress(const WalletAddress& address, bool bOwn)
    {
        m_walletDB->saveAddress(address);
    }

    void WalletClient::generateNewAddress()
    {
        try
        {
            WalletAddress address;
            m_walletDB->createAddress(address);

            onGeneratedNewAddress(address);
        }
        //catch (const TrezorKeyKeeper::DeviceNotConnected&)
        //{
        //    onNoDeviceConnected();
        //}
        catch (const CannotGenerateSecretException&)
        {
            onNewAddressFailed();
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::deleteAddress(const WalletID& id)
    {
        try
        {
            auto pVal = m_walletDB->getAddress(id);
            if (pVal)
            {
                m_walletDB->deleteAddress(id);
            }
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::updateAddress(const WalletID& id, const std::string& name, WalletAddress::ExpirationStatus status)
    {
        try
        {
            auto addr = m_walletDB->getAddress(id);

            if (addr)
            {
                if (addr->isOwn() &&
                    status != WalletAddress::ExpirationStatus::AsIs)
                {
                    addr->setExpiration(status);
                }
                addr->setLabel(name);
                m_walletDB->saveAddress(*addr);
            }
            else
            {
                LOG_ERROR() << "Address " << to_string(id) << " is absent.";
            }
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::activateAddress(const WalletID& id)
    {
        try
        {
            auto addr = m_walletDB->getAddress(id);
            if (addr)
            {
                if (addr->isOwn())
                {
                    addr->setExpiration(WalletAddress::ExpirationStatus::OneDay);
                }
                m_walletDB->saveAddress(*addr);
            }
            else
            {
                LOG_ERROR() << "Address " << to_string(id) << " is absent.";
            }
        }
        catch (const std::exception& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) {
            LOG_UNHANDLED_EXCEPTION();
        }
    }

    void WalletClient::setNodeAddress(const std::string& addr)
    {
        if (auto s = m_nodeNetwork.lock())
        {
            if (!(s->setNodeAddress(addr)))
            {
                LOG_ERROR() << "Unable to resolve node address: " << addr;
                onWalletError(ErrorType::HostResolvedError);
            }
            }
        else
        {
            io::Address address;
            if (address.resolve(addr.c_str()))
            {
                m_initialNodeAddrStr = addr;
        }
        else
        {
            LOG_ERROR() << "Unable to resolve node address: " << addr;
            onWalletError(ErrorType::HostResolvedError);
        }
    }
    }

    void WalletClient::changeWalletPassword(const SecString& pass)
    {
        m_walletDB->changePassword(pass);
    }

    void WalletClient::getNetworkStatus()
    {
        if (m_walletError.is_initialized() && !isConnected())
        {
            onWalletError(*m_walletError);
            return;
        }

        onNodeConnectionChanged(isConnected());
    }

    void WalletClient::rescan()
    {
        try
        {
            assert(!m_wallet.expired());
            auto s = m_wallet.lock();
            if (s)
            {
                s->Rescan();
            }
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

    void WalletClient::exportPaymentProof(const TxID& id)
    {
        onPaymentProofExported(id, storage::ExportPaymentProof(*m_walletDB, id));
    }

    void WalletClient::checkAddress(const std::string& addr)
    {
        io::Address nodeAddr;

        onAddressChecked(addr, nodeAddr.resolve(addr.c_str()));
    }

    void WalletClient::importRecovery(const std::string& path)
    {
        try
        {
            m_walletDB->ImportRecovery(path, *this);
            return;
        }
        catch (const std::runtime_error& e)
        {
            LOG_UNHANDLED_EXCEPTION() << "what = " << e.what();
        }
        catch (...) 
        {
            LOG_UNHANDLED_EXCEPTION();
        }
        onWalletError(ErrorType::ImportRecoveryError);
    }

    void WalletClient::importDataFromJson(const std::string& data)
    {
        auto isOk = storage::ImportDataFromJson(*m_walletDB, data.data(), data.size());

        onImportDataFromJson(isOk);
    }

    void WalletClient::exportDataToJson()
    {
        auto data = storage::ExportDataToJson(*m_walletDB);

        onExportDataToJson(data);
    }

    void WalletClient::exportTxHistoryToCsv()
    {
        auto data = storage::ExportTxHistoryToCsv(*m_walletDB);

        onExportTxHistoryToCsv(data);   
    }

    void WalletClient::switchOnOffExchangeRates(bool isActive)
    {
        assert(!m_exchangeRateProvider.expired());
        if (auto s = m_exchangeRateProvider.lock())
        {
            s->setOnOff(isActive);
        }
    }

    void WalletClient::switchOnOffNotifications(Notification::Type type, bool isActive)
    {
        m_notificationCenter->switchOnOffNotifications(type, isActive);
    }
    
    void WalletClient::getNotifications()
    {
        onNotificationsChanged(ChangeAction::Reset, m_notificationCenter->getNotifications());
    }

    void WalletClient::markNotificationAsRead(const ECC::uintBig& id)
    {
        m_notificationCenter->markNotificationAsRead(id);
    }

    void WalletClient::deleteNotification(const ECC::uintBig& id)
    {
        m_notificationCenter->deleteNotification(id);
    }

    void WalletClient::getExchangeRates()
    {
        assert(!m_exchangeRateProvider.expired());
        if (auto s = m_exchangeRateProvider.lock())
        {
            onExchangeRates(s->getRates());
        }
        else
        {
            onExchangeRates({});
        }
    }

    bool WalletClient::OnProgress(uint64_t done, uint64_t total)
    {
        onImportRecoveryProgress(done, total);
        return true;
    }

    WalletStatus WalletClient::getStatus() const
    {
        WalletStatus status;
        storage::Totals totalsCalc(*m_walletDB);
        const auto& totals = totalsCalc.GetHdsTotals();

        status.available         = AmountBig::get_Lo(totals.Avail);
        status.receivingIncoming = AmountBig::get_Lo(totals.ReceivingIncoming);
        status.receivingChange   = AmountBig::get_Lo(totals.ReceivingChange);
        status.receiving         = AmountBig::get_Lo(totals.Incoming);
        status.sending           = AmountBig::get_Lo(totals.Outgoing);
        status.maturing          = AmountBig::get_Lo(totals.Maturing);
        status.update.lastTime   = m_walletDB->getLastUpdateTime();

        ZeroObject(status.stateID);
        m_walletDB->getSystemStateID(status.stateID);

        return status;
    }

    vector<Coin> WalletClient::getUtxos() const
    {
        vector<Coin> utxos;
        m_walletDB->visitCoins([&utxos](const Coin& c)->bool
            {
                utxos.push_back(c);
                return true;
            });
        return utxos;
    }

    void WalletClient::onNodeConnectionFailed(const proto::NodeConnection::DisconnectReason& reason)
    {
        // reason -> ErrorType
        if (proto::NodeConnection::DisconnectReason::ProcessingExc == reason.m_Type)
        {
            m_walletError = getWalletError(reason.m_ExceptionDetails.m_ExceptionType);
            onWalletError(*m_walletError);
            return;
        }

        if (proto::NodeConnection::DisconnectReason::Io == reason.m_Type)
        {
            m_walletError = getWalletError(reason.m_IoError);
            onWalletError(*m_walletError);
            return;
        }

        LOG_ERROR() << "Unprocessed error: " << reason;
    }

    void WalletClient::onNodeConnectedStatusChanged(bool isNodeConnected)
    {
        if (isNodeConnected)
        {
            ++m_connectedNodesCount;
        }
        else if (m_connectedNodesCount)
        {
            --m_connectedNodesCount;
        }

        onNodeConnectionChanged(isConnected());
    }

    void WalletClient::updateClientState()
    {
        if (auto w = m_wallet.lock(); w)
        {
            postFunctionToClientContext([this, currentHeight = m_walletDB->getCurrentHeight(), count = w->GetUnsafeActiveTransactionsCount()]()
            {
                m_currentHeight = currentHeight;
                m_unsafeActiveTxCount = count;
            });
        }
    }
    void WalletClient::updateClientTxState()
    {
        if (auto w = m_wallet.lock(); w)
        {
            postFunctionToClientContext([this, count = w->GetUnsafeActiveTransactionsCount()]()
            {
                m_unsafeActiveTxCount = count;
            });
        }
    }

    void WalletClient::updateNotifications()
    {
        size_t count = m_notificationCenter->getUnreadCount(
            [this] (NotificationCenter::Cache::const_iterator first, NotificationCenter::Cache::const_iterator last)
            {
                auto currentLibVersion = getLibVersion();
                auto currentClientRevision = getClientRevision();
                return std::count_if(first, last,
                    [&currentLibVersion, &currentClientRevision](const auto& p)
                    {
                        if (p.second.m_state == Notification::State::Unread)
                        {
                            if (p.second.m_type == Notification::Type::WalletImplUpdateAvailable)
                            {
                                WalletImplVerInfo info;
                                if (fromByteBuffer(p.second.m_content, info) &&
                                    VersionInfo::Application::DesktopWallet == info.m_application &&
                                    (currentLibVersion < info.m_version ||
                                    (currentLibVersion == info.m_version && currentClientRevision < info.m_UIrevision)))
                                {
                                    return true;
                                }
                            }
                            if (p.second.m_type == Notification::Type::TransactionFailed)
                            {
                                return true;
                            }
                        }
                        return false;
                    });
            });
        postFunctionToClientContext([this, count]()
        {
            m_unreadNotificationsCount = count;
        });
    }

    void WalletClient::updateConnectionTrust(bool trustedConnected)
    {
        if (trustedConnected)
        {
            ++m_trustedConnectionCount;
        }
        else if (m_trustedConnectionCount)
        {
            --m_trustedConnectionCount;
        }

        postFunctionToClientContext([this, isTrusted = m_trustedConnectionCount > 0 && m_trustedConnectionCount == m_connectedNodesCount]()
        {
            m_isConnectionTrusted = isTrusted;
        });
    }

    bool WalletClient::isConnected() const
    {
        return m_connectedNodesCount > 0;
    }
}
