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

#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wdelete-non-virtual-dtor"
#endif

#include <boost/optional.hpp>

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif

#include <tuple>
#include "core/common.h"
#include "core/ecc_native.h"
#include "common.h"
#include "utility/io/address.h"
#include "secstring.h"
#include "private_key_keeper.h"
#include "variables_db.h"
#include "wallet/client/extensions/notifications/notification.h"
#include "wallet/client/extensions/news_channels/interface.h"
#include "wallet/core/assets_utils.h"

#include <string>

struct sqlite3;

namespace hds::wallet
{
    const uint32_t EmptyCoinSession = 0;

    // Describes a UTXO in the context of the Wallet
    struct Coin
    {
        // Status is not stored in the database but can be
        // deduced from the current blockchain state
        enum Status
        {
            Unavailable, // initial status of a new UTXO
            Available,   // UTXO is currently present in the chain and can be spent
            Maturing,    // UTXO is present in the chain has maturity higher than current height (i.e coinbase or treasury)
            Outgoing,    // Available and participates in outgoing transaction
            Incoming,    // Outputs of incoming transaction, currently unavailable
            ChangeV0,    // deprecated.
            Spent,       // UTXO that was spent. Stored in wallet database until reset or restore
            Consumed,    // Asset UTXO that was consumed (converted back to HDS). Stored in wallet db until reset or restore
            count
        };

        explicit Coin(Amount amount = 0, Key::Type keyType = Key::Type::Regular, Asset::ID assetId = Asset::s_InvalidID);
        bool operator==(const Coin&) const;
        bool operator!=(const Coin&) const;
        bool isReward() const;
        bool isAsset() const;
        bool isAsset(Asset::ID) const;
        std::string toStringID() const;
        Amount getAmount() const;

        typedef CoinID ID; // unique identifier for the coin
        ID m_ID;

        Status m_status;        // current status of the coin
        Height m_maturity;      // coin can be spent only when chain is >= this value. Valid for confirmed coins (Available, Outgoing, Incoming, Change, Spent, Maturing).

                                // The following fields are used to derive the status of the transaction
        Height m_confirmHeight; // height at which the coin was confirmed (appeared in the chain)
        Height m_spentHeight;   // height at which the coin was spent

        boost::optional<TxID> m_createTxId;  // id of the transaction which created the UTXO
        boost::optional<TxID> m_spentTxId;   // id of the transaction which spent the UTXO
        
        uint64_t m_sessionId;   // Used in the API to lock coins for specific session (see https://github.com/hadescoincom/hds-core/wiki/Hds-wallet-protocol-API#tx_split)

        bool m_isUnlinked = false;

        bool IsMaturityValid() const; // is/was the UTXO confirmed?
        Height get_Maturity() const; // would return MaxHeight unless the UTXO was confirmed
        
        std::string getStatusString() const;
        static boost::optional<Coin::ID> FromString(const std::string& str);
    };

    using CoinIDList = std::vector<Coin::ID>;
    std::string toString(const CoinID& id);
    // Used for SBBS Address management in the wallet
    struct WalletAddress
    {
        WalletID m_walletID; // derived from SBBS
        std::string m_label;
        std::string m_category;
        Timestamp m_createTime;
        uint64_t  m_duration;   // if equals to "AddressNeverExpires" then address never expires
        uint64_t  m_OwnID;      // set for own address
        PeerID    m_Identity;   // derived from master. Different from m_walletID
        
        WalletAddress();
        bool operator == (const WalletAddress& other) const;
        bool operator != (const WalletAddress& other) const;
        bool isExpired() const;
        bool isOwn() const;
        Timestamp getCreateTime() const;
        Timestamp getExpirationTime() const;

        SERIALIZE(  m_walletID,
                    m_label,
                    m_category,
                    m_createTime,
                    m_duration,
                    m_OwnID,
                    m_Identity);
        
        enum class ExpirationStatus
        {
            Expired = 0,
            OneDay,
            Never,
            AsIs
        };
        void setLabel(const std::string& label);
        void setExpiration(ExpirationStatus status);

        static constexpr uint64_t AddressExpirationNever = 0;
        static constexpr uint64_t AddressExpiration24h   = 24 * 60 * 60;
        static constexpr uint64_t AddressExpiration1h    = 60 * 60;
    };

    class ILaserChannelEntity
    {
    public:
        virtual const std::shared_ptr<uintBig_t<16>>& get_chID() const = 0;
        virtual const WalletID& get_myWID() const = 0;
        virtual const WalletID& get_trgWID() const = 0;
        virtual int get_State() const = 0;
        virtual const Amount& get_fee() const = 0;
        virtual const Height& getLocktime() const = 0;
        virtual const Amount& get_amountMy() const = 0;
        virtual const Amount& get_amountTrg() const = 0;
        virtual const Amount& get_amountCurrentMy() const = 0;
        virtual const Amount& get_amountCurrentTrg() const = 0;
        virtual const Height& get_LockHeight() const = 0;
        virtual const Timestamp& get_BbsTimestamp() const = 0;
        virtual const ByteBuffer& get_Data() const = 0;
        virtual const WalletAddress& get_myAddr() const = 0;
    };

    class LaserFields
    {
    public:
        static constexpr size_t LASER_CH_ID = 0;
        static constexpr size_t LASER_MY_WID = 1;
        static constexpr size_t LASER_TRG_WID = 2;
        static constexpr size_t LASER_STATE = 3;
        static constexpr size_t LASER_FEE = 4;
        static constexpr size_t LASER_LOCKTIME = 5;
        static constexpr size_t LASER_AMOUNT_MY = 6;
        static constexpr size_t LASER_AMOUNT_TRG = 7;
        static constexpr size_t LASER_AMOUNT_CURRENT_MY = 8;
        static constexpr size_t LASER_AMOUNT_CURRENT_TRG = 9;
        static constexpr size_t LASER_LOCK_HEIGHT = 10;
        static constexpr size_t LASER_BBS_TIMESTAMP = 11;
        static constexpr size_t LASER_DATA = 12;
    };

    // TODO: consider using struct here
    using TLaserChannelEntity = std::tuple<
        uintBig_t<16>,  // 0 chID
        WalletID,       // 1 myWID
        WalletID,       // 2 trgWID
        int,            // 3 State
        Amount,         // 4 fee
        Height,         // 5 Locktime
        Amount,         // 6 amountMy
        Amount,         // 7 amountTrg
        Amount,         // 8 amountCurrentMy
        Amount,         // 9 amountCurrentTrg
        Height,         // 10 lockHeight
        Timestamp,      // 11 bbs timestamp
        ByteBuffer      // 12 Data
    >;

    // Describes structure of generic transaction parameter
    struct TxParameter
    {
        TxID m_txID;
        int m_subTxID = static_cast<int>(kDefaultSubTxID);
        int m_paramID;
        ByteBuffer m_value;
    };

    // Outgoing wallet messages sent through SBBS (used in Cold Wallet)
    struct OutgoingWalletMessage
    {
        int m_ID;
        WalletID m_PeerID;
        ByteBuffer m_Message;
    };

    // Used for storing incoming SBBS messages before they can be processed (used in Cold Wallet)
    struct IncomingWalletMessage
    {
        int m_ID;
        BbsChannel m_Channel;
        ByteBuffer m_Message;
    };

    struct ShieldedCoin
    {
        static const TxoID kTxoInvalidID = std::numeric_limits<TxoID>::max();

        bool IsAvailable() const
        {
            return m_confirmHeight != MaxHeight && m_spentHeight == MaxHeight && !m_spentTxId;
        }

        ShieldedTxo::BaseKey m_Key;
        ShieldedTxo::User m_User;

        TxoID m_ID = kTxoInvalidID;
        Asset::ID m_assetID = 0;

        Amount m_value = 0;
        Height m_confirmHeight = MaxHeight;  // height at which the coin was confirmed (appeared in the chain)
        Height m_spentHeight = MaxHeight;    // height at which the coin was spent

        boost::optional<TxID> m_createTxId;  // id of the transaction which created the UTXO
        boost::optional<TxID> m_spentTxId;   // id of the transaction which spent the UTXO
    };

    // Notifications for all collection changes
    enum class ChangeAction
    {
        Added,
        Removed,
        Updated,
        Reset
    };

    class CannotGenerateSecretException : public std::runtime_error
    {
    public:
        explicit CannotGenerateSecretException()
            : std::runtime_error("")
        {
        }

    };

    class DatabaseException : public std::runtime_error
    {
    public:
        explicit DatabaseException(const std::string& message)
            : std::runtime_error(message)
        {
        }
    };

    class InvalidDatabaseVersionException : public DatabaseException
    {
    public:
        explicit InvalidDatabaseVersionException()
            : DatabaseException("Invalid database version")
        {
        }
    };

    class DatabaseMigrationException : public DatabaseException
    {
    public:
        explicit DatabaseMigrationException()
            : DatabaseException("Database migration error")
        {
        }
    };

    class DatabaseNotFoundException : public DatabaseException
    {
    public:
        explicit DatabaseNotFoundException()
            : DatabaseException("Database not found")
        {
        }
    };
    
    class FileIsNotDatabaseException : public DatabaseException
    {
    public:
        explicit FileIsNotDatabaseException()
            : DatabaseException("File is not a database")
        {
        }
    };

    struct IWalletDbObserver
    {
        virtual void onCoinsChanged(ChangeAction action, const std::vector<Coin>& items) {};
        virtual void onTransactionChanged(ChangeAction action, const std::vector<TxDescription>& items) {};
        virtual void onSystemStateChanged(const Block::SystemState::ID& stateID) {};
        virtual void onAddressChanged(ChangeAction action, const std::vector<WalletAddress>& items) {};
        virtual void onShieldedCoinsChanged(ChangeAction action, const std::vector<ShieldedCoin>& items) {};
    };

    struct IWalletDB : IVariablesDB
    {
        using Ptr = std::shared_ptr<IWalletDB>;
        virtual ~IWalletDB() {}

        // Those are the possible wallet modes:
        // 1. Wallet with seed. All the keys are available.
        // 2. Wallet with KeyKeeper in a trustless mode. Master key is inaccessible, only "simple" transactions are supported.
        // 3. Read-only wallet. Only owner key is accessible. Can't build txs, no sbbs communication. Only UTXO movements are visible.

        virtual hds::Key::IKdf::Ptr get_MasterKdf() const = 0; // Available in (1)
        virtual hds::Key::IPKdf::Ptr get_OwnerKdf() const = 0; // Always available
        virtual hds::Key::IKdf::Ptr get_SbbsKdf() const = 0; // Unavailable in (3)
        virtual IPrivateKeyKeeper2::Ptr get_KeyKeeper() const = 0; // Unavailable in (3)

        virtual IPrivateKeyKeeper2::Slot::Type SlotAllocate() = 0;
        virtual void SlotFree(IPrivateKeyKeeper2::Slot::Type) = 0;

		// import blockchain recovery data (all at once)
		// should be used only upon creation on 'clean' wallet. Throws exception on error
		void ImportRecovery(const std::string& path);

        bool IsRecoveredMatch(CoinID&, const ECC::Point& comm);
        bool get_CommitmentSafe(ECC::Point& comm, const CoinID&);

        void get_SbbsPeerID(ECC::Scalar::Native&, PeerID&, uint64_t ownID);
        void get_SbbsWalletID(ECC::Scalar::Native&, WalletID&, uint64_t ownID);
        void get_SbbsWalletID(WalletID&, uint64_t ownID);
        bool ValidateSbbsWalletID(const WalletID&, uint64_t ownID);
        void createAddress(WalletAddress&);
        void get_Identity(PeerID&, uint64_t ownID) const;

		struct IRecoveryProgress
		{
			virtual bool OnProgress(uint64_t done, uint64_t total) { return true; } // return false to stop recovery
		};

		// returns false if callback asked to stop verification.
		bool ImportRecovery(const std::string& path, IRecoveryProgress&);

        // Allocates new Key ID, used for generation of the blinding factor
        // Will return the next id starting from a random base created during wallet initialization
        virtual uint64_t AllocateKidRange(uint64_t nCount) = 0;

        // Selects a list of coins matching certain specified amount
        // Selection logic will optimize for number of UTXOs and minimize change
        // Uses greedy algorithm up to a point and follows by some heuristics
        virtual std::vector<Coin> selectCoins(Amount amount, Asset::ID) = 0;
        virtual std::vector<Coin> selectUnlinkedCoins(Amount amount, Asset::ID) = 0;

        // Some getters to get lists of coins by some input parameters
        virtual std::vector<Coin> getCoinsCreatedByTx(const TxID& txId) const = 0;
        virtual std::vector<Coin> getCoinsByTx(const TxID& txId) const = 0;
        virtual std::vector<Coin> getCoinsByID(const CoinIDList& ids) const = 0;

        // Generates a new valid coin with specific amount. In order to save it into the database you have to call save() method
        virtual Coin generateNewCoin(Amount amount, Asset::ID) = 0;

        // Set of basic coin related database methods
        virtual void storeCoin(Coin& coin) = 0;
        virtual void storeCoins(std::vector<Coin>&) = 0;
        virtual void saveCoin(const Coin& coin) = 0;
        virtual void saveCoins(const std::vector<Coin>& coins) = 0;
        virtual void removeCoin(const Coin::ID&) = 0;
        virtual void removeCoins(const std::vector<Coin::ID>&) = 0;
        virtual bool findCoin(Coin& coin) = 0;
        virtual void clearCoins() = 0;

        // Generic visitors
        virtual void visitCoins(std::function<bool(const Coin& coin)> func) = 0;
        virtual void visitAssets(std::function<bool(const WalletAsset&)> func) = 0;
        virtual void visitShieldedCoins(std::function<bool(const ShieldedCoin& info)> func) = 0;

        // Used in split API for session management
        virtual bool lockCoins(const CoinIDList& list, uint64_t session) = 0;
        virtual bool unlockCoins(uint64_t session) = 0;
        virtual CoinIDList getLockedCoins(uint64_t session) const = 0;

        // Returns currently known blockchain height
        virtual Height getCurrentHeight() const = 0;

        // Rollback UTXO set to known height (used in rollback scenario)
        virtual void rollbackConfirmedUtxo(Height minHeight) = 0;
        virtual void rollbackAssets(Height minHeight) = 0;

        // Shielded coins
        virtual std::vector<ShieldedCoin> getShieldedCoins(Asset::ID assetId) const = 0;
        virtual boost::optional<ShieldedCoin> getShieldedCoin(const TxID& txId) const = 0;
        virtual boost::optional<ShieldedCoin> getShieldedCoin(TxoID id) const = 0;
        virtual boost::optional<ShieldedCoin> getShieldedCoin(const ShieldedTxo::BaseKey&) const = 0;
        virtual void saveShieldedCoin(const ShieldedCoin& shieldedCoin) = 0;

        // Rollback shielded UTXO set to known height (used in rollback scenario)
        virtual void rollbackConfirmedShieldedUtxo(Height minHeight) = 0;

        // /////////////////////////////////////////////
        // Transaction management
        virtual std::vector<TxDescription> getTxHistory(wallet::TxType txType = wallet::TxType::Simple, uint64_t start = 0, int count = std::numeric_limits<int>::max()) const = 0;
        virtual boost::optional<TxDescription> getTx(const TxID& txId) const = 0;
        virtual void saveTx(const TxDescription& p) = 0;
        virtual void deleteTx(const TxID& txId) = 0;
        virtual bool setTxParameter(const TxID& txID, SubTxID subTxID, TxParameterID paramID,
            const ByteBuffer& blob, bool shouldNotifyAboutChanges) = 0;
        virtual bool getTxParameter(const TxID& txID, SubTxID subTxID, TxParameterID paramID, ByteBuffer& blob) const = 0;
        virtual std::vector<TxParameter> getAllTxParameters() const = 0;
        virtual void rollbackTx(const TxID& txId) = 0;
        virtual void deleteCoinsCreatedByTx(const TxID& txId) = 0;

        virtual void restoreShieldedCoinsSpentByTx(const TxID& txId) = 0;
        virtual void deleteShieldedCoinsCreatedByTx(const TxID& txId) = 0;

        // ////////////////////////////////////////////
        // Address management
        virtual boost::optional<WalletAddress> getAddress(
                const WalletID&, bool isLaser = false) const = 0;
        virtual std::vector<WalletAddress> getAddresses(bool own, bool isLaser = false) const = 0;
        virtual void saveAddress(const WalletAddress&, bool isLaser = false) = 0;
        virtual void deleteAddress(const WalletID&, bool isLaser = false) = 0;

        // Laser
        virtual void saveLaserChannel(const ILaserChannelEntity&) = 0;
        virtual bool getLaserChannel(const std::shared_ptr<uintBig_t<16>>& chId,
                                     TLaserChannelEntity* entity) = 0;
        virtual bool removeLaserChannel(const std::shared_ptr<uintBig_t<16>>& chId) = 0;
        virtual std::vector<TLaserChannelEntity> loadLaserChannels(uint8_t state = 0) = 0;

        // 
        virtual Timestamp getLastUpdateTime() const = 0;
        virtual void setSystemStateID(const Block::SystemState::ID& stateID) = 0;
        virtual bool getSystemStateID(Block::SystemState::ID& stateID) const = 0;

        virtual void Subscribe(IWalletDbObserver* observer) = 0;
        virtual void Unsubscribe(IWalletDbObserver* observer) = 0;

        virtual void changePassword(const SecString& password) = 0;

        // Block History management, used in FlyClient
        virtual Block::SystemState::IHistory& get_History() = 0;
        virtual void ShrinkHistory() = 0;

        // ///////////////////////////////
        // Message management
        virtual std::vector<OutgoingWalletMessage> getWalletMessages() const = 0;
        virtual uint64_t saveWalletMessage(const OutgoingWalletMessage& message) = 0;
        virtual void deleteWalletMessage(uint64_t id) = 0;

        virtual std::vector<IncomingWalletMessage> getIncomingWalletMessages() const = 0;
        virtual uint64_t saveIncomingWalletMessage(BbsChannel channel, const ByteBuffer& message) = 0;
        virtual void deleteIncomingWalletMessage(uint64_t id) = 0;

        // Assets management
        virtual void saveAsset(const Asset::Full& info, Height refreshHeight) = 0;
        virtual void markAssetOwned(const Asset::ID assetId) = 0;
        virtual void dropAsset(const Asset::ID assetId) = 0;
        virtual void dropAsset(const PeerID& ownerId) = 0;
        virtual boost::optional<WalletAsset> findAsset(Asset::ID) = 0;
        virtual boost::optional<WalletAsset> findAsset(const PeerID&) = 0;

        // Notifications management
        virtual std::vector<Notification> getNotifications() const = 0;
        virtual void saveNotification(const Notification&) = 0;

        // Exchange rates management
        virtual std::vector<ExchangeRate> getExchangeRates() const = 0;
        virtual void saveExchangeRate(const ExchangeRate&) = 0;

        void addStatusInterpreterCreator(TxType txType, TxStatusInterpreter::Creator interpreterCreator);
        TxStatusInterpreter getStatusInterpreter(const TxParameters& txParams) const;

       private:
           bool get_CommitmentSafe(ECC::Point& comm, const CoinID&, IPrivateKeyKeeper2*);
           std::map<TxType, TxStatusInterpreter::Creator> m_statusInterpreterCreators;
    };

    namespace sqlite
    {
        struct Statement;
        struct Transaction;
    }  // namespace sqlite

    class WalletDB : public IWalletDB
    {
    public:
        static bool isInitialized(const std::string& path);
        static Ptr init(const std::string& path, const SecString& password, const ECC::NoLeak<ECC::uintBig>& secretKey, bool separateDBForPrivateData = false);
        static Ptr init(const std::string& path, const SecString& password, const IPrivateKeyKeeper2::Ptr&, bool separateDBForPrivateData = false);
        static Ptr open(const std::string& path, const SecString& password, const IPrivateKeyKeeper2::Ptr&);
        static Ptr open(const std::string& path, const SecString& password);

        WalletDB(sqlite3* db);
        WalletDB(sqlite3* db, sqlite3* sdb);
        ~WalletDB();

        virtual hds::Key::IKdf::Ptr get_MasterKdf() const override;
        virtual hds::Key::IPKdf::Ptr get_OwnerKdf() const override;
        virtual hds::Key::IKdf::Ptr get_SbbsKdf() const override;
        virtual IPrivateKeyKeeper2::Ptr get_KeyKeeper() const override;

        virtual uint32_t SlotAllocate() override;
        virtual void SlotFree(uint32_t) override;

        uint64_t AllocateKidRange(uint64_t nCount) override;
        std::vector<Coin> selectCoins(Amount amount, Asset::ID) override;
        std::vector<Coin> selectUnlinkedCoins(Amount amount, Asset::ID) override;
        std::vector<Coin> selectCoinsEx(Amount amount, Asset::ID, bool unlinked);

        std::vector<Coin> getCoinsCreatedByTx(const TxID& txId) const override;
        std::vector<Coin> getCoinsByTx(const TxID& txId) const override;
        std::vector<Coin> getCoinsByID(const CoinIDList& ids) const override;
        Coin generateNewCoin(Amount amount, Asset::ID) override;
        void storeCoin(Coin& coin) override;
        void storeCoins(std::vector<Coin>&) override;
        void saveCoin(const Coin& coin) override;
        void saveCoins(const std::vector<Coin>& coins) override;
        void removeCoin(const Coin::ID&) override;
        void removeCoins(const std::vector<Coin::ID>&) override;
        bool findCoin(Coin& coin) override;
        void clearCoins() override;

        void visitCoins(std::function<bool(const Coin& coin)> func) override;
        void visitAssets(std::function<bool(const WalletAsset& info)> func) override;
        void visitShieldedCoins(std::function<bool(const ShieldedCoin& info)> func) override;

        void setVarRaw(const char* name, const void* data, size_t size) override;
        bool getVarRaw(const char* name, void* data, int size) const override;
        void removeVarRaw(const char* name) override;

        void setPrivateVarRaw(const char* name, const void* data, size_t size) override;
        bool getPrivateVarRaw(const char* name, void* data, int size) const override;

        bool getBlob(const char* name, ByteBuffer& var) const override;
        Height getCurrentHeight() const override;
        void rollbackConfirmedUtxo(Height minHeight) override;
        void rollbackAssets(Height minHeight) override;

        std::vector<ShieldedCoin> getShieldedCoins(Asset::ID assetId) const override;
        boost::optional<ShieldedCoin> getShieldedCoin(const TxID& txId) const override;
        boost::optional<ShieldedCoin> getShieldedCoin(TxoID id) const override;
        boost::optional<ShieldedCoin> getShieldedCoin(const ShieldedTxo::BaseKey&) const override;
        void saveShieldedCoin(const ShieldedCoin& shieldedCoin) override;
        void rollbackConfirmedShieldedUtxo(Height minHeight) override;

        std::vector<TxDescription> getTxHistory(wallet::TxType txType, uint64_t start, int count) const override;
        boost::optional<TxDescription> getTx(const TxID& txId) const override;
        void saveTx(const TxDescription& p) override;
        void deleteTx(const TxID& txId) override;
        void rollbackTx(const TxID& txId) override;
        void deleteCoinsCreatedByTx(const TxID& txId) override;
        void restoreShieldedCoinsSpentByTx(const TxID& txId) override;
        void deleteShieldedCoinsCreatedByTx(const TxID& txId) override;

        std::vector<WalletAddress> getAddresses(bool own, bool isLaser = false) const override;
        void saveAddress(const WalletAddress&, bool isLaser = false) override;
        boost::optional<WalletAddress> getAddress(
            const WalletID&, bool isLaser = false) const override;
        void deleteAddress(const WalletID&, bool isLaser = false) override;

        void saveLaserChannel(const ILaserChannelEntity&) override;
        virtual bool getLaserChannel(const std::shared_ptr<uintBig_t<16>>& chId,
                                     TLaserChannelEntity* entity) override;
        bool removeLaserChannel(const std::shared_ptr<uintBig_t<16>>& chId) override;
        std::vector<TLaserChannelEntity> loadLaserChannels(uint8_t state = 0) override;

        Timestamp getLastUpdateTime() const override;
        void setSystemStateID(const Block::SystemState::ID& stateID) override;
        bool getSystemStateID(Block::SystemState::ID& stateID) const override;

        void Subscribe(IWalletDbObserver* observer) override;
        void Unsubscribe(IWalletDbObserver* observer) override;

        void changePassword(const SecString& password) override;

        bool setTxParameter(const TxID& txID, SubTxID subTxID, TxParameterID paramID,
            const ByteBuffer& blob, bool shouldNotifyAboutChanges) override;
        bool getTxParameter(const TxID& txID, SubTxID subTxID, TxParameterID paramID, ByteBuffer& blob) const override;
        std::vector<TxParameter> getAllTxParameters() const override;

        Block::SystemState::IHistory& get_History() override;
        void ShrinkHistory() override;

        bool lockCoins(const CoinIDList& list, uint64_t session) override;
        bool unlockCoins(uint64_t session) override;
        CoinIDList getLockedCoins(uint64_t session) const override;

        std::vector<OutgoingWalletMessage> getWalletMessages() const override;
        uint64_t saveWalletMessage(const OutgoingWalletMessage& message) override;
        void deleteWalletMessage(uint64_t id) override;

        std::vector<IncomingWalletMessage> getIncomingWalletMessages() const override;
        uint64_t saveIncomingWalletMessage(BbsChannel channel, const ByteBuffer& message) override;
        void deleteIncomingWalletMessage(uint64_t id) override;

        void saveAsset(const Asset::Full& info, Height refreshHeight) override;
        void markAssetOwned(const Asset::ID assetId) override;
        void dropAsset(const Asset::ID assetId) override;
        void dropAsset(const PeerID& ownerId) override;
        boost::optional<WalletAsset> findAsset(Asset::ID) override;
        boost::optional<WalletAsset> findAsset(const PeerID&) override;

        std::vector<Notification> getNotifications() const override;
        void saveNotification(const Notification&) override;
        
        std::vector<ExchangeRate> getExchangeRates() const override;
        void saveExchangeRate(const ExchangeRate&) override;

    private:
        static std::shared_ptr<WalletDB> initBase(const std::string& path, const SecString& password, bool separateDBForPrivateData);
        void storeOwnerKey();
        void FromMaster();
        void FromMaster(const ECC::uintBig&);
        void FromKeyKeeper();
        void UpdateLocalSlots();
        static void createTables(sqlite3* db, sqlite3* privateDb);
        void removeCoinImpl(const Coin::ID& cid);
        void notifyCoinsChanged(ChangeAction action, const std::vector<Coin>& items);
        void notifyTransactionChanged(ChangeAction action, const std::vector<TxDescription>& items);
        void notifySystemStateChanged(const Block::SystemState::ID& stateID);
        void notifyAddressChanged(ChangeAction action, const std::vector<WalletAddress>& items);
        void notifyShieldedCoinsChanged(ChangeAction action, const std::vector<ShieldedCoin>& items);

        bool updateCoinRaw(const Coin&);
        void insertCoinRaw(const Coin&);
        void insertNewCoin(Coin&);
        void saveCoinRaw(const Coin&);
        std::vector<Coin> getCoinsByRowIDs(const std::vector<int>& rowIDs) const;
        std::vector<Coin> getUpdatedCoins(const std::vector<Coin>& coins) const;

        bool updateShieldedCoinRaw(const ShieldedCoin& coin);
        void insertShieldedCoinRaw(const ShieldedCoin& coin);
        void saveShieldedCoinRaw(const ShieldedCoin& coin);

        // ////////////////////////////////////////
        // Cache for optimized access for database fields
        using ParameterCache = std::map<TxID, std::map<SubTxID, std::map<TxParameterID, boost::optional<ByteBuffer>>>>;

        void insertParameterToCache(const TxID& txID, SubTxID subTxID, TxParameterID paramID, const boost::optional<ByteBuffer>& blob) const;
        void deleteParametersFromCache(const TxID& txID);
        bool hasTransaction(const TxID& txID) const;
        void insertAddressToCache(const WalletID& id, const boost::optional<WalletAddress>& address) const;
        void deleteAddressFromCache(const WalletID& id);
        void flushDB();
        void rollbackDB();
        void onModified();
        void onFlushTimer();
        void onPrepareToModify();
        void MigrateCoins();
    private:
        friend struct sqlite::Statement;
        bool m_Initialized = false;
        sqlite3* _db;
        sqlite3* m_PrivateDB;
        Key::IKdf::Ptr m_pKdfMaster;
        Key::IPKdf::Ptr m_pKdfOwner;
        Key::IKdf::Ptr m_pKdfSbbs;
        IPrivateKeyKeeper2::Ptr m_pKeyKeeper;
        IPrivateKeyKeeper2::Slot::Type m_KeyKeeperSlots = 0; // cache it
        io::Timer::Ptr m_FlushTimer;
        bool m_IsFlushPending;
        std::unique_ptr<sqlite::Transaction> m_DbTransaction;
        std::vector<IWalletDbObserver*> m_subscribers;
        const std::set<TxParameterID> m_mandatoryTxParams;

        // Wallet has ablity to track blockchain state
        // This interface allows to check and update the blockchain state 
        // in the wallet database. Used in FlyClient implementation
        struct History :public Block::SystemState::IHistory {
            bool Enum(IWalker&, const Height* pBelow) override;
            bool get_At(Block::SystemState::Full&, Height) override;
            void AddStates(const Block::SystemState::Full*, size_t nCount) override;
            void DeleteFrom(Height) override;

            IMPLEMENT_GET_PARENT_OBJ(WalletDB, m_History)
        } m_History;
        
        mutable ParameterCache m_TxParametersCache;
        mutable std::map<WalletID, boost::optional<WalletAddress>> m_AddressesCache;

        struct LocalKeyKeeper;
        LocalKeyKeeper* m_pLocalKeyKeeper = nullptr;
    };

    namespace storage
    {
        template <typename Var>
        void setVar(IWalletDB& db, const char* name, const Var& var)
        {
            db.setVarRaw(name, &var, sizeof(var));
        }

        template <typename Var>
        bool getVar(const IWalletDB& db, const char* name, Var& var)
        {
            return db.getVarRaw(name, &var, sizeof(var));
        }

        template <typename T>
        bool getTxParameter(const IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, T& value)
        {
            ByteBuffer b;
            if (db.getTxParameter(txID, subTxID, paramID, b))
            {
                fromByteBuffer(b, value);
                return true;
            }
            return false;
        }

        bool getTxParameter(const IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, ECC::Point::Native& value);
        bool getTxParameter(const IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, ByteBuffer& value);
        bool getTxParameter(const IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, ECC::Scalar::Native& value);

        template <typename T>
        bool setTxParameter(IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, const T& value, bool shouldNotifyAboutChanges)
        {
            return db.setTxParameter(txID, subTxID, paramID, toByteBuffer(value), shouldNotifyAboutChanges);
        }

        bool setTxParameter(IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, const ECC::Point::Native& value, bool shouldNotifyAboutChanges);
        bool setTxParameter(IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, const ECC::Scalar::Native& value, bool shouldNotifyAboutChanges);
        bool setTxParameter(IWalletDB& db, const TxID& txID, SubTxID subTxID, TxParameterID paramID, const ByteBuffer& value, bool shouldNotifyAboutChanges);

        template <typename T>
        bool getTxParameter(const IWalletDB& db, const TxID& txID, TxParameterID paramID, T& value)
        {
            return getTxParameter(db, txID, kDefaultSubTxID, paramID, value);
        }

        bool getTxParameter(const IWalletDB& db, const TxID& txID, TxParameterID paramID, ECC::Point::Native& value);
        bool getTxParameter(const IWalletDB& db, const TxID& txID, TxParameterID paramID, ByteBuffer& value);
        bool getTxParameter(const IWalletDB& db, const TxID& txID, TxParameterID paramID, ECC::Scalar::Native& value);

        template <typename T>
        bool setTxParameter(IWalletDB& db, const TxID& txID, TxParameterID paramID, const T& value, bool shouldNotifyAboutChanges)
        {
            return setTxParameter(db, txID, kDefaultSubTxID, paramID, toByteBuffer(value), shouldNotifyAboutChanges);
        }

        bool setTxParameter(IWalletDB& db, const TxID& txID, TxParameterID paramID, const ECC::Point::Native& value, bool shouldNotifyAboutChanges);
        bool setTxParameter(IWalletDB& db, const TxID& txID, TxParameterID paramID, const ECC::Scalar::Native& value, bool shouldNotifyAboutChanges);
        bool setTxParameter(IWalletDB& db, const TxID& txID, TxParameterID paramID, const ByteBuffer& value, bool shouldNotifyAboutChanges);

        Height DeduceTxProofHeight(const IWalletDB& walletDB, const TxDescription &tx);
        Height DeduceTxDisplayHeight(const IWalletDB& walletDB, const TxDescription &tx);

        bool changeAddressExpiration(IWalletDB& walletDB, const WalletID& walletID, WalletAddress::ExpirationStatus status);

        Coin::Status GetCoinStatus(const IWalletDB&, const Coin&, Height hTop);
        void DeduceStatus(const IWalletDB&, Coin&, Height hTop);

        // Used in statistics
        struct Totals
        {
            struct AssetTotals {
                Asset::ID AssetId = Asset::s_InvalidID;
                AmountBig::Type Avail = 0U;
                AmountBig::Type Maturing = 0U;
                AmountBig::Type Incoming = 0U;
                AmountBig::Type ReceivingIncoming = 0U;
                AmountBig::Type ReceivingChange = 0U;
                AmountBig::Type Unavail = 0U;
                AmountBig::Type Outgoing = 0U;
                AmountBig::Type AvailCoinbase = 0U;
                AmountBig::Type Coinbase = 0U;
                AmountBig::Type AvailFee = 0U;
                AmountBig::Type Fee = 0U;
                AmountBig::Type Unspent = 0U;
                AmountBig::Type Shielded = 0U;
                Height MinCoinHeight = 0;
            };

            Totals();
            explicit Totals(IWalletDB& db);
            void Init(IWalletDB&);

            bool HasTotals(Asset::ID) const;
            AssetTotals GetTotals(Asset::ID) const;

            inline AssetTotals GetHdsTotals() const {
                return GetTotals(Zero);
            }

            mutable std::map<Asset::ID, AssetTotals> allTotals;
        };

        // Used for Payment Proof feature
        struct PaymentInfo
        {
            WalletID m_Sender;
            WalletID m_Receiver;

            Asset::ID m_AssetID;
            Amount m_Amount;
            Merkle::Hash m_KernelID;
            ECC::Signature m_Signature;

            PaymentInfo();

            template <typename Archive>
            static void serializeWid(Archive& ar, WalletID& wid)
            {
                BbsChannel ch;
                wid.m_Channel.Export(ch);

                ar
                    & ch
                    & wid.m_Pk;

                wid.m_Channel = ch;
            }

            template <typename Archive>
            void serialize(Archive& ar)
            {
                serializeWid(ar, m_Sender);
                serializeWid(ar, m_Receiver);
                ar
                    & m_Amount
                    & m_KernelID
                    & m_Signature;

                //
                // If you want to store something new just define new flag then
                // set it if you want to write and add read/write block.
                //
                // This allows to read old proofs in new clients and also to produce
                // proofs compatible with old clients (if possible, i.e. HDS transactions
                // do not need AssetID and we can keep an old format)
                //
                // Old client would be unable to read proofs if you would store anything below
                //
                enum ContentFlags
                {
                    HasAssetID = 1 << 0
                };

                uint32_t cflags = 0;

                if (ar.is_readable())
                {
                    try
                    {
                        ar & cflags;
                    }
                    catch (const std::runtime_error &)
                    {
                        // old payment proof without flags and additional data
                        // just ignore and continue
                    }
                }
                else
                {
                    if (m_AssetID != Asset::s_InvalidID)
                    {
                        cflags |= ContentFlags::HasAssetID;
                    }

                    if (cflags)
                    {
                        ar & cflags;
                    }
                }

                if (cflags & ContentFlags::HasAssetID)
                {
                    ar & m_AssetID;
                }
            }

            bool IsValid() const;
            
            std::string to_string() const;
            void Reset();
            static PaymentInfo FromByteBuffer(const ByteBuffer& data);
        };

        std::string ExportDataToJson(const IWalletDB& db);
        bool ImportDataFromJson(IWalletDB& db, const char* data, size_t size);

        std::string TxDetailsInfo(const IWalletDB::Ptr& db, const TxID& txID);
        ByteBuffer ExportPaymentProof(const IWalletDB& db, const TxID& txID);
        bool VerifyPaymentProof(const ByteBuffer& data);
        std::string ExportTxHistoryToCsv(const IWalletDB& db);

        void HookErrors();
        bool isMyAddress(
            const std::vector<WalletAddress>& myAddresses, const WalletID& wid);
    }  // namespace storage
}  // namespace hds::wallet
