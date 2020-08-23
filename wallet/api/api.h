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

#include <boost/optional.hpp>

#include "wallet/core/wallet.h"
#ifdef HDS_ATOMIC_SWAP_SUPPORT
#include "wallet/client/extensions/offers_board/swap_offer.h"
#endif  // HDS_ATOMIC_SWAP_SUPPORT
#include "nlohmann/json.hpp"

namespace hds::wallet
{
    using json = nlohmann::json;
    using JsonRpcId = json;

#define JSON_RPC_ERRORS(macro) \
    macro(-32600, InvalidJsonRpc,            "Invalid JSON-RPC.")                \
    macro(-32601, NotFoundJsonRpc,           "Procedure not found.")             \
    macro(-32602, InvalidParamsJsonRpc,      "Invalid parameters.")              \
    macro(-32603, InternalErrorJsonRpc,      "Internal JSON-RPC error.")         \
    macro(-32001, InvalidTxStatus,           "Invalid TX status.")               \
    macro(-32002, UnknownApiKey,             "Unknown API key.")                 \
    macro(-32003, InvalidAddress,            "Invalid address.")                 \
    macro(-32004, InvalidTxId,               "Invalid transaction ID.")          \
    macro(-32005, NotSupported,              "Feature is not supported")         \
    macro(-32006, InvalidPaymentProof,       "Invalid payment proof provided")   \
    macro(-32007, PaymentProofExportError,   "Cannot export payment proof")      \
    macro(-32008, SwapFailToParseToken,      "Invalid swap token.")              \
    macro(-32009, SwapFailToAcceptOwnOffer,  "Can't accept own swap offer.")     \
    macro(-32010, SwapNotEnoughtHdss,       "Not enought hdss.")               \
    macro(-32011, SwapFailToConnect,         "Doesn't have active connection.")  \
    macro(-32012, DatabaseError,             "Database error")                   \
    macro(-32013, DatabaseNotFound,          "Database not found")               \

    enum ApiError
    {
#define ERROR_ITEM(code, item, _) item = code,
        JSON_RPC_ERRORS(ERROR_ITEM)
#undef ERROR_ITEM
    };

#define API_WRITE_ACCESS true
#define API_READ_ACCESS false

#if defined(HDS_ATOMIC_SWAP_SUPPORT)
#define SWAP_OFFER_API_METHODS(macro) \
    macro(OffersList,       "swap_offers_list",     API_READ_ACCESS)    \
    macro(OffersBoard,      "swap_offers_board",    API_READ_ACCESS)    \
    macro(CreateOffer,      "swap_create_offer",    API_WRITE_ACCESS)   \
    macro(PublishOffer,     "swap_publish_offer",   API_WRITE_ACCESS)   \
    macro(AcceptOffer,      "swap_accept_offer",    API_WRITE_ACCESS)   \
    macro(OfferStatus,      "swap_offer_status",    API_READ_ACCESS)    \
    macro(DecodeToken,      "swap_decode_token",    API_READ_ACCESS)    \
    macro(GetBalance,       "swap_get_balance",     API_READ_ACCESS)
#else  // !HDS_ATOMIC_SWAP_SUPPORT
#define SWAP_OFFER_API_METHODS(macro)
#endif  // HDS_ATOMIC_SWAP_SUPPORT

#define WALLET_API_METHODS(macro) \
    macro(CreateAddress,      "create_address",       API_WRITE_ACCESS)   \
    macro(DeleteAddress,      "delete_address",       API_WRITE_ACCESS)   \
    macro(EditAddress,        "edit_address",         API_WRITE_ACCESS)   \
    macro(AddrList,           "addr_list",            API_READ_ACCESS)    \
    macro(ValidateAddress,    "validate_address",     API_READ_ACCESS)    \
    macro(Send,               "tx_send",              API_WRITE_ACCESS)   \
    macro(Issue,              "tx_asset_issue",       API_WRITE_ACCESS)   \
    macro(Consume,            "tx_asset_consume",     API_WRITE_ACCESS)   \
    macro(TxAssetInfo,        "tx_asset_info",        API_WRITE_ACCESS)   \
    macro(Status,             "tx_status",            API_READ_ACCESS)    \
    macro(Split,              "tx_split",             API_WRITE_ACCESS)   \
    macro(TxCancel,           "tx_cancel",            API_WRITE_ACCESS)   \
    macro(TxDelete,           "tx_delete",            API_WRITE_ACCESS)   \
    macro(GetUtxo,            "get_utxo",             API_READ_ACCESS)    \
    macro(Lock,               "lock",                 API_WRITE_ACCESS)   \
    macro(Unlock,             "unlock",               API_WRITE_ACCESS)   \
    macro(TxList,             "tx_list",              API_READ_ACCESS)    \
    macro(WalletStatus,       "wallet_status",        API_READ_ACCESS)    \
    macro(GenerateTxId,       "generate_tx_id",       API_READ_ACCESS)    \
    macro(ExportPaymentProof, "export_payment_proof", API_READ_ACCESS)    \
    macro(VerifyPaymentProof, "verify_payment_proof", API_READ_ACCESS)    \
    macro(GetAssetInfo,       "get_asset_info",       API_READ_ACCESS)    \
    SWAP_OFFER_API_METHODS(macro)

#if defined(HDS_ATOMIC_SWAP_SUPPORT)
#define WALLET_API_METHODS_ALIASES(macro) \
    macro("swap_cancel_offer", TxCancel, "tx_cancel", API_WRITE_ACCESS)
#else  // !HDS_ATOMIC_SWAP_SUPPORT
#define WALLET_API_METHODS_ALIASES(macro)
#endif  // HDS_ATOMIC_SWAP_SUPPORT

#if defined(HDS_ATOMIC_SWAP_SUPPORT)

    class FailToParseToken : public std::runtime_error
    {
    public:
        FailToParseToken() : std::runtime_error("Parse Parameters from 'token' failed.") {}
    };

    class FailToAcceptOwnOffer : public std::runtime_error
    {
    public:
        FailToAcceptOwnOffer() : std::runtime_error("You can't accept own offer.") {}
    };

    class NotEnoughtHdss : public std::runtime_error
    {
    public:
        NotEnoughtHdss() : std::runtime_error("Not enought hdss") {}
    };

    class FailToConnectSwap : public std::runtime_error
    {
    public:
        FailToConnectSwap(const std::string& coin) : std::runtime_error(std::string("There is not connection with ") + coin + " wallet") {}
    };

    struct OfferInput
    {
        Amount hdsAmount = 0;
        Amount swapAmount = 0;
        AtomicSwapCoin swapCoin = AtomicSwapCoin::Bitcoin;
        bool isHdsSide = true;
        Amount hdsFee = kMinFeeInGroth;
        Amount swapFeeRate = 0;
        Height offerLifetime = 15;
        std::string comment;
    };

    struct OffersList
    {
        struct
        {
            boost::optional<AtomicSwapCoin> swapCoin;
            boost::optional<SwapOfferStatus> status;
        } filter;
        struct Response
        {
            std::vector<WalletAddress> addrList;
            Height systemHeight;
            std::vector<SwapOffer> list;
        };
    };

    struct OffersBoard
    {
        struct
        {
            boost::optional<AtomicSwapCoin> swapCoin;
        } filter;
        struct Response
        {
            std::vector<WalletAddress> addrList;
            Height systemHeight;
            std::vector<SwapOffer> list;
        };
    };

    struct CreateOffer : public OfferInput
    {
        CreateOffer() = default;
        CreateOffer(const OfferInput& oi) : OfferInput(oi) {}
        struct Response
        {
            std::vector<WalletAddress> addrList;
            Height systemHeight;
            std::string token;
            TxID txId;
        };
    };

    struct PublishOffer
    {
        std::string token;
        struct Response
        {
            std::vector<WalletAddress> addrList;
            Height systemHeight;
            SwapOffer offer;    
        };
    };

    struct AcceptOffer
    {
        std::string token;
        Amount hdsFee = kMinFeeInGroth;
        Amount swapFeeRate = 0;
        std::string comment;
        struct Response
        {
            std::vector<WalletAddress> addrList;
            Height systemHeight;
            SwapOffer offer;
        };
    };

    struct OfferStatus
    {
        TxID txId;
        struct Response
        {
            Height systemHeight;
            SwapOffer offer;
        };
    };

    struct DecodeToken
    {
        std::string token;
        struct Response
        {
            SwapOffer offer;
            bool isMyOffer;
            bool isPublic;
        };
    };

    struct GetBalance
    {
        AtomicSwapCoin coin;
        struct Response
        {
            Amount available;
        };
    };
#endif  // HDS_ATOMIC_SWAP_SUPPORT

    struct AddressData
    {
        boost::optional<std::string> comment;

        enum Expiration { Expired, Never, OneDay };
        boost::optional<Expiration> expiration;
    };

    struct CreateAddress : AddressData
    {
        struct Response
        {
            WalletID address;
        };
    };

    struct DeleteAddress
    {
        WalletID address;

        struct Response {};
    };

    struct EditAddress : AddressData
    {
        WalletID address;

        struct Response {};
    };

    struct AddrList
    {
        bool own;

        struct Response
        {
            std::vector<WalletAddress> list;
        };
    };

    struct ValidateAddress
    {
        WalletID address = Zero;

        struct Response
        {
            bool isValid;
            bool isMine;
        };
    };

    struct Send
    {
        Amount value = 0;
        Amount fee = kMinFeeInGroth;
        boost::optional<CoinIDList> coins;
        boost::optional<WalletID> from;
        boost::optional<uint64_t> session;
        boost::optional<TxID> txId;
        boost::optional<Asset::ID> assetId;
        WalletID address;
        std::string comment;
        TxParameters txParameters;

        struct Response
        {
            TxID txId;
        };
    };

    struct Issue
    {
        Amount value = 0;
        Amount fee = kMinFeeInGroth;
        boost::optional<std::string> assetMeta;
        boost::optional<Asset::ID> assetId;
        boost::optional<CoinIDList> coins;
        boost::optional<uint64_t> session;
        boost::optional<TxID> txId;

        struct Response
        {
            TxID txId;
        };
    };

    struct Consume
    {
        Amount value = 0;
        Amount fee = kMinFeeInGroth;
        boost::optional<std::string> assetMeta;
        boost::optional<Asset::ID> assetId;
        boost::optional<CoinIDList> coins;
        boost::optional<uint64_t> session;
        boost::optional<TxID> txId;

        struct Response
        {
            TxID txId;
        };
    };

    struct TxAssetInfo
    {
        boost::optional<std::string> assetMeta;
        boost::optional<Asset::ID> assetId;
        boost::optional<TxID> txId;

        struct Response
        {
            TxID txId;
        };
    };

    struct Status
    {
        TxID txId;

        struct Response
        {
            TxDescription tx;
            Height txHeight;
            Height systemHeight;
            uint64_t confirmations;
        };
    };

    struct Split
    {
        Amount fee = kMinFeeInGroth;
        AmountList coins;
        boost::optional<TxID> txId;
        boost::optional<Asset::ID> assetId;

        struct Response
        {
            TxID txId;
        };
    };

    struct TxCancel
    {
        TxID txId;

        struct Response
        {
            bool result;
        };
    };


    struct TxDelete
    {
        TxID txId;

        struct Response
        {
            bool result;
        };
    };

    struct GetUtxo
    {
        int count = 0;
        int skip = 0;
        bool withAssets = false;

        struct
        {
            boost::optional<Asset::ID> assetId;
        } filter;

        struct Response
        {
            std::vector<Coin> utxos;
        };
    };

    struct Lock
    {
        CoinIDList coins;
        uint64_t session;

        struct Response
        {
            bool result;
        };
    };

    struct Unlock
    {
        uint64_t session;

        struct Response
        {
            bool result;
        };
    };

    struct TxList
    {
        bool withAssets = false;

        struct
        {
            boost::optional<TxStatus>  status;
            boost::optional<Height>    height;
            boost::optional<Asset::ID> assetId;
        } filter;

        int count = 0;
        int skip = 0;

        struct Response
        {
            std::vector<Status::Response> resultList;
        };
    };

    struct WalletStatus
    {
        bool withAssets = false;
        struct Response
        {
            hds::Height currentHeight = 0;
            Merkle::Hash currentStateHash;
            Merkle::Hash prevStateHash;
            double difficulty = 0;
            Amount available = 0;
            Amount receiving = 0;
            Amount sending = 0;
            Amount maturing = 0;
            boost::optional<storage::Totals> totals;
        };
    };

    struct GenerateTxId
    {
        struct Response
        {
            TxID txId;
        };
    };

    struct ExportPaymentProof 
    {
        TxID txId;

        struct Response
        {
            ByteBuffer paymentProof;
        };
    };

    struct VerifyPaymentProof
    {
        ByteBuffer paymentProof;
        struct Response
        {
            storage::PaymentInfo paymentInfo;
        };
    };

    struct GetAssetInfo
    {
        boost::optional<std::string> assetMeta;
        boost::optional<Asset::ID> assetId;
        struct Response
        {
            WalletAsset AssetInfo;
        };
    };

    class IApiHandler
    {
    public:
        virtual void onInvalidJsonRpc(const json& msg) = 0;
    };

    class IWalletApiHandler : public IApiHandler
    {
    public:
#define MESSAGE_FUNC(api, name, _) \
        virtual void onMessage(const JsonRpcId& id, const api& data) = 0;

        WALLET_API_METHODS(MESSAGE_FUNC)

#undef MESSAGE_FUNC
    };

    class Api
    {
    public:

        using Ptr = std::shared_ptr<Api>;

        struct jsonrpc_exception
        {
            ApiError code;
            std::string data;
            JsonRpcId id;
        };

        static inline const char JsonRpcHrd[] = "jsonrpc";
        static inline const char JsonRpcVerHrd[] = "2.0";

        // user api key and read/write access
        using ACL = boost::optional<std::map<std::string, bool>>;

        Api(IApiHandler& handler, ACL acl = boost::none);

        bool parse(const char* data, size_t size);

        static const char* getErrorMessage(ApiError code);
        static bool existsJsonParam(const json& params, const std::string& name);
        static void checkJsonParam(const json& params, const std::string& name, const JsonRpcId& id);

    protected:
        IApiHandler& _handler;

        struct FuncInfo
        {
            std::function<void(const JsonRpcId & id, const json & msg)> func;
            bool writeAccess;
        };

        std::unordered_map<std::string, FuncInfo> _methods;
        ACL _acl;
    };

    class WalletApi : public Api
    {
    public:
        WalletApi(IWalletApiHandler& handler, bool withAssets, ACL acl = boost::none);

#define RESPONSE_FUNC(api, name, _) \
        void getResponse(const JsonRpcId& id, const api::Response& data, json& msg);

        WALLET_API_METHODS(RESPONSE_FUNC)

#undef RESPONSE_FUNC

    private:
        IWalletApiHandler& getHandler() const;

#define MESSAGE_FUNC(api, name, _) \
        void on##api##Message(const JsonRpcId& id, const json& msg);

        WALLET_API_METHODS(MESSAGE_FUNC)

#undef MESSAGE_FUNC

        template<typename T>
        void onIssueConsumeMessage(bool issue, const JsonRpcId& id, const json& params);
        void checkCAEnabled(const JsonRpcId& id);

    private:
        bool m_withAssets = false;
    };
}  // namespace hds::wallet
