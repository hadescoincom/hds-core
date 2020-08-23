// Copyright 2020 The Hds Team;
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


#include "common.h"
#include "utility/logger.h"
#include "core/ecc_native.h"
#include "core/serialization_adapters.h"
#include "base58.h"
#include "utility/string_helpers.h"
#include "strings_resources.h"
#include "core/shielded.h"
#include "3rdparty/nlohmann/json.hpp"
#include "wallet_db.h"

#include <algorithm>
#include <iomanip>
#include <regex>
#include <boost/algorithm/string.hpp>

#include <boost/serialization/nvp.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

#ifndef EMSCRIPTEN
#include <boost/multiprecision/cpp_int.hpp>
using boost::multiprecision::cpp_int;
#endif

using namespace std;
using namespace ECC;
using namespace hds;
using boost::multiprecision::cpp_dec_float_50;
namespace
{
    string SkipLeadingZeroes(const char* szPtr)
    {
        while (*szPtr == '0')
            szPtr++;

        if (!*szPtr)
            szPtr--; // leave at least 1 symbol

        return szPtr;
    }

    // skips leading zeroes
    template<typename T>
    string EncodeToHex(const T& v)
    {
        char szBuf[sizeof(v) * 2 + 1];
        hds::to_hex(szBuf, &v, sizeof(v));
        return SkipLeadingZeroes(szBuf);
    }

    string EncodeToHex(const ByteBuffer& v)
    {
        if (v.empty())
        {
            return {};
        }
        char* szBuf = (char*)alloca(2 * v.size() + 1);
        hds::to_hex(szBuf, &v[0], v.size());
        return SkipLeadingZeroes(szBuf);
    }
}

namespace std
{
    string to_string(const hds::wallet::WalletID& id)
    {
        static_assert(sizeof(id) == sizeof(id.m_Channel) + sizeof(id.m_Pk), "");
        return EncodeToHex(id);
    }

    string to_string(const Merkle::Hash& hash)
    {
        char sz[Merkle::Hash::nTxtLen + 1];
        hash.Print(sz);
        return string(sz);
    }

#ifndef EMSCRIPTEN
    string to_string(const hds::wallet::PrintableAmount& amount)
    {
        cpp_int intval;
        import_bits(intval, amount.m_value.m_pData, amount.m_value.m_pData + decltype(amount.m_value)::nBytes);

        if (amount.m_showPoint)
        {
            const auto maxGroths = std::lround(std::log10(Rules::Coin));
            cpp_dec_float_50 floatval(intval);

            stringstream ss;
            ss << fixed << setprecision(maxGroths) << floatval / Rules::Coin;
            auto str   = ss.str();
            const auto point = std::use_facet< std::numpunct<char>>(ss.getloc()).decimal_point();

            boost::algorithm::trim_right_if(str, boost::is_any_of("0"));
            boost::algorithm::trim_right_if(str, [point](const char ch) {return ch == point;});

            return str;
        }
        else
        {
            stringstream ss;
            cpp_int coin  = intval / Rules::Coin;
            cpp_int groth = intval - coin * Rules::Coin;

            if (intval >= Rules::Coin)
            {
                ss << coin << " " << (amount.m_coinName.empty() ? "hdss" : amount.m_coinName);
            }

            if (groth > 0 || intval == 0)
            {
                ss << (intval >= Rules::Coin ? (" ") : "")
                   << groth << " " << (amount.m_grothName.empty() ? "groth" : amount.m_grothName);
            }

            return ss.str();
        }
    }
#endif  // EMSCRIPTEN

    string to_string(const hds::wallet::TxParameters& value)
    {
        hds::wallet::TxToken token(value);
        Serializer s;
        s & token;
        ByteBuffer buffer;
        s.swap_buf(buffer);
        return hds::wallet::EncodeToBase58(buffer);
    }

    string to_string(const hds::Version& v)
    {
        return v.to_string();
    }

    string to_string(const hds::wallet::TxID& id)
    {
        return to_hex(id.data(), id.size());
    }

    string to_string(const hds::PeerID& id)
    {
        return EncodeToHex(id);
    }

#ifndef EMSCRIPTEN
    string to_string(const hds::AmountBig::Type& amount)
    {
        cpp_int intval;
        import_bits(intval, amount.m_pData, amount.m_pData + hds::AmountBig::Type::nBytes);

        stringstream ss;
        ss << intval;

        return ss.str();
    }
#endif  // EMSCRIPTEN

}  // namespace std

namespace hds
{
    std::ostream& operator<<(std::ostream& os, const wallet::TxID& uuid)
    {
        stringstream ss;
        ss << "[" << std::to_string(uuid) << "]";
        os << ss.str();
        return os;
    }

    std::ostream& operator<<(std::ostream& os, const wallet::PrintableAmount& amount)
    {
        os << std::to_string(amount);
        
        return os;
    }
}  // namespace hds

namespace hds::wallet
{
    const char kTimeStampFormat3x3[] = "%Y.%m.%d %H:%M:%S";
    const char kTimeStampFormatCsv[] = "%d %b %Y | %H:%M";

    int WalletID::cmp(const WalletID& x) const
    {
        int n = m_Channel.cmp(x.m_Channel);
        if (n)
            return n;
        return m_Pk.cmp(x.m_Pk);
    }

    bool WalletID::FromBuf(const ByteBuffer& x)
    {
        if (x.size() > sizeof(*this))
            return false;

        typedef uintBig_t<sizeof(*this)> BigSelf;
        static_assert(sizeof(BigSelf) == sizeof(*this), "");

        *reinterpret_cast<BigSelf*>(this) = Blob(x);
        return true;
    }

    bool WalletID::FromHex(const std::string& s)
    {
        bool bValid = true;
        ByteBuffer bb = from_hex(s, &bValid);

        return bValid && FromBuf(bb);
    }

    bool WalletID::IsValid() const
    {
        Point::Native p;
        return m_Pk.ExportNnz(p);
    }

    boost::optional<PeerID> FromHex(const std::string& s)
    {
        boost::optional<PeerID> res;
        bool isValid = false;
        auto buf = from_hex(s, &isValid);
        if (!isValid)
        {
            return res;
        }
        res.emplace();
        *res = Blob(buf);
        return res;
    }

    bool fromByteBuffer(const ByteBuffer& b, ByteBuffer& value)
    {
        value = b;
        return true;
    }

    ByteBuffer toByteBuffer(const ECC::Point::Native& value)
    {
        ECC::Point pt;
        if (value.Export(pt))
        {
            return toByteBuffer(pt);
        }
        return ByteBuffer();
    }

    ByteBuffer toByteBuffer(const ECC::Scalar::Native& value)
    {
        ECC::Scalar s;
        value.Export(s);
        return toByteBuffer(s);
    }

    ByteBuffer toByteBuffer(const ByteBuffer& value)
    {
        return value;
    }

    ErrorType getWalletError(proto::NodeProcessingException::Type exceptionType)
    {
        switch (exceptionType)
        {
        case proto::NodeProcessingException::Type::Incompatible:
            return ErrorType::NodeProtocolIncompatible;
        case proto::NodeProcessingException::Type::TimeOutOfSync:
            return ErrorType::TimeOutOfSync;
        default:
            return ErrorType::NodeProtocolBase;
        }
    }

    ErrorType getWalletError(io::ErrorCode errorCode)
    {
        switch (errorCode)
        {
        case io::ErrorCode::EC_ETIMEDOUT:
            return ErrorType::ConnectionTimedOut;
        case io::ErrorCode::EC_ECONNREFUSED:
            return ErrorType::ConnectionRefused;
        case io::ErrorCode::EC_EHOSTUNREACH:
            return ErrorType::ConnectionHostUnreach;
        case io::ErrorCode::EC_EADDRINUSE:
            return ErrorType::ConnectionAddrInUse;
        case io::ErrorCode::EC_HOST_RESOLVED_ERROR:
            return ErrorType::HostResolvedError;
        default:
            return ErrorType::ConnectionBase;
        }
    }

    bool ConfirmationBase::IsValid(const PeerID& pid) const
    {
        Point::Native pk;
        if (!pid.ExportNnz(pk))
            return false;

        Hash::Value hv;
        get_Hash(hv);

        return m_Signature.IsValid(hv, pk);
    }

    void ConfirmationBase::Sign(const Scalar::Native& sk)
    {
        Hash::Value hv;
        get_Hash(hv);

        m_Signature.Sign(hv, sk);
    }

    void PaymentConfirmation::get_Hash(Hash::Value& hv) const
    {
        Hash::Processor hp;
        hp
            << "PaymentConfirmation"
            << m_KernelID
            << m_Sender
            << m_Value;

        if (m_AssetID != Asset::s_InvalidID)
        {
            hp
                << "asset"
                << m_AssetID;
        }

        hp >> hv;
    }

    void SwapOfferConfirmation::get_Hash(Hash::Value& hv) const
    {
        hds::Blob data(m_offerData);
        Hash::Processor()
            << "SwapOfferSignature"
            << data
            >> hv;
    }

    void SignatureHandler::get_Hash(Hash::Value& hv) const
    {
        hds::Blob data(m_data);
        Hash::Processor()
            << "Undersign"
            << data
            >> hv;
    }

    TxParameters::TxParameters(const boost::optional<TxID>& txID)
        : m_ID(txID)
    {

    }

    bool TxParameters::operator==(const TxParameters& other)
    {
        return m_ID == other.m_ID &&
            m_Parameters == other.m_Parameters;
    }

    bool TxParameters::operator!=(const TxParameters& other)
    {
        return !(*this == other);
    }

    const boost::optional<TxID>& TxParameters::GetTxID() const
    {
        return m_ID;
    }

    boost::optional<ByteBuffer> TxParameters::GetParameter(TxParameterID parameterID, SubTxID subTxID) const
    {
        auto subTxIt = m_Parameters.find(subTxID);
        if (subTxIt == m_Parameters.end())
        {
            return {};
        }
        auto it = subTxIt->second.find(parameterID);
        if (it == subTxIt->second.end())
        {
            return {};
        }
        return boost::optional<ByteBuffer>(it->second);
    }

    TxParameters& TxParameters::SetParameter(TxParameterID parameterID, const ByteBuffer& parameter, SubTxID subTxID)
    {
        m_Parameters[subTxID][parameterID] = parameter;
        return *this;
    }

    PackedTxParameters TxParameters::Pack() const
    {
        PackedTxParameters parameters;
        for (const auto& subTx : m_Parameters)
        {
            if (subTx.first > kDefaultSubTxID)
            {
                parameters.emplace_back(TxParameterID::SubTxIndex, toByteBuffer(subTx.first));
            }
            for (const auto& p : subTx.second)
            {
                parameters.emplace_back(p.first, p.second);
            }
        }
        return parameters;
    }

    TxToken::TxToken(const TxParameters& parameters)
        : m_Flags(TxToken::TokenFlag)
        , m_TxID(parameters.GetTxID())
        , m_Parameters(parameters.Pack())
    {

    }

    TxParameters TxToken::UnpackParameters() const
    {
        TxParameters result(m_TxID);

        SubTxID subTxID = kDefaultSubTxID;
        Deserializer d;
        for (const auto& p : m_Parameters)
        {
            if (p.first == TxParameterID::SubTxIndex)
            {
                // change subTxID
                d.reset(p.second.data(), p.second.size());
                d & subTxID;
                continue;
            }

            result.SetParameter(p.first, p.second, subTxID);
        }
        return result;
    }

    boost::optional<TxParameters> ParseParameters(const string& text)
    {
        bool isValid = true;
        ByteBuffer buffer = from_hex(text, &isValid);
        if (!isValid)
        {
            buffer = DecodeBase58(text);
            if (buffer.empty())
            {
                return {};
            }
        }

        if (buffer.size() < 2)
        {
            return {};
        }

        if (buffer.size() > 33 && buffer[0] & TxToken::TokenFlag) // token
        {
            try
            {
                TxToken token;
                // simply deserialize for now
                Deserializer d;
                d.reset(&buffer[0], buffer.size());
                d & token;

                return boost::make_optional<TxParameters>(token.UnpackParameters());
            }
            catch (...)
            {
                // failed to deserialize
            }
        }
        else // plain WalletID
        {
            WalletID walletID;
            if (walletID.FromBuf(buffer))
            {
                auto result = boost::make_optional<TxParameters>({});
                result->SetParameter(TxParameterID::PeerID, walletID);
                return result;
            }
        }
        return {};
    }

    bool LoadReceiverParams(const TxParameters& receiverParams, TxParameters& params)
    {
        bool res = false;
        const TxParameters& p = receiverParams;
        if (auto peerID = p.GetParameter<WalletID>(TxParameterID::PeerID); peerID)
        {
            params.SetParameter(TxParameterID::PeerID, *peerID);
            res = true;
        }
        if (auto peerID = p.GetParameter<PeerID>(TxParameterID::PeerWalletIdentity); peerID)
        {
            params.SetParameter(TxParameterID::PeerWalletIdentity, *peerID);

            if (auto vouchers = p.GetParameter<ShieldedVoucherList>(TxParameterID::ShieldedVoucherList); vouchers)
            {
                if (!IsValidVoucherList(*vouchers, *peerID))
                {
                    LOG_ERROR() << "Voucher signature verification failed. Unauthorized voucher was provider.";
                    return false;
                }
                params.SetParameter(TxParameterID::ShieldedVoucherList, *vouchers);
            }
            res &= true;
        }

#ifdef HDS_LIB_VERSION
        if (auto libVersion = receiverParams.GetParameter(hds::wallet::TxParameterID::LibraryVersion); libVersion)
        {
            std::string libVersionStr;
            hds::wallet::fromByteBuffer(*libVersion, libVersionStr);
            std::string myLibVersionStr = HDS_LIB_VERSION;

            std::regex libVersionRegex("\\d{1,}\\.\\d{1,}\\.\\d{4,}");
            if (std::regex_match(libVersionStr, libVersionRegex) &&
                std::lexicographical_compare(
                    myLibVersionStr.begin(),
                    myLibVersionStr.end(),
                    libVersionStr.begin(),
                    libVersionStr.end(),
                    std::less<char>{}))
            {
                LOG_WARNING() <<
                    "This token generated by newer Hds library version(" << libVersionStr << ")\n" <<
                    "Your version is: " << myLibVersionStr << " Please, check for updates.";
            }
        }
#endif  // HDS_LIB_VERSION

        return res;
    }

    bool IsValidTimeStamp(Timestamp currentBlockTime_s, Timestamp tolerance_s)
    {
        Timestamp currentTime_s = getTimestamp();

        if (currentTime_s > currentBlockTime_s + tolerance_s)
        {
            LOG_INFO() << "It seems that last known blockchain tip is not up to date";
            return false;
        }
        return true;
    }

    TxStatusInterpreter::TxStatusInterpreter(const TxParameters& txParams) : m_txParams(txParams)
    {
        auto value = txParams.GetParameter(TxParameterID::Status);
        if (value) fromByteBuffer(*value, m_status);

        value = txParams.GetParameter(TxParameterID::IsSender);
        if (value) fromByteBuffer(*value, m_sender);

        value = txParams.GetParameter(TxParameterID::IsSelfTx);
        if (value) fromByteBuffer(*value, m_selfTx);

        value = txParams.GetParameter(TxParameterID::FailureReason);
        if (value) fromByteBuffer(*value, m_failureReason);
    }

    std::string TxStatusInterpreter::getStatus() const
    {
        switch (m_status)
        {
            case TxStatus::Pending: return "pending";
            case TxStatus::InProgress:
                return m_selfTx  ? "self sending" : (m_sender ? "waiting for receiver" : "waiting for sender");
            case TxStatus::Registering: 
                return m_selfTx ? "self sending" : (m_sender == false ? "receiving" : "sending");
            case TxStatus::Failed: 
                return TxFailureReason::TransactionExpired == m_failureReason ? "expired" : "failed";
            case TxStatus::Canceled: return "cancelled";
            case TxStatus::Completed:
                return m_selfTx ? "completed" : (m_sender ? "sent" : "received");
            default:
                BOOST_ASSERT_MSG(false, kErrorUnknownTxStatus);
                return "unknown";
        }
    }

    std::string SimpleTxStatusInterpreter::getStatus() const
    {
        const auto& status = TxStatusInterpreter::getStatus();
        if (status == "receiving" || status == "sending")
            return "in progress";
        else if (status == "completed")
            return "sent to own address";
        else if (status == "self sending")
            return "sending to own address";
        return status;
    }

    AssetTxStatusInterpreter::AssetTxStatusInterpreter(const TxParameters& txParams) : TxStatusInterpreter(txParams)
    {
        boost::optional<ByteBuffer> value = txParams.GetParameter(TxParameterID::TransactionType);
        if (value) fromByteBuffer(*value, m_txType);
    }

    std::string AssetTxStatusInterpreter::getStatus() const
    {
        if (m_status == TxStatus::InProgress && m_txType == TxType::AssetInfo) return "getting info";
        if (m_status == TxStatus::Completed)
        {
            switch (m_txType)
            {
                case TxType::AssetIssue: return "asset issued";
                case TxType::AssetConsume: return "asset consumed";
                case TxType::AssetReg: return "asset registered";
                case TxType::AssetUnreg: return "asset unregistered";
                case TxType::AssetInfo: return "asset confirmed";
                default: break;
            }
        }

        return TxStatusInterpreter::getStatus();
    }

    TxDescription::TxDescription(const TxParameters p)
        : TxParameters(p)
    {
        fillFromTxParameters(*this);
    }

    void TxDescription::fillFromTxParameters(const TxParameters& parameters)
    {
        boost::optional<TxID> txId = parameters.GetTxID();
        if (txId)
        {
            m_txId = *txId;
        }

        for (const TxParameterID p : m_initialParameters)
        {
            boost::optional<ByteBuffer> value = parameters.GetParameter(p);
            if (value)
            {
                switch (p)
                {
                    case TxParameterID::TransactionType:
                        fromByteBuffer(*value, m_txType);
                        break;
                    case TxParameterID::Amount:
                        fromByteBuffer(*value, m_amount);
                        break;
                    case TxParameterID::Fee:
                        fromByteBuffer(*value, m_fee);
                        break;
                    case TxParameterID::MinHeight:
                        fromByteBuffer(*value, m_minHeight);
                        break;
                    case TxParameterID::PeerID:
                        fromByteBuffer(*value, m_peerId);
                        break;
                    case TxParameterID::MyID:
                        fromByteBuffer(*value, m_myId);
                        break;
                    case TxParameterID::CreateTime:
                        fromByteBuffer(*value, m_createTime);
                        break;
                    case TxParameterID::IsSender:
                        fromByteBuffer(*value, m_sender);
                        break;
                    case TxParameterID::Message:
                        fromByteBuffer(*value, m_message);
                        break;
                    case TxParameterID::ChangeHds:
                        fromByteBuffer(*value, m_changeHds);
                        break;
                    case TxParameterID::ChangeAsset:
                        fromByteBuffer(*value, m_changeAsset);
                        break;
                    case TxParameterID::ModifyTime:
                        fromByteBuffer(*value, m_modifyTime);
                        break;
                    case TxParameterID::Status:
                        fromByteBuffer(*value, m_status);
                        break;
                    case TxParameterID::KernelID:
                        fromByteBuffer(*value, m_kernelID);
                        break;
                    case TxParameterID::FailureReason:
                        fromByteBuffer(*value, m_failureReason);
                        break;
                    case TxParameterID::IsSelfTx:
                        fromByteBuffer(*value, m_selfTx);
                        break;
                    case TxParameterID::AssetID:
                        fromByteBuffer(*value, m_assetId);
                        break;
                    case TxParameterID::AssetMetadata:
                        fromByteBuffer(*value, m_assetMeta);
                        break;
                    default:
                        break; // suppress warning
                }
            }
        }
    }

    bool TxDescription::canResume() const
    {
        return m_status == TxStatus::Pending
            || m_status == TxStatus::InProgress
            || m_status == TxStatus::Registering;
    }

    bool TxDescription::canCancel() const
    {
        return m_status == TxStatus::InProgress
            || m_status == TxStatus::Pending;
    }

    bool TxDescription::canDelete() const
    {
        return m_status == TxStatus::Failed
            || m_status == TxStatus::Completed
            || m_status == TxStatus::Canceled;
    }

    std::string TxDescription::getTxTypeString() const
    {
        switch(m_txType)
        {
        case TxType::Simple: return "simple";
        case TxType::AssetReg: return "asset register";
        case TxType::AssetUnreg: return "asset unregister";
        case TxType::AssetIssue: return "asset issue";
        case TxType::AssetConsume: return "asset consume";
        case TxType::AtomicSwap: return "atomic swap";
        case TxType::AssetInfo: return "asset info";
        default:
            BOOST_ASSERT_MSG(false, kErrorUnknownTxType);
            return "unknown";
        }
    }

    /// Return empty string if second currency exchange rate is not presented
    std::string TxDescription::getAmountInSecondCurrency(ExchangeRate::Currency secondCurrency) const
    {
        auto exchangeRatesOptional = GetParameter<std::vector<ExchangeRate>>(TxParameterID::ExchangeRates);
        if (exchangeRatesOptional)
        {
            std::vector<ExchangeRate>& rates = *exchangeRatesOptional;
            for (const auto r : rates)
            {
                if (r.m_currency == ExchangeRate::Currency::Hds &&
                    r.m_unit == secondCurrency &&
                    r.m_rate != 0)
                {
                    cpp_dec_float_50 dec_first(m_amount);
                    dec_first /= Rules::Coin;
                    cpp_dec_float_50 dec_second(r.m_rate);
                    dec_second /= Rules::Coin;
                    cpp_dec_float_50 product = dec_first * dec_second;

                    std::ostringstream oss;
                    uint32_t precision = secondCurrency == ExchangeRate::Currency::Usd
                                            ? 2
                                            : std::lround(std::log10(Rules::Coin));
                    oss.precision(precision);
                    oss << std::fixed << product;

                    return oss.str();
                }
            }
        }
        return "";
    }

    std::string TxDescription::getToken() const
    {
        auto token = GetParameter<std::string>(TxParameterID::OriginalToken);
        if (token)
        {
            return *token;
        }
        return {};
    }

    std::string TxDescription::getSenderIdentity() const
    {
        return getIdentity(m_sender);
    }

    std::string TxDescription::getReceiverIdentity() const
    {
        return getIdentity(!m_sender);
    }

    std::string TxDescription::getIdentity(bool isSender) const
    {
        auto v = isSender ? GetParameter<PeerID>(TxParameterID::MyWalletIdentity)
            : GetParameter<PeerID>(TxParameterID::PeerWalletIdentity);
        if (v)
        {
            return std::to_string(*v);
        }
        return {};
    }

    uint64_t get_RandomID()
    {
        uintBigFor<uint64_t>::Type val;
        ECC::GenRandom(val);

        uint64_t ret;
        val.Export(ret);
        return ret;
    }

    std::string GetSendToken(const std::string& sbbsAddress, const std::string& identityStr, Amount amount)
    {
        WalletID walletID;
        if (!walletID.FromHex(sbbsAddress))
        {
            return "";
        }
        auto identity = FromHex(identityStr);
        if (!identity)
        {
            return "";
        }

        TxParameters parameters;
        if (amount > 0)
        {
            parameters.SetParameter(TxParameterID::Amount, amount);
        }

        parameters.SetParameter(TxParameterID::PeerID, walletID);
        parameters.SetParameter(TxParameterID::TransactionType, hds::wallet::TxType::Simple);
        parameters.SetParameter(TxParameterID::PeerWalletIdentity, *identity);

        return std::to_string(parameters);
    }

    ShieldedVoucherList GenerateVoucherList(ECC::Key::IKdf::Ptr pKdf, uint64_t ownID, size_t count)
    {
        ShieldedVoucherList res;
        if (!pKdf || count == 0)
            return res;

        const size_t MAX_VOUCHERS = 20;

        if (MAX_VOUCHERS < count)
        {
            LOG_WARNING() << "You are trying to generate more than " << MAX_VOUCHERS << ". The list of vouchers will be truncated.";
        }

        res.reserve(std::min(count, MAX_VOUCHERS));

        ECC::Scalar::Native sk;
        pKdf->DeriveKey(sk, Key::ID(ownID, Key::Type::WalletID));
        PeerID pid;
        pid.FromSk(sk);

        ECC::Hash::Value hv;
        ShieldedTxo::Viewer viewer;
        viewer.FromOwner(*pKdf, 0);
        for (size_t i = 0; i < res.capacity(); ++i)
        {
            if (res.empty())
                ECC::GenRandom(hv);
            else
                ECC::Hash::Processor() << hv >> hv;

            ShieldedTxo::Voucher& voucher = res.emplace_back();

            ShieldedTxo::Data::TicketParams tp;
            tp.Generate(voucher.m_Ticket, viewer, hv);

            voucher.m_SharedSecret = tp.m_SharedSecret;

            ECC::Hash::Value hvMsg;
            voucher.get_Hash(hvMsg);
            voucher.m_Signature.Sign(hvMsg, sk);
        }
        return res;
    }

    bool IsValidVoucherList(const ShieldedVoucherList& vouchers, const PeerID& identity)
    {
        if (vouchers.empty())
            return false;

        ECC::Point::Native pk;
        if (!identity.ExportNnz(pk))
            return false;

        for (const auto& voucher : vouchers)
        {
            if (!voucher.IsValid(pk))
            {
                return false;
            }
        }
        return true;
    }

    using nlohmann::json;

#define HDS_IGNORED_JSON_TYPES2(MACRO) \
        MACRO(ECC::RangeProof::Confidential::Part2) \
        MACRO(ECC::RangeProof::Confidential::Part3)

#define MACRO(type) \
    static bool fromByteBuffer(const ByteBuffer&, type&) \
    { \
        return false; \
    } \

    HDS_IGNORED_JSON_TYPES2(MACRO)
#undef MACRO

#define MACRO(type) \
    static ByteBuffer toByteBuffer(const type&) \
    { \
        return {}; \
    } \

    HDS_IGNORED_JSON_TYPES2(MACRO)
#undef MACRO

    namespace
    {
        using Names = std::array<string, uint8_t(128)>;
        Names GetParameterNames()
        {
            Names names;
#define MACRO(name, index, type) names[index] = #name;
            HDS_TX_PUBLIC_PARAMETERS_MAP(MACRO)
#undef MACRO
            return names;
        }

        using NameIDs = std::map<string, TxParameterID>;
        NameIDs GetParameterNameIDs()
        {
            NameIDs names;
#define MACRO(name, index, type) names[#name] = TxParameterID(index);
            HDS_TX_PUBLIC_PARAMETERS_MAP(MACRO)
#undef MACRO
            return names;
        }

        template<typename T>
        string ToJsonValue(const T& v)
        {
            return std::to_string(v);
        }

        json ToJsonValue(TxType v)
        {
            return uint8_t(v);
        }

        json ToJsonValue(bool v)
        {
            return v;
        }

        string ToJsonValue(const ByteBuffer& buf)
        {
            return EncodeToHex(buf);
        }

        json ToJsonValue(const AmountList& amountList)
        {
            json list = json::array();
            for (const auto& a : amountList)
            {
                list.push_back(std::to_string(a));
            }
            return list;
        }

        json ToJsonValue(const CoinIDList& coinList)
        {
            json list = json::array();
            for (const auto& c : coinList)
            {
                list.push_back(toString(c));
            }
            return list;
        }

#define HDS_IGNORED_JSON_TYPES(MACRO) \
        MACRO(ECC::Point) \
        MACRO(ECC::Scalar) \
        MACRO(ECC::Signature) \
        MACRO(std::vector<Input::Ptr>) \
        MACRO(std::vector<Output::Ptr>) \
        MACRO(std::vector<ExchangeRate>) \
        MACRO(ShieldedVoucherList)

#define MACRO(type) \
        json ToJsonValue(const type&) \
        { \
            return {}; \
        } \

        HDS_IGNORED_JSON_TYPES(MACRO)
        HDS_IGNORED_JSON_TYPES2(MACRO)

#undef MACRO

#define MACRO(type) \
        bool FromJson(const json&, type&) \
        { \
            return false; \
        } \

        HDS_IGNORED_JSON_TYPES(MACRO)
        HDS_IGNORED_JSON_TYPES2(MACRO)
#undef MACRO

        const string& ToJsonValue(const std::string& s)
        {
            return s;
        }

        const string& GetParameterName(TxParameterID id)
        {
            static auto names = GetParameterNames();
            return names[uint8_t(id)];
        }

        TxParameterID GetParameterID(const std::string& n)
        {
            static auto names = GetParameterNameIDs();
            return names[n];
        }

        json GetParameterValue(TxParameterID id, const ByteBuffer& buffer)
        {
            switch (id)
            {
#define MACRO(name, index, type) \
            case TxParameterID::name: \
                { \
                    type value; \
                    if (fromByteBuffer(buffer, value)) \
                    { \
                        return ToJsonValue(value); \
                    } \
                } break; 
             HDS_TX_PUBLIC_PARAMETERS_MAP(MACRO)
#undef MACRO
            default:
                break;
            }
            return {};
        }

        bool FromJson(const json& s, WalletID& v)
        {
            if (!s.is_string())
            {
                return false;
            }
            return v.FromHex(s.get<string>());
        }

        template<typename T>
        bool FromJson(const json& s, T& v)
        {
            if (!s.is_string())
            {
                return false;
            }
            v = T(stoll(s.get<string>()));
            return true;
        }

        bool FromJson(const json& s, TxType& v)
        {
            if (!s.is_number_integer())
            {
                return false;
            }

            v = TxType(s.get<uint8_t>());
            return true;
        }

        bool FromJson(const json& s, bool& v)
        {
            if (!s.is_boolean())
            {
                return false;
            }

            v = s.get<bool>();
            return true;
        }

        bool FromJson(const json& s, uintBig& v)
        {
            if (!s.is_string())
            {
                return false;
            }
            bool isValid = false;
            auto buf = from_hex(s.get<std::string>(), &isValid);
            if (!isValid)
            {
                return false;
            }
            v = Blob(buf.data(), static_cast<uint32_t>(buf.size()));
            return true;
        }

        bool FromJson(const json& s, PeerID& p)
        {
            if (!s.is_string())
            {
                return false;
            }
            return FromJson(s, static_cast<uintBig&>(p));
        }

        bool FromJson(const json& s, CoinID& v)
        {
            if (!s.is_string())
            {
                return false;
            }
            auto t = Coin::FromString(s.get<std::string>());
            if (!t)
            {
                return false;
            }
            v = *t;
            return true;
        }

        bool FromJson(const json& s, std::string& v)
        {
            if (!s.is_string())
            {
                return false;
            }
            v = s.get<std::string>();
            return true;
        }

        bool FromJson(const json& s, ByteBuffer& v)
        {
            if (!s.is_string())
            {
                return false;
            }
            bool isValid = false;
            v = from_hex(s.get<std::string>(), &isValid);
            return isValid;
        }

        template<typename T>
        bool VectorFromJson(const json& s, T& v)
        {
            if (!s.is_array())
            {
                return false;
            }
            for (const auto& item : s)
            {
                typename T::value_type t;
                if (FromJson(item, t))
                {
                    v.push_back(t);
                }
            }
            return true;
        }

        bool FromJson(const json& s, AmountList& v)
        {
            return VectorFromJson(s, v);
        }

        bool FromJson(const json& s, CoinIDList& v)
        {
            return VectorFromJson(s, v);
        }

        ByteBuffer GetParameterValue(TxParameterID id, const json& jsonValue)
        {
            switch (id)
            {
#define MACRO(name, index, type) \
            case TxParameterID::name: \
                { \
                    type value; \
                    if (FromJson(jsonValue, value)) \
                    { \
                        return toByteBuffer(value); \
                    } \
                } break; 
                HDS_TX_PUBLIC_PARAMETERS_MAP(MACRO)
#undef MACRO
            default:
                break;
            }
            return {};
        }

        const std::string ParamsName = "params";
        const std::string TxIDName = "tx_id";
        const std::string IdName = "id";
        const std::string ValueName = "value";
    }

    std::string ConvertTokenToJson(const std::string& token)
    {
        auto p = ParseParameters(token);
        if (!p)
        {
            return {};
        }
        auto packedParams = p->Pack();
        json params = json::object();

        for (const auto& pair : packedParams)
        {
            params.push_back(
            {
                GetParameterName(pair.first),
                GetParameterValue(pair.first, pair.second)
            });
        }
        auto txID = p->GetTxID();

        json res = json
        {
            { TxIDName, txID.is_initialized() ? json(std::to_string(*txID)) : json{}},
            { ParamsName, params }
        };
        return res.dump();
    }

    std::string ConvertJsonToToken(const std::string& jsonParams)
    {
        try
        {
            json obj = json::parse(jsonParams.data(), jsonParams.data() + jsonParams.size());
            auto paramsIt = obj.find(ParamsName);
            if (paramsIt == obj.end())
            {
                return {};
            }
            boost::optional<TxID> txID;
            auto txIDIt = obj.find(TxIDName);
            if (txIDIt != obj.end() && !txIDIt->is_null())
            {
                auto txIdVec = from_hex(*txIDIt);

                if (txIdVec.size() >= 16)
                {
                    txID.emplace();
                    std::copy_n(txIdVec.begin(), 16, txID->begin());
                }
            }
            TxParameters txParams(txID);
            for (const auto& p : paramsIt->items())
            {
                auto id = GetParameterID(p.key());
                ByteBuffer value = GetParameterValue(id, p.value());
                txParams.SetParameter(id, value);
            }
            return std::to_string(txParams);
        }
        catch (const nlohmann::detail::exception&)
        {
        }
        return {};

    }

}  // namespace hds::wallet
