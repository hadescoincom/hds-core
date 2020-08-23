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

#include "wallet_model.h"
#include "utility/logger.h"

#include <jni.h>
#include "common.h"

using namespace hds;
using namespace hds::wallet;
using namespace hds::io;
using namespace std;

namespace
{
    jobject fillNotificationInfo(JNIEnv* env, const Notification& notification)
    {
        jobject jNotificationInfo = env->AllocObject(NotificationClass);

        setStringField(env, NotificationClass, jNotificationInfo, "id", to_string(notification.m_ID));
        setIntField(env, NotificationClass, jNotificationInfo, "state", hds::underlying_cast(notification.m_state));
        setLongField(env, NotificationClass, jNotificationInfo, "createTime", notification.m_createTime);

        return jNotificationInfo;
    }

    jobject fillAddressData(JNIEnv* env, const WalletAddress& address)
    {
        jobject addr = env->AllocObject(WalletAddressClass);

        setStringField(env, WalletAddressClass, addr, "walletID", to_string(address.m_walletID));
        setStringField(env, WalletAddressClass, addr, "label", address.m_label);
        setStringField(env, WalletAddressClass, addr, "category", address.m_category);
        setLongField(env, WalletAddressClass, addr, "createTime", address.m_createTime);
        setLongField(env, WalletAddressClass, addr, "duration", address.m_duration);
        setLongField(env, WalletAddressClass, addr, "own", address.m_OwnID);

        return addr;
    }

    jobject fillTransactionData(JNIEnv* env, const TxDescription& txDescription)
    {
        jobject tx = env->AllocObject(TxDescriptionClass);

        setStringField(env, TxDescriptionClass, tx, "id", to_hex(txDescription.m_txId.data(), txDescription.m_txId.size()));
        setLongField(env, TxDescriptionClass, tx, "amount", txDescription.m_amount);
        setLongField(env, TxDescriptionClass, tx, "fee", txDescription.m_fee);
        setLongField(env, TxDescriptionClass, tx, "change", txDescription.m_changeHds);
        setLongField(env, TxDescriptionClass, tx, "minHeight", txDescription.m_minHeight);

        setStringField(env, TxDescriptionClass, tx, "peerId", to_string(txDescription.m_peerId));
        setStringField(env, TxDescriptionClass, tx, "myId", to_string(txDescription.m_myId));

        setStringField(env, TxDescriptionClass, tx, "message", string(txDescription.m_message.begin(), txDescription.m_message.end()));
        setLongField(env, TxDescriptionClass, tx, "createTime", txDescription.m_createTime);
        setLongField(env, TxDescriptionClass, tx, "modifyTime", txDescription.m_modifyTime);
        setBooleanField(env, TxDescriptionClass, tx, "sender", txDescription.m_sender);
        setBooleanField(env, TxDescriptionClass, tx, "selfTx", txDescription.m_selfTx);
        setIntField(env, TxDescriptionClass, tx, "status", static_cast<jint>(txDescription.m_status));
        setStringField(env, TxDescriptionClass, tx, "kernelId", to_hex(txDescription.m_kernelID.m_pData, txDescription.m_kernelID.nBytes));
        setIntField(env, TxDescriptionClass, tx, "failureReason", static_cast<jint>(txDescription.m_failureReason));

        return tx;
    }

    jobjectArray convertCoinsToJObject(JNIEnv* env, const std::vector<Coin>& utxosVec)
    {
        jobjectArray utxos = 0;

        if (!utxosVec.empty())
        {
            utxos = env->NewObjectArray(static_cast<jsize>(utxosVec.size()), UtxoClass, NULL);

            for (size_t i = 0; i < utxosVec.size(); ++i)
            {
                const auto& coin = utxosVec[i];

                jobject utxo = env->AllocObject(UtxoClass);

                setLongField(env, UtxoClass, utxo, "id", coin.m_ID.m_Idx);
                setStringField(env, UtxoClass, utxo, "stringId", coin.toStringID());
                setLongField(env, UtxoClass, utxo, "amount", coin.m_ID.m_Value);
                setIntField(env, UtxoClass, utxo, "status", coin.m_status);
                setLongField(env, UtxoClass, utxo, "maturity", coin.m_maturity);
                setIntField(env, UtxoClass, utxo, "keyType", static_cast<jint>(coin.m_ID.m_Type));
                setLongField(env, UtxoClass, utxo, "confirmHeight", coin.m_confirmHeight);

                if (coin.m_createTxId)
                    setStringField(env, UtxoClass, utxo, "createTxId", to_hex(coin.m_createTxId->data(), coin.m_createTxId->size()));

                if (coin.m_spentTxId)
                    setStringField(env, UtxoClass, utxo, "spentTxId", to_hex(coin.m_spentTxId->data(), coin.m_spentTxId->size()));

                env->SetObjectArrayElement(utxos, static_cast<jsize>(i), utxo);

                env->DeleteLocalRef(utxo);
            }
        }

        return utxos;
    }

    jobjectArray convertAddressesToJObject(JNIEnv* env, const std::vector<WalletAddress>& addresses)
    {
        jobjectArray addrArray = 0;

        if (!addresses.empty())
        {
            addrArray = env->NewObjectArray(static_cast<jsize>(addresses.size()), WalletAddressClass, NULL);

            for (size_t i = 0; i < addresses.size(); ++i)
            {
                const auto& addrRef = addresses[i];

                jobject addr = fillAddressData(env, addrRef);

                env->SetObjectArrayElement(addrArray, static_cast<jsize>(i), addr);

                env->DeleteLocalRef(addr);
            }
        }
        return addrArray;
    }

    jobjectArray convertExchangeRatesToJObject(JNIEnv* env, const std::vector<ExchangeRate>& rates)
    {
        jobjectArray ratesArray = 0;

        if (!rates.empty())
        {
            ratesArray = env->NewObjectArray(static_cast<jsize>(rates.size()), ExchangeRateClass, NULL);

            for (size_t i = 0; i < rates.size(); ++i)
            {
                jobject rate = env->AllocObject(ExchangeRateClass);

                {
                    setIntField(env, ExchangeRateClass, rate, "currency", underlying_cast(rates[i].m_currency));
                    setIntField(env, ExchangeRateClass, rate, "unit", underlying_cast(rates[i].m_unit));
                    setLongField(env, ExchangeRateClass, rate, "amount", rates[i].m_rate);
                    setLongField(env, ExchangeRateClass, rate, "updateTime", rates[i].m_updateTime);
                }

                env->SetObjectArrayElement(ratesArray, static_cast<jsize>(i), rate);

                env->DeleteLocalRef(rate);
            }
        }
        return ratesArray;
    }

    void callSoftwareUpdateNotification(JNIEnv* env, const Notification& notification, ChangeAction action)
    {
        WalletImplVerInfo walletVersionInfo;

        if (fromByteBuffer(notification.m_content, walletVersionInfo))
        {
            jobject jNotificationInfo = fillNotificationInfo(env, notification);

            jobject jVersionInfo = env->AllocObject(VersionInfoClass);
            {
                setIntField(env, VersionInfoClass, jVersionInfo, "application", hds::underlying_cast(walletVersionInfo.m_application));
                setLongField(env, VersionInfoClass, jVersionInfo, "versionMajor", walletVersionInfo.m_version.m_major);
                setLongField(env, VersionInfoClass, jVersionInfo, "versionMinor", walletVersionInfo.m_version.m_minor);
                setLongField(env, VersionInfoClass, jVersionInfo, "versionRevision", walletVersionInfo.m_UIrevision);
            }

            if (walletVersionInfo.m_application == VersionInfo::Application::AndroidWallet)
            {
                jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onNewVersionNotification", "(IL" HDS_JAVA_PATH "/entities/dto/NotificationDTO;L" HDS_JAVA_PATH "/entities/dto/VersionInfoDTO;)V");

                env->CallStaticVoidMethod(WalletListenerClass, callback, action, jNotificationInfo, jVersionInfo);
            }

            env->DeleteLocalRef(jNotificationInfo);
            env->DeleteLocalRef(jVersionInfo);
        }
    }
    
    void callAddressStatusNotification(JNIEnv* env, const Notification& notification, ChangeAction action)
    {
        WalletAddress address;

        if (fromByteBuffer(notification.m_content, address))
        {
            jobject jNotificationInfo = fillNotificationInfo(env, notification);

            jobject jAddress = fillAddressData(env, address);

            jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onAddressChangedNotification", "(IL" HDS_JAVA_PATH "/entities/dto/NotificationDTO;L" HDS_JAVA_PATH "/entities/dto/WalletAddressDTO;)V");
            
            env->CallStaticVoidMethod(WalletListenerClass, callback, action, jNotificationInfo, jAddress);

            env->DeleteLocalRef(jNotificationInfo);
            env->DeleteLocalRef(jAddress);
        }
    }

    void callTransactionFailed(JNIEnv* env, const Notification& notification, ChangeAction action)
    {
        TxToken token;

        if (fromByteBuffer(notification.m_content, token))
        {
            TxParameters txParameters = token.UnpackParameters();
            TxDescription txDescription(txParameters);

            jobject jNotificationInfo = fillNotificationInfo(env, notification);

            jobject jTransaction = fillTransactionData(env, txDescription);

            jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onTransactionFailedNotification", "(IL" HDS_JAVA_PATH "/entities/dto/NotificationDTO;L" HDS_JAVA_PATH "/entities/dto/TxDescriptionDTO;)V");
            
            env->CallStaticVoidMethod(WalletListenerClass, callback, action, jNotificationInfo, jTransaction);

            env->DeleteLocalRef(jNotificationInfo);
            env->DeleteLocalRef(jTransaction);
        }
    }

    void callTransactionCompleted(JNIEnv* env, const Notification& notification, ChangeAction action)
    {
        TxToken token;

        if (fromByteBuffer(notification.m_content, token))
        {
            TxParameters txParameters = token.UnpackParameters();
            TxDescription txDescription(txParameters);

            jobject jNotificationInfo = fillNotificationInfo(env, notification);

            jobject jTransaction = fillTransactionData(env, txDescription);

            jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onTransactionCompletedNotification", "(IL" HDS_JAVA_PATH "/entities/dto/NotificationDTO;L" HDS_JAVA_PATH "/entities/dto/TxDescriptionDTO;)V");
            
            env->CallStaticVoidMethod(WalletListenerClass, callback, action, jNotificationInfo, jTransaction);

            env->DeleteLocalRef(jNotificationInfo);
            env->DeleteLocalRef(jTransaction);
        }
    }

    void callHdsNewsNotification(JNIEnv* env, const Notification& notification, ChangeAction action)
    {
        // TODO: deserialize notification content and fill JAVA data object

        jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onHdsNewsNotification", "(I)V");

        env->CallStaticVoidMethod(WalletListenerClass, callback, action);
    }
}

WalletModel::WalletModel(IWalletDB::Ptr walletDB, const std::string& nodeAddr, Reactor::Ptr reactor)
    : WalletClient(walletDB, nodeAddr, reactor)
{    
}

WalletModel::~WalletModel()
{
    stopReactor();
}

void WalletModel::onStatus(const WalletStatus& status)
{
    JNIEnv* env = Android_JNI_getEnv();

    jobject walletStatus = env->AllocObject(WalletStatusClass);

    setLongField(env, WalletStatusClass, walletStatus, "available", status.available);
    setLongField(env, WalletStatusClass, walletStatus, "receiving", status.receiving);
    setLongField(env, WalletStatusClass, walletStatus, "sending", status.sending);
    setLongField(env, WalletStatusClass, walletStatus, "maturing", status.maturing);

    {
        jobject systemState = env->AllocObject(SystemStateClass);

        setLongField(env, SystemStateClass, systemState, "height", status.stateID.m_Height);
        setStringField(env, SystemStateClass, systemState, "hash", to_hex(status.stateID.m_Hash.m_pData, status.stateID.m_Hash.nBytes));

        jfieldID systemStateID = env->GetFieldID(WalletStatusClass, "system", "L" HDS_JAVA_PATH "/entities/dto/SystemStateDTO;");
        env->SetObjectField(walletStatus, systemStateID, systemState);

        env->DeleteLocalRef(systemState);
    }

    ////////////////

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onStatus", "(L" HDS_JAVA_PATH "/entities/dto/WalletStatusDTO;)V");
    env->CallStaticVoidMethod(WalletListenerClass, callback, walletStatus);

    env->DeleteLocalRef(walletStatus);
}

void WalletModel::onTxStatus(ChangeAction action, const std::vector<TxDescription>& items)
{
    LOG_DEBUG() << "onTxStatus()";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onTxStatus", "(I[L" HDS_JAVA_PATH "/entities/dto/TxDescriptionDTO;)V");

    jobjectArray txItems = 0;

    if (!items.empty())
    {
        txItems = env->NewObjectArray(static_cast<jsize>(items.size()), TxDescriptionClass, NULL);

        for (size_t i = 0; i < items.size(); ++i)
        {
            const auto& item = items[i];

            jobject tx = fillTransactionData(env, item);

            env->SetObjectArrayElement(txItems, static_cast<jsize>(i), tx);

            env->DeleteLocalRef(tx);
        }
    }

    env->CallStaticVoidMethod(WalletListenerClass, callback, action, txItems);

    env->DeleteLocalRef(txItems);
}

void WalletModel::onSyncProgressUpdated(int done, int total)
{
    LOG_DEBUG() << "onSyncProgressUpdated(" << done << ", " << total << ")";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onSyncProgressUpdated", "(II)V");

    env->CallStaticVoidMethod(WalletListenerClass, callback, done, total);
}

void WalletModel::onChangeCalculated(Amount change)
{
    LOG_DEBUG() << "onChangeCalculated(" << change << ")";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onChangeCalculated", "(J)V");

    env->CallStaticVoidMethod(WalletListenerClass, callback, change);
}

void WalletModel::onAllUtxoChanged(ChangeAction action, const std::vector<Coin>& utxosVec)
{
    LOG_DEBUG() << "onAllUtxoChanged()";

    JNIEnv* env = Android_JNI_getEnv();

    jobjectArray utxos = convertCoinsToJObject(env, utxosVec);

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onAllUtxoChanged", "(I[L" HDS_JAVA_PATH "/entities/dto/UtxoDTO;)V");
    env->CallStaticVoidMethod(WalletListenerClass, callback, action, utxos);

    env->DeleteLocalRef(utxos);
}

void WalletModel::onAddressesChanged(ChangeAction action, const std::vector<WalletAddress>& addresses)
{
    LOG_DEBUG() << "onAddressesChanged()";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onAddressesChanged", "(I[L" HDS_JAVA_PATH "/entities/dto/WalletAddressDTO;)V");

    jobjectArray addrArray = convertAddressesToJObject(env, addresses);

    env->CallStaticVoidMethod(WalletListenerClass, callback, action, addrArray);

    env->DeleteLocalRef(addrArray);
}

void WalletModel::onAddresses(bool own, const std::vector<WalletAddress>& addresses)
{
    LOG_DEBUG() << "onAddresses(" << own << ")";

    JNIEnv* env = Android_JNI_getEnv();

    jobjectArray addrArray = convertAddressesToJObject(env, addresses);

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onAddresses", "(Z[L" HDS_JAVA_PATH "/entities/dto/WalletAddressDTO;)V");
    env->CallStaticVoidMethod(WalletListenerClass, callback, own, addrArray);

    env->DeleteLocalRef(addrArray);
}

#ifdef HDS_ATOMIC_SWAP_SUPPORT
void WalletModel::onSwapOffersChanged(ChangeAction action, const std::vector<SwapOffer>& offers)
{
    LOG_DEBUG() << "onSwapOffersChanged()";

    // TODO
}
#endif  // HDS_ATOMIC_SWAP_SUPPORT

void WalletModel::onGeneratedNewAddress(const WalletAddress& address)
{
    LOG_DEBUG() << "onGeneratedNewAddress()";

    JNIEnv* env = Android_JNI_getEnv();

    jobject addr = fillAddressData(env, address);

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onGeneratedNewAddress", "(L" HDS_JAVA_PATH "/entities/dto/WalletAddressDTO;)V");
    env->CallStaticVoidMethod(WalletListenerClass, callback, addr);

    env->DeleteLocalRef(addr);
}

void WalletModel::onSwapParamsLoaded(const hds::ByteBuffer& params)
{
    LOG_DEBUG() << "onSwapParamsLoaded()";

    // TODO
}

void WalletModel::onNewAddressFailed()
{

}

void WalletModel::onNodeConnectionChanged(bool isNodeConnected)
{
    LOG_DEBUG() << "onNodeConnectedStatusChanged(" << isNodeConnected << ")";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onNodeConnectedStatusChanged", "(Z)V");

    env->CallStaticVoidMethod(WalletListenerClass, callback, isNodeConnected);
}

void WalletModel::onWalletError(ErrorType error)
{
    LOG_DEBUG() << "onWalletError: error = " << underlying_cast(error);

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onNodeConnectionFailed", "(I)V");

    env->CallStaticVoidMethod(WalletListenerClass, callback, underlying_cast(error));
}

void WalletModel::FailedToStartWallet()
{
    
}

void WalletModel::onSendMoneyVerified()
{
    
}

void WalletModel::onCantSendToExpired()
{
    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onCantSendToExpired", "()V");

    env->CallStaticVoidMethod(WalletListenerClass, callback);
}

void WalletModel::onPaymentProofExported(const TxID& txID, const ByteBuffer& proof)
{
    string strProof;
    strProof.resize(proof.size() * 2);

    to_hex(strProof.data(), proof.data(), proof.size());
    storage::PaymentInfo paymentInfo = storage::PaymentInfo::FromByteBuffer(proof);

    JNIEnv* env = Android_JNI_getEnv();

    jobject jPaymentInfo = env->AllocObject(PaymentInfoClass);

    {
        setStringField(env, PaymentInfoClass, jPaymentInfo, "senderId", to_string(paymentInfo.m_Sender));
        setStringField(env, PaymentInfoClass, jPaymentInfo, "receiverId", to_string(paymentInfo.m_Receiver));
        setLongField(env, PaymentInfoClass, jPaymentInfo, "amount", paymentInfo.m_Amount);
        setStringField(env, PaymentInfoClass, jPaymentInfo, "kernelId", to_string(paymentInfo.m_KernelID));
        setBooleanField(env, PaymentInfoClass, jPaymentInfo, "isValid", paymentInfo.IsValid());
        setStringField(env, PaymentInfoClass, jPaymentInfo, "rawProof", strProof);
    }

    jstring jStrTxId = env->NewStringUTF(to_hex(txID.data(), txID.size()).c_str());

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onPaymentProofExported", "(Ljava/lang/String;L" HDS_JAVA_PATH "/entities/dto/PaymentInfoDTO;)V");

    
    //jstring jStrProof = env->NewStringUTF(str.c_str());
    env->CallStaticVoidMethod(WalletListenerClass, callback, jStrTxId, jPaymentInfo);

    env->DeleteLocalRef(jStrTxId);
    env->DeleteLocalRef(jPaymentInfo);
}

void WalletModel::onCoinsByTx(const std::vector<Coin>& coins)
{
    JNIEnv* env = Android_JNI_getEnv();

    jobjectArray utxos = convertCoinsToJObject(env, coins);

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onCoinsByTx", "([L" HDS_JAVA_PATH "/entities/dto/UtxoDTO;)V");
    env->CallStaticVoidMethod(WalletListenerClass, callback, utxos);

    env->DeleteLocalRef(utxos);
}

void WalletModel::onAddressChecked(const std::string& addr, bool isValid)
{

}

void WalletModel::onImportRecoveryProgress(uint64_t done, uint64_t total)
{
    LOG_DEBUG() << "onImportRecoveryProgress(" << done << ", " << total << ")";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onImportRecoveryProgress", "(JJ)V");

    env->CallStaticVoidMethod(WalletListenerClass, callback, done, total);
}

void WalletModel::onImportDataFromJson(bool isOk)
{
    LOG_DEBUG() << "onImportDataFromJson(" << isOk << ")";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onImportDataFromJson", "(Z)V");

    env->CallStaticVoidMethod(WalletListenerClass, callback, isOk);
}

void WalletModel::onExportDataToJson(const std::string& data)
{
    LOG_DEBUG() << "onExportDataToJson";

    JNIEnv* env = Android_JNI_getEnv();

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onExportDataToJson", "(Ljava/lang/String;)V");

    jstring jdata = env->NewStringUTF(data.c_str());

    env->CallStaticVoidMethod(WalletListenerClass, callback, jdata);
    env->DeleteLocalRef(jdata);
}

void WalletModel::onNotificationsChanged(ChangeAction action, const std::vector<Notification>& notifications)
{
    LOG_DEBUG() << "onNotificationsChanged";

    JNIEnv* env = Android_JNI_getEnv();

    for (const auto& notification : notifications)
    {
        switch(notification.m_type)
        {
            case Notification::Type::SoftwareUpdateAvailable:
                 break;
            case Notification::Type::WalletImplUpdateAvailable:
                 callSoftwareUpdateNotification(env, notification, action);
                 break;
            case Notification::Type::AddressStatusChanged:
                callAddressStatusNotification(env, notification, action);
                break;
            case Notification::Type::TransactionFailed:
                callTransactionFailed(env, notification, action);
                break;
            case Notification::Type::TransactionCompleted:
                callTransactionCompleted(env, notification, action);
                break;
            case Notification::Type::HdsNews:
                callHdsNewsNotification(env, notification, action);
                break;
            default:
                break;
        }
    }
}

void WalletModel::onExchangeRates(const std::vector<ExchangeRate>& rates)
{
    LOG_DEBUG() << "onExchangeRates";

    JNIEnv* env = Android_JNI_getEnv();

    jobjectArray jRates = convertExchangeRatesToJObject(env, rates);

    jmethodID callback = env->GetStaticMethodID(WalletListenerClass, "onExchangeRates", "([L" HDS_JAVA_PATH "/entities/dto/ExchangeRateDTO;)V");

    env->CallStaticVoidMethod(WalletListenerClass, callback, jRates);

    env->DeleteLocalRef(jRates);
}
