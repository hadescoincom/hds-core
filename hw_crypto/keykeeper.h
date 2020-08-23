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
#include "kdf.h"
#include "coinid.h"
#include "sign.h"

typedef struct
{
	HdsCrypto_Kdf m_MasterKey;

	int m_AllowWeakInputs;

	// TODO: state, Slot management, etc.

} HdsCrypto_KeyKeeper;

uint32_t HdsCrypto_KeyKeeper_getNumSlots();
void HdsCrypto_KeyKeeper_ReadSlot(uint32_t, HdsCrypto_UintBig*);
void HdsCrypto_KeyKeeper_RegenerateSlot(uint32_t);

typedef struct
{
	HdsCrypto_UintBig m_Secret;
	HdsCrypto_CompactPoint m_CoFactorG;
	HdsCrypto_CompactPoint m_CoFactorJ;

} HdsCrypto_KdfPub;

void HdsCrypto_KeyKeeper_GetPKdf(const HdsCrypto_KeyKeeper*, HdsCrypto_KdfPub*, const uint32_t* pChild); // if pChild is NULL then the master kdfpub (owner key) is returned

typedef uint64_t HdsCrypto_Height;
typedef uint64_t HdsCrypto_WalletIdentity;

typedef struct
{
	HdsCrypto_Amount m_Fee;
	HdsCrypto_Height m_hMin;
	HdsCrypto_Height m_hMax;

	HdsCrypto_CompactPoint m_Commitment;
	HdsCrypto_Signature m_Signature;

} HdsCrypto_TxKernel;

void HdsCrypto_TxKernel_getID(const HdsCrypto_TxKernel*, HdsCrypto_UintBig* pMsg);
int HdsCrypto_TxKernel_IsValid(const HdsCrypto_TxKernel*);

typedef struct
{
	const HdsCrypto_CoinID* m_pIns;
	const HdsCrypto_CoinID* m_pOuts;
	unsigned int m_Ins;
	unsigned int m_Outs;

	HdsCrypto_TxKernel m_Krn;
	HdsCrypto_UintBig m_kOffset;

} HdsCrypto_TxCommon;

#define HdsCrypto_KeyKeeper_Status_Ok 0
#define HdsCrypto_KeyKeeper_Status_Unspecified 1
#define HdsCrypto_KeyKeeper_Status_UserAbort 2
#define HdsCrypto_KeyKeeper_Status_NotImpl 3

// Split tx, no value transfer. Only fee is spent (hence the user agreement is required)
int HdsCrypto_KeyKeeper_SignTx_Split(const HdsCrypto_KeyKeeper*, HdsCrypto_TxCommon*);

typedef struct
{
	HdsCrypto_UintBig m_Peer;
	HdsCrypto_WalletIdentity m_MyIDKey;
	HdsCrypto_Signature m_PaymentProofSignature;

} HdsCrypto_TxMutualInfo;

int HdsCrypto_KeyKeeper_SignTx_Receive(const HdsCrypto_KeyKeeper*, HdsCrypto_TxCommon*, HdsCrypto_TxMutualInfo*);

typedef struct
{
	uint32_t m_iSlot;
	HdsCrypto_UintBig m_UserAgreement; // set to Zero on 1st invocation

} HdsCrypto_TxSenderParams;

int HdsCrypto_KeyKeeper_SignTx_Send(const HdsCrypto_KeyKeeper*, HdsCrypto_TxCommon*, HdsCrypto_TxMutualInfo*, HdsCrypto_TxSenderParams*);
