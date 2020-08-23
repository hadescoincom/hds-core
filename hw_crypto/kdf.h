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
#include "coinid.h"

typedef struct
{
	HdsCrypto_UintBig m_Secret;
	secp256k1_scalar m_kCoFactor;

} HdsCrypto_Kdf;

void HdsCrypto_Kdf_Init(HdsCrypto_Kdf*, const HdsCrypto_UintBig* pSeed);
void HdsCrypto_Kdf_Derive_PKey(const HdsCrypto_Kdf*, const HdsCrypto_UintBig* pHv, secp256k1_scalar* pK);
void HdsCrypto_Kdf_Derive_SKey(const HdsCrypto_Kdf*, const HdsCrypto_UintBig* pHv, secp256k1_scalar* pK);
void HdsCrypto_Kdf_getChild(HdsCrypto_Kdf*, uint32_t iChild, const HdsCrypto_Kdf* pParent);

void HdsCrypto_CoinID_getSk(const HdsCrypto_Kdf*, const HdsCrypto_CoinID*, secp256k1_scalar*);
void HdsCrypto_CoinID_getSkComm(const HdsCrypto_Kdf*, const HdsCrypto_CoinID*, secp256k1_scalar*, HdsCrypto_FlexPoint*);
