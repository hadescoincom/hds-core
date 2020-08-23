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
#include "ecc_decl.h"

#define HdsCrypto_MultiMac_Directions 2 // must be 1 or 2. For 2 interleaving is used. Faster (~1 effective window bit), but needs an extra scalar per element
#define HdsCrypto_MultiMac_Fast_nBits 4
#define HdsCrypto_MultiMac_Secure_nBits 4
#define HdsCrypto_MultiMac_Fast_nCount (1 << (HdsCrypto_MultiMac_Fast_nBits - 1)) // odd powers
#define HdsCrypto_MultiMac_Secure_nCount (1 << HdsCrypto_MultiMac_Secure_nBits)

typedef struct {
	secp256k1_ge_storage m_pPt[HdsCrypto_MultiMac_Fast_nCount]; // odd powers
} HdsCrypto_MultiMac_Fast;

typedef struct {
	secp256k1_ge_storage m_pPt[HdsCrypto_MultiMac_Secure_nCount + 1]; // the last is the compensation term
} HdsCrypto_MultiMac_Secure;

typedef struct {
	uint8_t m_iBit;
	uint8_t m_iElement;
} HdsCrypto_MultiMac_WNaf_Cursor;

typedef struct {
	HdsCrypto_MultiMac_WNaf_Cursor m_pC[HdsCrypto_MultiMac_Directions];
} HdsCrypto_MultiMac_WNaf;

typedef struct {
	secp256k1_scalar m_pK[HdsCrypto_MultiMac_Directions];
} HdsCrypto_MultiMac_Scalar;

typedef struct
{
	secp256k1_gej* m_pRes;

	unsigned int m_Fast;
	unsigned int m_Secure;

	const HdsCrypto_MultiMac_Fast* m_pGenFast;
	HdsCrypto_MultiMac_Scalar* m_pS;
	HdsCrypto_MultiMac_WNaf* m_pWnaf;

	const HdsCrypto_MultiMac_Secure* m_pGenSecure;
	const secp256k1_scalar* m_pSecureK;

	secp256k1_fe* m_pZDenom; // optional common z-denominator of 'fast' generators.

} HdsCrypto_MultiMac_Context;

void HdsCrypto_MultiMac_Calculate(const HdsCrypto_MultiMac_Context*);

#define HdsCrypto_MultiMac_Fast_nGenerators (sizeof(uint64_t) * 8 * 2)
#define HdsCrypto_MultiMac_Fast_Idx_H HdsCrypto_MultiMac_Fast_nGenerators

typedef struct
{
	HdsCrypto_MultiMac_Fast m_pGenFast[HdsCrypto_MultiMac_Fast_Idx_H + 1];
	HdsCrypto_MultiMac_Secure m_GenG;
	HdsCrypto_MultiMac_Secure m_GenJ;

} HdsCrypto_Context;

HdsCrypto_Context* HdsCrypto_Context_get();

// simplified versions
void HdsCrypto_MulPoint(HdsCrypto_FlexPoint*, const HdsCrypto_MultiMac_Secure*, const secp256k1_scalar*);
void HdsCrypto_MulG(HdsCrypto_FlexPoint*, const secp256k1_scalar*);
void HdsCrypto_Sk2Pk(HdsCrypto_UintBig*, secp256k1_scalar*);
