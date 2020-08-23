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

typedef struct
{
	HdsCrypto_CompactPoint m_NoncePub;
	HdsCrypto_UintBig m_k; // scalar, but in a platform-independent way

} HdsCrypto_Signature; // Schnorr

void HdsCrypto_Signature_Sign(HdsCrypto_Signature*, const HdsCrypto_UintBig* pMsg, const secp256k1_scalar* pSk);
void HdsCrypto_Signature_SignPartial(HdsCrypto_Signature*, const HdsCrypto_UintBig* pMsg, const secp256k1_scalar* pSk, const secp256k1_scalar* pNonce);
int HdsCrypto_Signature_IsValid(const HdsCrypto_Signature*, const HdsCrypto_UintBig* pMsg, HdsCrypto_FlexPoint* pPk);
