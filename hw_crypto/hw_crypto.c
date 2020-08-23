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

#include <assert.h>
#include "multimac.h"
#include "oracle.h"
#include "noncegen.h"
#include "coinid.h"
#include "kdf.h"
#include "rangeproof.h"
#include "sign.h"
#include "keykeeper.h"

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wunused-function"
#else
#	pragma warning (push, 0) // suppress warnings from secp256k1
#	pragma warning (disable: 4706 4701) // assignment within conditional expression
#endif


#include "secp256k1-zkp/src/group_impl.h"
#include "secp256k1-zkp/src/scalar_impl.h"
#include "secp256k1-zkp/src/field_impl.h"
#include "secp256k1-zkp/src/hash_impl.h"

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
#	pragma GCC diagnostic pop
#else
#	pragma warning (default: 4706 4701)
#	pragma warning (pop)
#endif

#define SECURE_ERASE_OBJ(x) memset(&x, 0, sizeof(x))

#define s_WNaf_HiBit 0x80
static_assert(HdsCrypto_MultiMac_Fast_nCount < s_WNaf_HiBit, "");

#ifdef USE_SCALAR_4X64
typedef uint64_t secp256k1_scalar_uint;
#else // USE_SCALAR_4X64
typedef uint32_t secp256k1_scalar_uint;
#endif // USE_SCALAR_4X64

#ifndef _countof
#	define _countof(arr) sizeof(arr) / sizeof((arr)[0])
#endif

#define secp256k1_scalar_WordBits (sizeof(secp256k1_scalar_uint) * 8)

//////////////////////////////
// MultiMac
typedef struct
{
	int m_Word;
	secp256k1_scalar_uint m_Msk;
} BitWalker;

inline static void BitWalker_SetPos(BitWalker* p, uint8_t iBit)
{
	p->m_Word = iBit / secp256k1_scalar_WordBits;
	p->m_Msk = ((secp256k1_scalar_uint) 1) << (iBit & (secp256k1_scalar_WordBits - 1));
}

inline static void BitWalker_MoveUp(BitWalker* p)
{
	if (!(p->m_Msk <<= 1))
	{
		p->m_Msk = 1;
		p->m_Word++;
	}
}

inline static void BitWalker_MoveDown(BitWalker* p)
{
	if (!(p->m_Msk >>= 1))
	{
		p->m_Msk = ((secp256k1_scalar_uint) 1) << (secp256k1_scalar_WordBits - 1);

		p->m_Word--;
	}
}

inline static secp256k1_scalar_uint BitWalker_get(const BitWalker* p, const secp256k1_scalar* pK)
{
	return pK->d[p->m_Word] & p->m_Msk;
}

inline static void BitWalker_xor(const BitWalker* p, secp256k1_scalar* pK)
{
	pK->d[p->m_Word] ^= p->m_Msk;
}


static void WNaf_Cursor_MoveNext(HdsCrypto_MultiMac_WNaf_Cursor* p, const secp256k1_scalar* pK)
{
	BitWalker bw;
	BitWalker_SetPos(&bw, --p->m_iBit);

	// find next nnz bit
	for (; ; p->m_iBit--, BitWalker_MoveDown(&bw))
	{
		if (BitWalker_get(&bw, pK))
			break;

		if (!p->m_iBit)
		{
			// end
			p->m_iBit = 1;
			p->m_iElement = s_WNaf_HiBit;
			return;
		}
	}

	uint8_t nOdd = 1;

	uint8_t nWndBits = HdsCrypto_MultiMac_Fast_nBits - 1;
	if (nWndBits > p->m_iBit)
		nWndBits = p->m_iBit;

	for (uint8_t i = 0; i < nWndBits; i++, p->m_iBit--)
	{
		BitWalker_MoveDown(&bw);
		nOdd = (nOdd << 1) | (BitWalker_get(&bw, pK) != 0);
	}

	for (; !(1 & nOdd); p->m_iBit++)
		nOdd >>= 1;

	p->m_iElement = nOdd >> 1;
}

static int Scalar_SplitPosNeg(HdsCrypto_MultiMac_Scalar* p)
{
#if HdsCrypto_MultiMac_Directions != 2
	static_assert(HdsCrypto_MultiMac_Directions == 1, "");
#else // HdsCrypto_MultiMac_Directions

	memset(p->m_pK[1].d, 0, sizeof(p->m_pK[1].d));

	uint8_t iBit = 0;
	BitWalker bw;
	bw.m_Word = 0;
	bw.m_Msk = 1;

	while (1)
	{
		// find nnz bit
		while (1)
		{
			if (iBit >= HdsCrypto_nBits - HdsCrypto_MultiMac_Fast_nBits)
				return 0;

			if (BitWalker_get(&bw, p->m_pK))
				break;

			iBit++;
			BitWalker_MoveUp(&bw);
		}

		BitWalker bw0 = bw;

		iBit += HdsCrypto_MultiMac_Fast_nBits;
		for (uint32_t i = 0; i < HdsCrypto_MultiMac_Fast_nBits; i++)
			BitWalker_MoveUp(&bw); // akward

		if (!BitWalker_get(&bw, p->m_pK))
			continue; // interleaving is not needed

		// set negative bits
		BitWalker_xor(&bw0, p->m_pK);
		BitWalker_xor(&bw0, p->m_pK + 1);

		for (uint8_t i = 1; i < HdsCrypto_MultiMac_Fast_nBits; i++)
		{
			BitWalker_MoveUp(&bw0);

			secp256k1_scalar_uint val = BitWalker_get(&bw0, p->m_pK);
			BitWalker_xor(&bw0, p->m_pK + !val);
		}

		// propagate carry
		while (1)
		{
			BitWalker_xor(&bw, p->m_pK);
			if (BitWalker_get(&bw, p->m_pK))
				break;

			if (! ++iBit)
				return 1; // carry goes outside

			BitWalker_MoveUp(&bw);
		}
	}
#endif // HdsCrypto_MultiMac_Directions

	return 0;
}

void mem_cmov(unsigned int* pDst, const unsigned int* pSrc, int flag, unsigned int nWords)
{
	const unsigned int mask0 = flag + ~((unsigned int) 0);
	const unsigned int mask1 = ~mask0;

	for (unsigned int n = 0; n < nWords; n++)
		pDst[n] = (pDst[n] & mask0) | (pSrc[n] & mask1);
}

void HdsCrypto_MultiMac_Calculate(const HdsCrypto_MultiMac_Context* p)
{
	secp256k1_gej_set_infinity(p->m_pRes);

	for (unsigned int i = 0; i < p->m_Fast; i++)
	{
		HdsCrypto_MultiMac_WNaf* pWnaf = p->m_pWnaf + i;
		HdsCrypto_MultiMac_Scalar* pS = p->m_pS + i;

		pWnaf->m_pC[0].m_iBit = 0;

		int carry = Scalar_SplitPosNeg(pS);
		if (carry)
			pWnaf->m_pC[0].m_iElement = s_WNaf_HiBit;
		else
			WNaf_Cursor_MoveNext(pWnaf->m_pC, pS->m_pK);

#if HdsCrypto_MultiMac_Directions == 2
		pWnaf->m_pC[1].m_iBit = 0;
		WNaf_Cursor_MoveNext(pWnaf->m_pC + 1, pS->m_pK + 1);
#endif // HdsCrypto_MultiMac_Directions
	}

	secp256k1_ge ge;
	secp256k1_ge_storage ges;

	for (uint16_t iBit = HdsCrypto_nBits + 1; iBit--; ) // extra bit may be necessary because of interleaving
	{
		secp256k1_gej_double_var(p->m_pRes, p->m_pRes, 0); // would be fast if zero, no need to check explicitly

		if (!(iBit % HdsCrypto_MultiMac_Secure_nBits) && (iBit < HdsCrypto_nBits) && p->m_Secure)
		{
			static_assert(!(secp256k1_scalar_WordBits % HdsCrypto_MultiMac_Secure_nBits), "");

			unsigned int iWord = iBit / secp256k1_scalar_WordBits;
			unsigned int nShift = iBit % secp256k1_scalar_WordBits;
			const secp256k1_scalar_uint nMsk = ((1U << HdsCrypto_MultiMac_Secure_nBits) - 1);

			for (unsigned int i = 0; i < p->m_Secure; i++)
			{
				unsigned int iElement = (p->m_pSecureK[i].d[iWord] >> nShift) & nMsk;
				const HdsCrypto_MultiMac_Secure* pGen = p->m_pGenSecure + i;

				for (unsigned int j = 0; j < HdsCrypto_MultiMac_Secure_nCount; j++)
				{
					static_assert(sizeof(ges) == sizeof(pGen->m_pPt[j]), "");
					static_assert(!(sizeof(ges) % sizeof(unsigned int)), "");

					mem_cmov(
						(unsigned int*) &ges,
						(unsigned int*) (pGen->m_pPt + j),
						iElement == j,
						sizeof(ges) / sizeof(unsigned int));
				}

				secp256k1_ge_from_storage(&ge, &ges);

				if (p->m_pZDenom)
					secp256k1_gej_add_zinv_var(p->m_pRes, p->m_pRes, &ge, p->m_pZDenom);
				else
					secp256k1_gej_add_ge_var(p->m_pRes, p->m_pRes, &ge, 0);
			}
		}

		for (unsigned int i = 0; i < p->m_Fast; i++)
		{
			HdsCrypto_MultiMac_WNaf* pWnaf = p->m_pWnaf + i;

			for (unsigned int j = 0; j < HdsCrypto_MultiMac_Directions; j++)
			{
				HdsCrypto_MultiMac_WNaf_Cursor* pWc = pWnaf->m_pC + j;

				if (((uint8_t) iBit) != pWc->m_iBit)
					continue;

				// special case: resolve 256-0 ambiguity
				if ((pWc->m_iElement ^ ((uint8_t) (iBit >> 1))) & s_WNaf_HiBit)
					continue;

				secp256k1_ge_from_storage(&ge, p->m_pGenFast[i].m_pPt + (pWc->m_iElement & ~s_WNaf_HiBit));

				if (j)
					secp256k1_ge_neg(&ge, &ge);

				secp256k1_gej_add_ge_var(p->m_pRes, p->m_pRes, &ge, 0);

				if (iBit)
					WNaf_Cursor_MoveNext(pWc, p->m_pS[i].m_pK + j);
			}
		}
	}

	SECURE_ERASE_OBJ(ges);

	if (p->m_pZDenom)
		// fix denominator
		secp256k1_fe_mul(&p->m_pRes->z, &p->m_pRes->z, p->m_pZDenom);

	for (unsigned int i = 0; i < p->m_Secure; i++)
	{
		secp256k1_ge_from_storage(&ge, p->m_pGenSecure[i].m_pPt + HdsCrypto_MultiMac_Secure_nCount);
		secp256k1_gej_add_ge_var(p->m_pRes, p->m_pRes, &ge, 0);
	}
}

//////////////////////////////
// Batch normalization
static void secp256k1_gej_rescale_XY(secp256k1_gej* pGej, const secp256k1_fe* pZ)
{
	// equivalent of secp256k1_gej_rescale, but doesn't change z coordinate
	// A bit more effective when the value of z is known in advance (such as when normalizing)
	secp256k1_fe zz;
	secp256k1_fe_sqr(&zz, pZ);

	secp256k1_fe_mul(&pGej->x, &pGej->x, &zz);
	secp256k1_fe_mul(&pGej->y, &pGej->y, &zz);
	secp256k1_fe_mul(&pGej->y, &pGej->y, pZ);
}

static void BatchNormalize_Fwd(secp256k1_fe* pFe, unsigned int n, const secp256k1_gej* pGej, const secp256k1_fe* pFePrev)
{
	if (n)
		secp256k1_fe_mul(pFe, pFePrev, &pGej->z);
	else
		*pFe = pGej[0].z;
}

static void BatchNormalize_Apex(secp256k1_fe* pZDenom, secp256k1_fe* pFePrev, int nNormalize)
{
	if (nNormalize)
		secp256k1_fe_inv(pZDenom, pFePrev); // the only expensive call
	else
		secp256k1_fe_set_int(pZDenom, 1);
}

static void BatchNormalize_Bwd(secp256k1_fe* pFe, unsigned int n, secp256k1_gej* pGej, const secp256k1_fe* pFePrev, secp256k1_fe* pZDenom)
{
	if (n)
		secp256k1_fe_mul(pFe, pFePrev, pZDenom);
	else
		*pFe = *pZDenom;

	secp256k1_gej_rescale_XY(pGej, pFe);

	secp256k1_fe_mul(pZDenom, pZDenom, &pGej->z);
}


static void HdsCrypto_ToCommonDenominator(unsigned int nCount, secp256k1_gej* pGej, secp256k1_fe* pFe, secp256k1_fe* pZDenom, int nNormalize)
{
	assert(nCount);

	for (unsigned int i = 0; i < nCount; i++)
		BatchNormalize_Fwd(pFe + i, i, pGej + i, pFe + i - 1);

	BatchNormalize_Apex(pZDenom, pFe + nCount - 1, nNormalize);

	for (unsigned int i = nCount; i--; )
		BatchNormalize_Bwd(pFe + i, i, pGej + i, pFe + i - 1, pZDenom);
}

static void secp256k1_ge_set_gej_normalized(secp256k1_ge* pGe, const secp256k1_gej* pGej)
{
	pGe->infinity = pGej->infinity;
	pGe->x = pGej->x;
	pGe->y = pGej->y;
}

static void HdsCrypto_MultiMac_SetCustom_Nnz(HdsCrypto_MultiMac_Context* p, HdsCrypto_FlexPoint* pFlex)
{
	assert(p->m_Fast == 1);
	assert(p->m_pZDenom);

	HdsCrypto_FlexPoint_MakeGej(pFlex);
	assert(HdsCrypto_FlexPoint_Gej & pFlex->m_Flags);
	assert(!secp256k1_gej_is_infinity(&pFlex->m_Gej));

	secp256k1_gej pOdds[HdsCrypto_MultiMac_Fast_nCount];
	pOdds[0] = pFlex->m_Gej;

	// calculate odd powers
	secp256k1_gej x2;
	secp256k1_gej_double_var(&x2, pOdds, 0);

	for (unsigned int i = 1; i < HdsCrypto_MultiMac_Fast_nCount; i++)
	{
		secp256k1_gej_add_var(pOdds + i, pOdds + i - 1, &x2, 0);
		assert(!secp256k1_gej_is_infinity(pOdds + i)); // odd powers of non-zero point must not be zero!
	}

	secp256k1_fe pFe[HdsCrypto_MultiMac_Fast_nCount];

	HdsCrypto_ToCommonDenominator(HdsCrypto_MultiMac_Fast_nCount, pOdds, pFe, p->m_pZDenom, 0);

	for (unsigned int i = 0; i < HdsCrypto_MultiMac_Fast_nCount; i++)
	{
		secp256k1_ge ge;
		secp256k1_ge_set_gej_normalized(&ge, pOdds + i);
		secp256k1_ge_to_storage((secp256k1_ge_storage*)p->m_pGenFast[0].m_pPt + i, &ge);
	}
}

//////////////////////////////
// NonceGenerator
void HdsCrypto_NonceGenerator_InitBegin(HdsCrypto_NonceGenerator* p, secp256k1_hmac_sha256_t* pHMac, const char* szSalt, size_t nSalt)
{
	p->m_Counter = 0;
	p->m_FirstTime = 1;
	p->m_pContext = 0;
	p->m_nContext = 0;

	secp256k1_hmac_sha256_initialize(pHMac, (uint8_t*) szSalt, nSalt);
}

void HdsCrypto_NonceGenerator_InitEnd(HdsCrypto_NonceGenerator* p, secp256k1_hmac_sha256_t* pHMac)
{
	secp256k1_hmac_sha256_finalize(pHMac, p->m_Prk.m_pVal);
}

void HdsCrypto_NonceGenerator_Init(HdsCrypto_NonceGenerator* p, const char* szSalt, size_t nSalt, const HdsCrypto_UintBig* pSeed)
{
	secp256k1_hmac_sha256_t hmac;

	HdsCrypto_NonceGenerator_InitBegin(p, &hmac, szSalt, nSalt);
	secp256k1_hmac_sha256_write(&hmac, pSeed->m_pVal, sizeof(pSeed->m_pVal));
	HdsCrypto_NonceGenerator_InitEnd(p, &hmac);
}

void HdsCrypto_NonceGenerator_NextOkm(HdsCrypto_NonceGenerator* p)
{
	// Expand
	secp256k1_hmac_sha256_t hmac;
	secp256k1_hmac_sha256_initialize(&hmac, p->m_Prk.m_pVal, sizeof(p->m_Prk.m_pVal));

	if (p->m_FirstTime)
		p->m_FirstTime = 0;
	else
		secp256k1_hmac_sha256_write(&hmac, p->m_Okm.m_pVal, sizeof(p->m_Okm.m_pVal));

	secp256k1_hmac_sha256_write(&hmac, p->m_pContext, p->m_nContext);

	p->m_Counter++;
	secp256k1_hmac_sha256_write(&hmac, &p->m_Counter, sizeof(p->m_Counter));

	secp256k1_hmac_sha256_finalize(&hmac, p->m_Okm.m_pVal);
}

void HdsCrypto_NonceGenerator_NextScalar(HdsCrypto_NonceGenerator* p, secp256k1_scalar* pS)
{
	while (1)
	{
		HdsCrypto_NonceGenerator_NextOkm(p);

		int overflow;
		secp256k1_scalar_set_b32(pS, p->m_Okm.m_pVal, &overflow);
		if (!overflow)
			break;
	}
}

static int IsUintBigZero(const HdsCrypto_UintBig* p)
{
	// const-time isn't required
	for (unsigned int i = 0; i < _countof(p->m_pVal); i++)
		if (p->m_pVal[i])
			return 0;
	return 1;
}

//////////////////////////////
// Point
void HdsCrypto_FlexPoint_MakeCompact(HdsCrypto_FlexPoint* pFlex)
{
	if ((HdsCrypto_FlexPoint_Compact & pFlex->m_Flags) || !pFlex->m_Flags)
		return;

	HdsCrypto_FlexPoint_MakeGe(pFlex);
	assert(HdsCrypto_FlexPoint_Ge & pFlex->m_Flags);

	if (secp256k1_ge_is_infinity(&pFlex->m_Ge))
		memset(&pFlex->m_Compact, 0, sizeof(pFlex->m_Compact));
	else
	{
		secp256k1_fe_normalize(&pFlex->m_Ge.x);
		secp256k1_fe_normalize(&pFlex->m_Ge.y);

		secp256k1_fe_get_b32(pFlex->m_Compact.m_X.m_pVal, &pFlex->m_Ge.x);
		pFlex->m_Compact.m_Y = (secp256k1_fe_is_odd(&pFlex->m_Ge.y) != 0);
	}

	pFlex->m_Flags |= HdsCrypto_FlexPoint_Compact;
}

void HdsCrypto_FlexPoint_MakeGej(HdsCrypto_FlexPoint* pFlex)
{
	if (HdsCrypto_FlexPoint_Gej & pFlex->m_Flags)
		return;

	HdsCrypto_FlexPoint_MakeGe(pFlex);
	if (!pFlex->m_Flags)
		return;

	assert(HdsCrypto_FlexPoint_Ge & pFlex->m_Flags);
	secp256k1_gej_set_ge(&pFlex->m_Gej, &pFlex->m_Ge);

	pFlex->m_Flags |= HdsCrypto_FlexPoint_Gej;
}

void HdsCrypto_FlexPoint_MakeGe(HdsCrypto_FlexPoint* pFlex)
{
	if (HdsCrypto_FlexPoint_Ge & pFlex->m_Flags)
		return;

	if (HdsCrypto_FlexPoint_Gej & pFlex->m_Flags)
		secp256k1_ge_set_gej_var(&pFlex->m_Ge, &pFlex->m_Gej); // expensive, better to a batch convertion
	else
	{
		if (!(HdsCrypto_FlexPoint_Compact & pFlex->m_Flags))
			return;

		pFlex->m_Flags = 0; // will restore Compact flag iff import is successful

		if (pFlex->m_Compact.m_Y > 1)
			return; // not well-formed

		secp256k1_fe nx;
		if (!secp256k1_fe_set_b32(&nx, pFlex->m_Compact.m_X.m_pVal))
			return; // not well-formed

		if (!secp256k1_ge_set_xo_var(&pFlex->m_Ge, &nx, pFlex->m_Compact.m_Y))
		{
			// be convention zeroed Compact is a zero point
			if (pFlex->m_Compact.m_Y || !IsUintBigZero(&pFlex->m_Compact.m_X))
				return;

			pFlex->m_Ge.infinity = 1; // no specific function like secp256k1_ge_set_infinity
		}

		pFlex->m_Flags = HdsCrypto_FlexPoint_Compact; // restored
	}

	pFlex->m_Flags |= HdsCrypto_FlexPoint_Ge;
}

void HdsCrypto_FlexPoint_MakeGe_Batch(HdsCrypto_FlexPoint* pFlex, unsigned int nCount)
{
	assert(nCount);

	static_assert(sizeof(pFlex->m_Ge) >= sizeof(secp256k1_fe), "Ge is used as a temp placeholder for Fe");
#define FLEX_POINT_TEMP_FE(pt) ((secp256k1_fe*) (&(pt).m_Ge))

	for (unsigned int i = 0; i < nCount; i++)
	{
		assert(HdsCrypto_FlexPoint_Gej == pFlex[i].m_Flags);

		BatchNormalize_Fwd(FLEX_POINT_TEMP_FE(pFlex[i]), i, &pFlex[i].m_Gej, FLEX_POINT_TEMP_FE(pFlex[i - 1]));
	}

	secp256k1_fe zDenom;
	BatchNormalize_Apex(&zDenom, FLEX_POINT_TEMP_FE(pFlex[nCount - 1]), 1);

	for (unsigned int i = nCount; i--; )
	{
		BatchNormalize_Bwd(FLEX_POINT_TEMP_FE(pFlex[i]), i, &pFlex[i].m_Gej, FLEX_POINT_TEMP_FE(pFlex[i - 1]), &zDenom);

		secp256k1_ge_set_gej_normalized(&pFlex[i].m_Ge, &pFlex[i].m_Gej);
		pFlex[i].m_Flags = HdsCrypto_FlexPoint_Ge;
	}

	assert(nCount);
}

void HdsCrypto_MulPoint(HdsCrypto_FlexPoint* pFlex, const HdsCrypto_MultiMac_Secure* pGen, const secp256k1_scalar* pK)
{
	HdsCrypto_MultiMac_Context ctx;
	ctx.m_pRes = &pFlex->m_Gej;
	ctx.m_pZDenom = 0;
	ctx.m_Fast = 0;
	ctx.m_Secure = 1;
	ctx.m_pGenSecure = pGen;
	ctx.m_pSecureK = pK;

	HdsCrypto_MultiMac_Calculate(&ctx);
	pFlex->m_Flags = HdsCrypto_FlexPoint_Gej;
}

void HdsCrypto_MulG(HdsCrypto_FlexPoint* pFlex, const secp256k1_scalar* pK)
{
	HdsCrypto_MulPoint(pFlex, &HdsCrypto_Context_get()->m_GenG, pK);
}

void HdsCrypto_Sk2Pk(HdsCrypto_UintBig* pRes, secp256k1_scalar* pK)
{
	HdsCrypto_FlexPoint fp;
	HdsCrypto_MulG(&fp, pK);

	HdsCrypto_FlexPoint_MakeCompact(&fp);
	assert(HdsCrypto_FlexPoint_Compact & fp.m_Flags);

	*pRes = fp.m_Compact.m_X;

	if (fp.m_Compact.m_Y)
		secp256k1_scalar_negate(pK, pK);
}
//////////////////////////////
// Oracle
void HdsCrypto_Oracle_Init(HdsCrypto_Oracle* p)
{
	secp256k1_sha256_initialize(&p->m_sha);
}

void HdsCrypto_Oracle_Expose(HdsCrypto_Oracle* p, const uint8_t* pPtr, size_t nSize)
{
	secp256k1_sha256_write(&p->m_sha, pPtr, nSize);
}

void HdsCrypto_Oracle_NextHash(HdsCrypto_Oracle* p, HdsCrypto_UintBig* pHash)
{
	secp256k1_sha256_t sha = p->m_sha; // copy
	secp256k1_sha256_finalize(&sha, pHash->m_pVal);

	secp256k1_sha256_write(&p->m_sha, pHash->m_pVal, HdsCrypto_nBytes);
}

void HdsCrypto_Oracle_NextScalar(HdsCrypto_Oracle* p, secp256k1_scalar* pS)
{
	while (1)
	{
		HdsCrypto_UintBig hash;
		HdsCrypto_Oracle_NextHash(p, &hash);

		int overflow;
		secp256k1_scalar_set_b32(pS, hash.m_pVal, &overflow);
		if (!overflow)
			break;
	}
}

void HdsCrypto_Oracle_NextPoint(HdsCrypto_Oracle* p, HdsCrypto_FlexPoint* pFlex)
{
	pFlex->m_Compact.m_Y = 0;

	while (1)
	{
		HdsCrypto_Oracle_NextHash(p, &pFlex->m_Compact.m_X);
		pFlex->m_Flags = HdsCrypto_FlexPoint_Compact;

		HdsCrypto_FlexPoint_MakeGe(pFlex);

		if ((HdsCrypto_FlexPoint_Ge & pFlex->m_Flags) && !secp256k1_ge_is_infinity(&pFlex->m_Ge))
			break;
	}
}

//////////////////////////////
// CoinID
#define HdsCrypto_CoinID_nSubkeyBits 24

int HdsCrypto_CoinID_getSchemeAndSubkey(const HdsCrypto_CoinID* p, uint8_t* pScheme, uint32_t* pSubkey)
{
	*pScheme = (uint8_t) (p->m_SubIdx >> HdsCrypto_CoinID_nSubkeyBits);
	*pSubkey = p->m_SubIdx & ((1U << HdsCrypto_CoinID_nSubkeyBits) - 1);

	if (!*pSubkey)
		return 0; // by convention: up to latest scheme, Subkey=0 - is a master key

	if (HdsCrypto_CoinID_Scheme_BB21 == *pScheme)
		return 0; // BB2.1 workaround

	return 1;
}

#define HASH_WRITE_STR(hash, str) secp256k1_sha256_write(&hash, str, sizeof(str))

void secp256k1_sha256_write_Num(secp256k1_sha256_t* pSha, uint64_t val)
{
	int nContinue;
	do
	{
		uint8_t x = (uint8_t)val;

		nContinue = (val >= 0x80);
		if (nContinue)
		{
			x |= 0x80;
			val >>= 7;
		}

		secp256k1_sha256_write(pSha, &x, sizeof(x));

	} while (nContinue);
}

void secp256k1_sha256_write_CompactPoint(secp256k1_sha256_t* pSha, const HdsCrypto_CompactPoint* pCompact)
{
	secp256k1_sha256_write(pSha, pCompact->m_X.m_pVal, sizeof(pCompact->m_X.m_pVal));
	secp256k1_sha256_write(pSha, &pCompact->m_Y, sizeof(pCompact->m_Y));
}

void secp256k1_sha256_write_Point(secp256k1_sha256_t* pSha, HdsCrypto_FlexPoint* pFlex)
{
	HdsCrypto_FlexPoint_MakeCompact(pFlex);
	assert(HdsCrypto_FlexPoint_Compact & pFlex->m_Flags);
	secp256k1_sha256_write_CompactPoint(pSha, &pFlex->m_Compact);
}

void HdsCrypto_CoinID_getHash(const HdsCrypto_CoinID* p, HdsCrypto_UintBig* pHash)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	uint8_t nScheme;
	uint32_t nSubkey;
	HdsCrypto_CoinID_getSchemeAndSubkey(p, &nScheme, &nSubkey);

	uint32_t nSubIdx = p->m_SubIdx;

	switch (nScheme)
	{
	case HdsCrypto_CoinID_Scheme_BB21:
		// this is actually V0, with a workaround
		nSubIdx = nSubkey | (HdsCrypto_CoinID_Scheme_V0 << HdsCrypto_CoinID_nSubkeyBits);
		nScheme = HdsCrypto_CoinID_Scheme_V0;
		// no break;

	case HdsCrypto_CoinID_Scheme_V0:
		HASH_WRITE_STR(sha, "kid");
		break;

	default:
		HASH_WRITE_STR(sha, "kidv-1");
	}

	secp256k1_sha256_write_Num(&sha, p->m_Idx);
	secp256k1_sha256_write_Num(&sha, p->m_Type);
	secp256k1_sha256_write_Num(&sha, nSubIdx);

	if (nScheme >= HdsCrypto_CoinID_Scheme_V1)
	{
		// newer scheme - account for the Value and Asset.
		secp256k1_sha256_write_Num(&sha, p->m_Amount);

		if (p->m_AssetID)
		{
			HASH_WRITE_STR(sha, "asset");
			secp256k1_sha256_write_Num(&sha, p->m_AssetID);
		}
	}

	secp256k1_sha256_finalize(&sha, pHash->m_pVal);
}

//////////////////////////////
// Kdf
void HdsCrypto_Kdf_Init(HdsCrypto_Kdf* p, const HdsCrypto_UintBig* pSeed)
{
	static const char szSalt[] = "hds-HKdf";

	HdsCrypto_NonceGenerator ng1, ng2;
	HdsCrypto_NonceGenerator_Init(&ng1, szSalt, sizeof(szSalt), pSeed);
	ng2 = ng1;

	static const char szCtx1[] = "gen";
	static const char szCtx2[] = "coF";

	ng1.m_pContext = szCtx1;
	ng1.m_nContext = sizeof(szCtx1);

	HdsCrypto_NonceGenerator_NextOkm(&ng1);
	p->m_Secret = ng1.m_Okm;

	ng2.m_pContext = szCtx2;
	ng2.m_nContext = sizeof(szCtx2);
	HdsCrypto_NonceGenerator_NextScalar(&ng2, &p->m_kCoFactor);

	SECURE_ERASE_OBJ(ng1);
	SECURE_ERASE_OBJ(ng2);
}

void HdsCrypto_Kdf_Derive_PKey(const HdsCrypto_Kdf* p, const HdsCrypto_UintBig* pHv, secp256k1_scalar* pK)
{
	static const char szSalt[] = "hds-Key";

	HdsCrypto_NonceGenerator ng;
	secp256k1_hmac_sha256_t hmac;
	HdsCrypto_NonceGenerator_InitBegin(&ng, &hmac, szSalt, sizeof(szSalt));

	secp256k1_hmac_sha256_write(&hmac, p->m_Secret.m_pVal, sizeof(p->m_Secret.m_pVal));
	secp256k1_hmac_sha256_write(&hmac, pHv->m_pVal, sizeof(pHv->m_pVal));

	HdsCrypto_NonceGenerator_InitEnd(&ng, &hmac);

	HdsCrypto_NonceGenerator_NextScalar(&ng, pK);

	SECURE_ERASE_OBJ(ng);
}

void HdsCrypto_Kdf_Derive_SKey(const HdsCrypto_Kdf* p, const HdsCrypto_UintBig* pHv, secp256k1_scalar* pK)
{
	HdsCrypto_Kdf_Derive_PKey(p, pHv, pK);
	secp256k1_scalar_mul(pK, pK, &p->m_kCoFactor);
}

#define ARRAY_ELEMENT_SAFE(arr, index) ((arr)[(((index) < _countof(arr)) ? (index) : (_countof(arr) - 1))])
#define FOURCC_FROM_BYTES(a, b, c, d) (((((((uint32_t) a << 8) | (uint32_t) b) << 8) | (uint32_t) c) << 8) | (uint32_t) d)
#define FOURCC_FROM_STR(name) FOURCC_FROM_BYTES(ARRAY_ELEMENT_SAFE(#name,0), ARRAY_ELEMENT_SAFE(#name,1), ARRAY_ELEMENT_SAFE(#name,2), ARRAY_ELEMENT_SAFE(#name,3))

void HdsCrypto_Kdf_getChild(HdsCrypto_Kdf* p, uint32_t iChild, const HdsCrypto_Kdf* pParent)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "kid");

	const uint32_t nType = FOURCC_FROM_STR(SubK);

	secp256k1_sha256_write_Num(&sha, iChild);
	secp256k1_sha256_write_Num(&sha, nType);
	secp256k1_sha256_write_Num(&sha, 0);

	HdsCrypto_UintBig hv;
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	secp256k1_scalar sk;
	HdsCrypto_Kdf_Derive_SKey(pParent, &hv, &sk);

	secp256k1_scalar_get_b32(hv.m_pVal, &sk);
	SECURE_ERASE_OBJ(sk);

	HdsCrypto_Kdf_Init(p, &hv);
	SECURE_ERASE_OBJ(hv);
}

//////////////////////////////
// Kdf - CoinID key derivation
void HdsCrypto_CoinID_getSk(const HdsCrypto_Kdf* pKdf, const HdsCrypto_CoinID* pCid, secp256k1_scalar* pK)
{
	HdsCrypto_CoinID_getSkComm(pKdf, pCid, pK, 0);
}

void HdsCrypto_CoinID_getSkComm(const HdsCrypto_Kdf* pKdf, const HdsCrypto_CoinID* pCid, secp256k1_scalar* pK, HdsCrypto_FlexPoint* pComm)
{
	HdsCrypto_FlexPoint pFlex[2];

	union
	{
		// save some space
		struct
		{
			uint8_t nScheme;
			uint32_t nSubkey;
			HdsCrypto_UintBig hv;
			HdsCrypto_Kdf kdfC;
		} k;

		struct
		{
			HdsCrypto_Oracle oracle;
			secp256k1_scalar k1;
		} o;

		struct
		{
			HdsCrypto_MultiMac_Scalar s;
			HdsCrypto_MultiMac_WNaf wnaf;
			HdsCrypto_MultiMac_Fast genAsset;
			secp256k1_fe zDenom;
		} mm;

	} u;

	int nChild = HdsCrypto_CoinID_getSchemeAndSubkey(pCid, &u.k.nScheme, &u.k.nSubkey);
	if (nChild)
	{
		HdsCrypto_Kdf_getChild(&u.k.kdfC, u.k.nSubkey, pKdf);
		pKdf = &u.k.kdfC;
	}

	HdsCrypto_CoinID_getHash(pCid, &u.k.hv);

	HdsCrypto_Kdf_Derive_SKey(pKdf, &u.k.hv, pK);

	if (nChild)
		SECURE_ERASE_OBJ(u.k.kdfC);

	HdsCrypto_Context* pCtx = HdsCrypto_Context_get();


	// sk*G + v*H
	HdsCrypto_MultiMac_Context mmCtx;
	mmCtx.m_pRes = &pFlex[0].m_Gej;
	mmCtx.m_Secure = 1;
	mmCtx.m_pSecureK = pK;
	mmCtx.m_pGenSecure = &pCtx->m_GenG;
	mmCtx.m_Fast = 1;
	mmCtx.m_pS = &u.mm.s;
	mmCtx.m_pWnaf = &u.mm.wnaf;

	if (pCid->m_AssetID)
	{
		// derive asset gen
		HdsCrypto_Oracle_Init(&u.o.oracle);

		HASH_WRITE_STR(u.o.oracle.m_sha, "B.Asset.Gen.V1");
		secp256k1_sha256_write_Num(&u.o.oracle.m_sha, pCid->m_AssetID);

		HdsCrypto_FlexPoint fpAsset;
		HdsCrypto_Oracle_NextPoint(&u.o.oracle, &fpAsset);

		mmCtx.m_pGenFast = &u.mm.genAsset;
		mmCtx.m_pZDenom = &u.mm.zDenom;

		HdsCrypto_MultiMac_SetCustom_Nnz(&mmCtx, &fpAsset);

	}
	else
	{
		mmCtx.m_pGenFast = pCtx->m_pGenFast + HdsCrypto_MultiMac_Fast_Idx_H;
		mmCtx.m_pZDenom = 0;
	}

	secp256k1_scalar_set_u64(u.mm.s.m_pK, pCid->m_Amount);

	HdsCrypto_MultiMac_Calculate(&mmCtx);
	pFlex[0].m_Flags = HdsCrypto_FlexPoint_Gej;

	// sk * J
	mmCtx.m_pRes = &pFlex[1].m_Gej;
	mmCtx.m_pGenSecure = &pCtx->m_GenJ;
	mmCtx.m_pZDenom = 0;
	mmCtx.m_Fast = 0;

	HdsCrypto_MultiMac_Calculate(&mmCtx);
	pFlex[1].m_Flags = HdsCrypto_FlexPoint_Gej;

	// adjust sk
	HdsCrypto_FlexPoint_MakeGe_Batch(pFlex, _countof(pFlex));

	HdsCrypto_Oracle_Init(&u.o.oracle);

	for (unsigned int i = 0; i < _countof(pFlex); i++)
		secp256k1_sha256_write_Point(&u.o.oracle.m_sha, pFlex + i);

	HdsCrypto_Oracle_NextScalar(&u.o.oracle, &u.o.k1);

	secp256k1_scalar_add(pK, pK, &u.o.k1);

	if (pComm)
	{
		mmCtx.m_pGenSecure = &pCtx->m_GenG; // not really secure here, just no good reason to have additional non-secure J-gen
		mmCtx.m_pSecureK = &u.o.k1;

		HdsCrypto_MultiMac_Calculate(&mmCtx);
		pFlex[1].m_Flags = HdsCrypto_FlexPoint_Gej;

		assert(HdsCrypto_FlexPoint_Ge & pFlex[0].m_Flags);

		secp256k1_gej_add_ge_var(&pComm->m_Gej, &pFlex[1].m_Gej, &pFlex[0].m_Ge, 0);
		pComm->m_Flags = HdsCrypto_FlexPoint_Gej;
	}
}

//////////////////////////////
// RangeProof

static void WriteInNetworkOrder(uint8_t** ppDst, uint64_t val, unsigned int nLen)
{
	for (unsigned int i = 0; i < nLen; i++, val >>= 8)
	{
		--*ppDst;
		**ppDst = (uint8_t) val;
	}
}

typedef struct
{
	HdsCrypto_RangeProof* m_pRangeProof;
	HdsCrypto_NonceGenerator m_NonceGen; // 88 bytes
	secp256k1_gej m_pGej[2]; // 248 bytes

	// 97 bytes. This can be saved, at expense of calculating them again (HdsCrypto_CoinID_getSkComm)
	secp256k1_scalar m_sk;
	secp256k1_scalar m_alpha;
	HdsCrypto_CompactPoint m_Commitment;

} HdsCrypto_RangeProof_Worker;

static void HdsCrypto_RangeProof_Calculate_Before_S(HdsCrypto_RangeProof_Worker* pWrk)
{
	const HdsCrypto_RangeProof* p = pWrk->m_pRangeProof;

	HdsCrypto_FlexPoint fp;
	HdsCrypto_CoinID_getSkComm(p->m_pKdf, &p->m_Cid, &pWrk->m_sk, &fp);

	HdsCrypto_FlexPoint_MakeCompact(&fp);
	assert(HdsCrypto_FlexPoint_Compact & fp.m_Flags);
	pWrk->m_Commitment = fp.m_Compact;

	// get seed
	HdsCrypto_Oracle oracle;
	secp256k1_sha256_initialize(&oracle.m_sha);
	secp256k1_sha256_write_Point(&oracle.m_sha, &fp);

	HdsCrypto_UintBig hv;
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);

	secp256k1_scalar k;
	HdsCrypto_Kdf_Derive_PKey(p->m_pKdf, &hv, &k);
	secp256k1_scalar_get_b32(hv.m_pVal, &k);

	secp256k1_sha256_initialize(&oracle.m_sha);
	secp256k1_sha256_write(&oracle.m_sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_finalize(&oracle.m_sha, hv.m_pVal);

	// NonceGen
	static const char szSalt[] = "bulletproof";
	HdsCrypto_NonceGenerator_Init(&pWrk->m_NonceGen, szSalt, sizeof(szSalt), &hv);

	HdsCrypto_NonceGenerator_NextScalar(&pWrk->m_NonceGen, &pWrk->m_alpha); // alpha

	// embed params into alpha
	uint8_t* pPtr = hv.m_pVal + HdsCrypto_nBytes;
	WriteInNetworkOrder(&pPtr, p->m_Cid.m_Amount, sizeof(p->m_Cid.m_Amount));
	WriteInNetworkOrder(&pPtr, p->m_Cid.m_SubIdx, sizeof(p->m_Cid.m_SubIdx));
	WriteInNetworkOrder(&pPtr, p->m_Cid.m_Type, sizeof(p->m_Cid.m_Type));
	WriteInNetworkOrder(&pPtr, p->m_Cid.m_Idx, sizeof(p->m_Cid.m_Idx));
	WriteInNetworkOrder(&pPtr, p->m_Cid.m_AssetID, sizeof(p->m_Cid.m_AssetID));
	memset(hv.m_pVal, 0, pPtr - hv.m_pVal); // padding

	int overflow;
	secp256k1_scalar_set_b32(&k, hv.m_pVal, &overflow);
	assert(!overflow);

	secp256k1_scalar_add(&pWrk->m_alpha, &pWrk->m_alpha, &k);
}


#define nDims (sizeof(HdsCrypto_Amount) * 8)

static void HdsCrypto_RangeProof_Calculate_S(HdsCrypto_RangeProof_Worker* pWrk)
{
	// Data buffers needed for calculating Part1.S
	// Need to multi-exponentiate nDims * 2 == 128 elements.
	// Calculating everything in a single pass is faster, but requires more buffers (stack memory)
	// Each element size is sizeof(HdsCrypto_MultiMac_Scalar) + sizeof(HdsCrypto_MultiMac_WNaf),
	// which is either 34 or 68 bytes, depends on HdsCrypto_MultiMac_Directions (larger size is for faster algorithm)
	//
	// This requires 8.5K stack memory (or 4.25K if HdsCrypto_MultiMac_Directions == 1)
#define Calc_S_Naggle_Max (nDims * 2)

#define Calc_S_Naggle Calc_S_Naggle_Max // currently using max

	static_assert(Calc_S_Naggle <= Calc_S_Naggle_Max, "Naggle too large");

	HdsCrypto_MultiMac_Scalar pS[Calc_S_Naggle];
	HdsCrypto_MultiMac_WNaf pWnaf[Calc_S_Naggle];

	// Try to avoid local vars, save as much stack as possible

	secp256k1_scalar ro;
	HdsCrypto_NonceGenerator_NextScalar(&pWrk->m_NonceGen, &ro);

	HdsCrypto_MultiMac_Context mmCtx;
	mmCtx.m_pZDenom = 0;

	mmCtx.m_Secure = 1;
	mmCtx.m_pSecureK = &ro;
	mmCtx.m_pGenSecure = &HdsCrypto_Context_get()->m_GenG;

	mmCtx.m_Fast = 0;
	mmCtx.m_pGenFast = HdsCrypto_Context_get()->m_pGenFast;
	mmCtx.m_pS = pS;
	mmCtx.m_pWnaf = pWnaf;

	for (unsigned int iBit = 0; iBit < nDims * 2; iBit++, mmCtx.m_Fast++)
	{
		if (Calc_S_Naggle == mmCtx.m_Fast)
		{
			// flush
			mmCtx.m_pRes = pWrk->m_pGej + (iBit != Calc_S_Naggle); // 1st flush goes to pGej[0] directly
			HdsCrypto_MultiMac_Calculate(&mmCtx);

			if (iBit != Calc_S_Naggle)
				secp256k1_gej_add_var(pWrk->m_pGej, pWrk->m_pGej + 1, pWrk->m_pGej, 0);

			mmCtx.m_Secure = 0;
			mmCtx.m_Fast = 0;
			mmCtx.m_pGenFast += Calc_S_Naggle;
		}

		HdsCrypto_NonceGenerator_NextScalar(&pWrk->m_NonceGen, pS[mmCtx.m_Fast].m_pK);

		if (!(iBit % nDims) && pWrk->m_pRangeProof->m_pKExtra)
			// embed more info
			secp256k1_scalar_add(pS[mmCtx.m_Fast].m_pK, pS[mmCtx.m_Fast].m_pK, pWrk->m_pRangeProof->m_pKExtra + (iBit / nDims));
	}

	mmCtx.m_pRes = pWrk->m_pGej + 1;
	HdsCrypto_MultiMac_Calculate(&mmCtx);

	if (Calc_S_Naggle < Calc_S_Naggle_Max)
		secp256k1_gej_add_var(pWrk->m_pGej + 1, pWrk->m_pGej + 1, pWrk->m_pGej, 0);
}

static int HdsCrypto_RangeProof_Calculate_After_S(HdsCrypto_RangeProof_Worker* pWrk)
{
	HdsCrypto_RangeProof* p = pWrk->m_pRangeProof;
	HdsCrypto_Context* pCtx = HdsCrypto_Context_get();

	secp256k1_scalar pK[2];

	HdsCrypto_Oracle oracle;
	secp256k1_scalar pChallenge[2];
	HdsCrypto_UintBig hv;
	secp256k1_hmac_sha256_t hmac;

	HdsCrypto_FlexPoint pFp[2]; // 496 bytes
	pFp[1].m_Gej = pWrk->m_pGej[1];
	pFp[1].m_Flags = HdsCrypto_FlexPoint_Gej;

	// CalcA
	HdsCrypto_MultiMac_Context mmCtx;
	mmCtx.m_pZDenom = 0;
	mmCtx.m_Fast = 0;
	mmCtx.m_Secure = 1;
	mmCtx.m_pSecureK = &pWrk->m_alpha;
	mmCtx.m_pGenSecure = &pCtx->m_GenG;
	mmCtx.m_pRes = &pFp[0].m_Gej;

	HdsCrypto_MultiMac_Calculate(&mmCtx); // alpha*G
	pFp[0].m_Flags = HdsCrypto_FlexPoint_Gej;

	HdsCrypto_Amount v = p->m_Cid.m_Amount;

	for (uint32_t i = 0; i < nDims; i++)
	{
		if (1 & (v >> i))
			secp256k1_ge_from_storage(&pFp[0].m_Ge, pCtx->m_pGenFast[i].m_pPt);
		else
		{
			secp256k1_ge_from_storage(&pFp[0].m_Ge, pCtx->m_pGenFast[nDims + i].m_pPt);
			secp256k1_ge_neg(&pFp[0].m_Ge, &pFp[0].m_Ge);
		}

		secp256k1_gej_add_ge_var(&pFp[0].m_Gej, &pFp[0].m_Gej, &pFp[0].m_Ge, 0);
	}

	// normalize A,S at once, feed them to Oracle
	HdsCrypto_FlexPoint_MakeGe_Batch(pFp, _countof(pFp));

	HdsCrypto_Oracle_Init(&oracle);
	secp256k1_sha256_write_Num(&oracle.m_sha, 0); // incubation time, must be zero
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &pWrk->m_Commitment); // starting from Fork1, earlier schem is not allowed

	for (unsigned int i = 0; i < 2; i++)
		secp256k1_sha256_write_Point(&oracle.m_sha, pFp + i);

	// get challenges. Use the challenges, sk, T1 and T2 to init the NonceGen for blinding the sk
	static const char szSalt[] = "bulletproof-sk";
	HdsCrypto_NonceGenerator_InitBegin(&pWrk->m_NonceGen, &hmac, szSalt, sizeof(szSalt));

	secp256k1_scalar_get_b32(hv.m_pVal, &pWrk->m_sk);
	secp256k1_hmac_sha256_write(&hmac, hv.m_pVal, sizeof(hv.m_pVal));

	for (unsigned int i = 0; i < 2; i++)
	{
		secp256k1_hmac_sha256_write(&hmac, p->m_pT[i].m_X.m_pVal, sizeof(p->m_pT[i].m_X.m_pVal));
		secp256k1_hmac_sha256_write(&hmac, &p->m_pT[i].m_Y, sizeof(p->m_pT[i].m_Y));

		HdsCrypto_Oracle_NextScalar(&oracle, pChallenge); // challenges y,z. The 'y' is not needed, will be overwritten by 'z'.
		secp256k1_scalar_get_b32(hv.m_pVal, pChallenge);
		secp256k1_hmac_sha256_write(&hmac, hv.m_pVal, sizeof(hv.m_pVal));
	}

	int ok = 1;

	HdsCrypto_NonceGenerator_InitEnd(&pWrk->m_NonceGen, &hmac);

	for (unsigned int i = 0; i < 2; i++)
	{
		HdsCrypto_NonceGenerator_NextScalar(&pWrk->m_NonceGen, pK + i); // tau1/2
		mmCtx.m_pSecureK = pK + i;
		mmCtx.m_pRes = pWrk->m_pGej;

		HdsCrypto_MultiMac_Calculate(&mmCtx); // pub nonces of T1/T2

		pFp[i].m_Compact = p->m_pT[i];
		pFp[i].m_Flags = HdsCrypto_FlexPoint_Compact;
		HdsCrypto_FlexPoint_MakeGe(pFp + i);
		if (!pFp[i].m_Flags)
		{
			ok = 0;
			break;
		}

		secp256k1_gej_add_ge_var(&pFp[i].m_Gej, mmCtx.m_pRes, &pFp[i].m_Ge, 0);
		pFp[i].m_Flags = HdsCrypto_FlexPoint_Gej;
	}

	SECURE_ERASE_OBJ(pWrk->m_NonceGen);

	if (ok)
	{
		// normalize & expose
		HdsCrypto_FlexPoint_MakeGe_Batch(pFp, _countof(pFp));

		for (unsigned int i = 0; i < 2; i++)
		{
			secp256k1_sha256_write_Point(&oracle.m_sha, pFp + i);
			assert(HdsCrypto_FlexPoint_Compact & pFp[i].m_Flags);
			p->m_pT[i] = pFp[i].m_Compact;
		}

		// last challenge
		HdsCrypto_Oracle_NextScalar(&oracle, pChallenge + 1);

		// m_TauX = tau2*x^2 + tau1*x + sk*z^2
		secp256k1_scalar_mul(pK, pK, pChallenge + 1); // tau1*x
		secp256k1_scalar_mul(pChallenge + 1, pChallenge + 1, pChallenge + 1); // x^2
		secp256k1_scalar_mul(pK + 1, pK + 1, pChallenge + 1); // tau2*x^2

		secp256k1_scalar_mul(pChallenge, pChallenge, pChallenge); // z^2

		secp256k1_scalar_mul(&p->m_TauX, &pWrk->m_sk, pChallenge); // sk*z^2
		secp256k1_scalar_add(&p->m_TauX, &p->m_TauX, pK);
		secp256k1_scalar_add(&p->m_TauX, &p->m_TauX, pK + 1);
	}

	SECURE_ERASE_OBJ(pWrk->m_sk);
	SECURE_ERASE_OBJ(pK); // tau1/2
	//SECURE_ERASE_OBJ(hv); - no need, last value is the challenge

	return ok;
}


int HdsCrypto_RangeProof_Calculate(HdsCrypto_RangeProof* p)
{
	HdsCrypto_RangeProof_Worker wrk;
	wrk.m_pRangeProof = p;

	HdsCrypto_RangeProof_Calculate_Before_S(&wrk);
	HdsCrypto_RangeProof_Calculate_S(&wrk);
	return HdsCrypto_RangeProof_Calculate_After_S(&wrk);
}

//////////////////////////////
// Signature
void HdsCrypto_Signature_GetChallenge(const HdsCrypto_Signature* p, const HdsCrypto_UintBig* pMsg, secp256k1_scalar* pE)
{
	HdsCrypto_Oracle oracle;
	HdsCrypto_Oracle_Init(&oracle);
	secp256k1_sha256_write_CompactPoint(&oracle.m_sha, &p->m_NoncePub);
	secp256k1_sha256_write(&oracle.m_sha, pMsg->m_pVal, sizeof(pMsg->m_pVal));

	HdsCrypto_Oracle_NextScalar(&oracle, pE);
}

void HdsCrypto_Signature_Sign(HdsCrypto_Signature* p, const HdsCrypto_UintBig* pMsg, const secp256k1_scalar* pSk)
{
	// get nonce
	secp256k1_hmac_sha256_t hmac;
	HdsCrypto_NonceGenerator ng;
	static const char szSalt[] = "hds-Schnorr";
	HdsCrypto_NonceGenerator_InitBegin(&ng, &hmac, szSalt, sizeof(szSalt));

	union
	{
		HdsCrypto_UintBig sk;
		secp256k1_scalar nonce;
	} u;

	static_assert(sizeof(u.nonce) >= sizeof(u.sk), ""); // means nonce completely overwrites the sk

	secp256k1_scalar_get_b32(u.sk.m_pVal, pSk);
	secp256k1_hmac_sha256_write(&hmac, u.sk.m_pVal, sizeof(u.sk.m_pVal));
	secp256k1_hmac_sha256_write(&hmac, pMsg->m_pVal, sizeof(pMsg->m_pVal));

	HdsCrypto_NonceGenerator_InitEnd(&ng, &hmac);
	HdsCrypto_NonceGenerator_NextScalar(&ng, &u.nonce);
	SECURE_ERASE_OBJ(ng);

	// expose the nonce
	HdsCrypto_FlexPoint fp;
	HdsCrypto_MulG(&fp, &u.nonce);
	HdsCrypto_FlexPoint_MakeCompact(&fp);
	p->m_NoncePub = fp.m_Compact;

	HdsCrypto_Signature_SignPartial(p, pMsg, pSk, &u.nonce);

	SECURE_ERASE_OBJ(u.nonce);
}

void HdsCrypto_Signature_SignPartial(HdsCrypto_Signature* p, const HdsCrypto_UintBig* pMsg, const secp256k1_scalar* pSk, const secp256k1_scalar* pNonce)
{
	secp256k1_scalar e;
	HdsCrypto_Signature_GetChallenge(p, pMsg, &e);

	secp256k1_scalar_mul(&e, &e, pSk);
	secp256k1_scalar_add(&e, &e, pNonce);
	secp256k1_scalar_negate(&e, &e);

	secp256k1_scalar_get_b32(p->m_k.m_pVal, &e);
}

int HdsCrypto_Signature_IsValid(const HdsCrypto_Signature* p, const HdsCrypto_UintBig* pMsg, HdsCrypto_FlexPoint* pPk)
{
	HdsCrypto_FlexPoint fpNonce;
	fpNonce.m_Compact = p->m_NoncePub;
	fpNonce.m_Flags = HdsCrypto_FlexPoint_Compact;
	
	HdsCrypto_FlexPoint_MakeGe(&fpNonce);
	if (!fpNonce.m_Flags)
		return 0;

	secp256k1_scalar k;
	int overflow; // for historical reasons we don't check for overflow, i.e. theoretically there can be an ambiguity, but it makes not much sense for the attacker
	secp256k1_scalar_set_b32(&k, p->m_k.m_pVal, &overflow);


	HdsCrypto_FlexPoint_MakeGej(pPk);
	if (!pPk->m_Flags)
		return 0; // bad Pubkey

	secp256k1_gej gej;
	secp256k1_fe zDenom;

	HdsCrypto_MultiMac_WNaf wnaf;
	HdsCrypto_MultiMac_Scalar s;
	HdsCrypto_MultiMac_Fast gen;

	HdsCrypto_MultiMac_Context ctx;
	ctx.m_pRes = &gej;
	ctx.m_Secure = 1;
	ctx.m_pGenSecure = &HdsCrypto_Context_get()->m_GenG;
	ctx.m_pSecureK = &k;

	if (secp256k1_gej_is_infinity(&pPk->m_Gej))
	{
		// unlikely, but allowed for historical reasons
		ctx.m_Fast = 0;
		ctx.m_pZDenom = 0;
	}
	else
	{
		ctx.m_pZDenom = &zDenom;
		ctx.m_Fast = 1;
		ctx.m_pGenFast = &gen;
		ctx.m_pS = &s;
		ctx.m_pWnaf = &wnaf;
		HdsCrypto_MultiMac_SetCustom_Nnz(&ctx, pPk);

		HdsCrypto_Signature_GetChallenge(p, pMsg, s.m_pK);
	}

	HdsCrypto_MultiMac_Calculate(&ctx);
	secp256k1_gej_add_ge_var(&gej, &gej, &fpNonce.m_Ge, 0);

	return secp256k1_gej_is_infinity(&gej);
}

//////////////////////////////
// TxKernel
void HdsCrypto_TxKernel_getID(const HdsCrypto_TxKernel* pKrn, HdsCrypto_UintBig* pMsg)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	secp256k1_sha256_write_Num(&sha, pKrn->m_Fee);
	secp256k1_sha256_write_Num(&sha, pKrn->m_hMin);
	secp256k1_sha256_write_Num(&sha, pKrn->m_hMax);

	secp256k1_sha256_write_CompactPoint(&sha, &pKrn->m_Commitment);
	secp256k1_sha256_write_Num(&sha, 0); // former m_AssetEmission

	uint8_t nFlags = 0; // extended flags, irrelevent for HW wallet
	secp256k1_sha256_write(&sha, &nFlags, sizeof(nFlags));

	nFlags = 1; // no more nested kernels
	secp256k1_sha256_write(&sha, &nFlags, sizeof(nFlags));

	secp256k1_sha256_finalize(&sha, pMsg->m_pVal);
}

int HdsCrypto_TxKernel_IsValid(const HdsCrypto_TxKernel* pKrn)
{
	HdsCrypto_UintBig msg;
	HdsCrypto_TxKernel_getID(pKrn, &msg);

	HdsCrypto_FlexPoint fp;
	fp.m_Compact = pKrn->m_Commitment;
	fp.m_Flags = HdsCrypto_FlexPoint_Compact;

	return HdsCrypto_Signature_IsValid(&pKrn->m_Signature, &msg, &fp);
}

//////////////////////////////
// KeyKeeper - pub Kdf export
static void Kdf2Pub(const HdsCrypto_Kdf* pKdf, HdsCrypto_KdfPub* pRes)
{
	HdsCrypto_Context* pCtx = HdsCrypto_Context_get();

	pRes->m_Secret = pKdf->m_Secret;

	HdsCrypto_FlexPoint fp;

	HdsCrypto_MulPoint(&fp, &pCtx->m_GenG, &pKdf->m_kCoFactor);
	HdsCrypto_FlexPoint_MakeCompact(&fp);
	pRes->m_CoFactorG = fp.m_Compact;

	HdsCrypto_MulPoint(&fp, &pCtx->m_GenJ, &pKdf->m_kCoFactor);
	HdsCrypto_FlexPoint_MakeCompact(&fp);
	pRes->m_CoFactorJ = fp.m_Compact;
}

void HdsCrypto_KeyKeeper_GetPKdf(const HdsCrypto_KeyKeeper* p, HdsCrypto_KdfPub* pRes, const uint32_t* pChild)
{
	if (pChild)
	{
		HdsCrypto_Kdf kdfChild;
		HdsCrypto_Kdf_getChild(&kdfChild, *pChild, &p->m_MasterKey);
		Kdf2Pub(&kdfChild, pRes);
	}
	else
		Kdf2Pub(&p->m_MasterKey, pRes);
}

//////////////////////////////
// KeyKeeper - transaction common. Aggregation
typedef struct
{
	HdsCrypto_Amount m_Hdss;
	HdsCrypto_Amount m_Assets;

} TxAggr0;

typedef struct
{
	TxAggr0 m_Ins;
	TxAggr0 m_Outs;

	HdsCrypto_AssetID m_AssetID;
	secp256k1_scalar m_sk;

} TxAggr;


static int TxAggregate0(const HdsCrypto_KeyKeeper* p, const HdsCrypto_CoinID* pCid, unsigned int nCount, TxAggr0* pRes, TxAggr* pCommon, int isOuts)
{
	for (unsigned int i = 0; i < nCount; i++)
	{
		uint8_t nScheme;
		uint32_t nSubkey;
		HdsCrypto_CoinID_getSchemeAndSubkey(pCid + i, &nScheme, &nSubkey);

		if (nSubkey && isOuts)
			return 0; // HW wallet should not send funds to child subkeys (potentially belonging to miners)

		switch (nScheme)
		{
		case HdsCrypto_CoinID_Scheme_V0:
		case HdsCrypto_CoinID_Scheme_BB21:
			// weak schemes
			if (isOuts)
				return 0; // no reason to create weak outputs

			if (!p->m_AllowWeakInputs)
				return 0;
		}

		HdsCrypto_Amount* pVal;
		if (pCid[i].m_AssetID)
		{
			if (pCommon->m_AssetID)
			{
				if (pCommon->m_AssetID != pCid[i].m_AssetID)
					return 0; // multiple assets are not allowed
			}
			else
				pCommon->m_AssetID = pCid[i].m_AssetID;

			pVal = &pRes->m_Assets;
		}
		else
			pVal = &pRes->m_Hdss;

		HdsCrypto_Amount val = *pVal;
		(*pVal) += pCid[i].m_Amount;

		if (val > (*pVal))
			return 0; // overflow

		secp256k1_scalar sk;
		HdsCrypto_CoinID_getSk(&p->m_MasterKey, pCid + i, &sk);

		secp256k1_scalar_add(&pCommon->m_sk, &pCommon->m_sk, &sk);
		SECURE_ERASE_OBJ(sk);
	}

	return 1;
}

static int TxAggregate(const HdsCrypto_KeyKeeper* p, const HdsCrypto_TxCommon* pTx, TxAggr* pRes)
{
	memset(pRes, 0, sizeof(*pRes));

	if (!TxAggregate0(p, pTx->m_pIns, pTx->m_Ins, &pRes->m_Ins, pRes, 0))
		return 0;

	secp256k1_scalar_negate(&pRes->m_sk, &pRes->m_sk);

	return TxAggregate0(p, pTx->m_pOuts, pTx->m_Outs, &pRes->m_Outs, pRes, 1);
}

static void TxAggrToOffset(TxAggr* pAggr, const secp256k1_scalar* pKrn, HdsCrypto_TxCommon* pTx)
{
	secp256k1_scalar_add(&pAggr->m_sk, &pAggr->m_sk, pKrn);
	secp256k1_scalar_negate(&pAggr->m_sk, &pAggr->m_sk);
	secp256k1_scalar_get_b32(pTx->m_kOffset.m_pVal, &pAggr->m_sk);
}

static void TxImportSubtract(secp256k1_scalar* pK, const HdsCrypto_UintBig* pPrev)
{
	secp256k1_scalar kPeer;
	int overflow;
	secp256k1_scalar_set_b32(&kPeer, pPrev->m_pVal, &overflow);
	secp256k1_scalar_negate(&kPeer, &kPeer);
	secp256k1_scalar_add(pK, pK, &kPeer);
}

//////////////////////////////
// KeyKeeper - user permission required
static int HdsCrypto_KeyKeeper_ConfirmSpend(HdsCrypto_Amount val, HdsCrypto_AssetID aid, const HdsCrypto_UintBig* pPeerID, const HdsCrypto_TxKernel* pKrn, const HdsCrypto_UintBig* pKrnID)
{
	// pPeerID is NULL, if it's a Split tx.
	// pKrnID may be NULL, if this is a 'preliminary' confirmation (SendTx 1st invocation)

	return HdsCrypto_KeyKeeper_Status_Ok; // TODO
}

//////////////////////////////
// KeyKeeper - Kernel modification
static int KernelUpdateKeys(HdsCrypto_TxKernel* pKrn, const secp256k1_scalar* pSk, const secp256k1_scalar* pNonce, int nAdd)
{
	HdsCrypto_FlexPoint pFp[2];

	HdsCrypto_MulG(pFp, pSk);
	HdsCrypto_MulG(pFp + 1, pNonce);

	if (nAdd)
	{
		HdsCrypto_FlexPoint fp;
		fp.m_Compact = pKrn->m_Commitment;
		fp.m_Flags = HdsCrypto_FlexPoint_Compact;

		HdsCrypto_FlexPoint_MakeGe(&fp);
		if (!fp.m_Flags)
			return 0;

		secp256k1_gej_add_ge_var(&pFp[0].m_Gej, &pFp[0].m_Gej, &fp.m_Ge, 0);

		fp.m_Compact = pKrn->m_Signature.m_NoncePub;
		fp.m_Flags = HdsCrypto_FlexPoint_Compact;

		HdsCrypto_FlexPoint_MakeGe(&fp);
		if (!fp.m_Flags)
			return 0;

		secp256k1_gej_add_ge_var(&pFp[1].m_Gej, &pFp[1].m_Gej, &fp.m_Ge, 0);
	}

	HdsCrypto_FlexPoint_MakeGe_Batch(pFp, _countof(pFp));

	HdsCrypto_FlexPoint_MakeCompact(pFp);
	pKrn->m_Commitment = pFp[0].m_Compact;

	HdsCrypto_FlexPoint_MakeCompact(pFp + 1);
	pKrn->m_Signature.m_NoncePub = pFp[1].m_Compact;

	return 1;
}

//////////////////////////////
// KeyKeeper - SplitTx
int HdsCrypto_KeyKeeper_SignTx_Split(const HdsCrypto_KeyKeeper* p, HdsCrypto_TxCommon* pTx)
{
	TxAggr txAggr;
	if (!TxAggregate(p, pTx, &txAggr))
		return HdsCrypto_KeyKeeper_Status_Unspecified;

	if (txAggr.m_Ins.m_Assets != txAggr.m_Outs.m_Assets)
		return HdsCrypto_KeyKeeper_Status_Unspecified;
	if (txAggr.m_Ins.m_Hdss < txAggr.m_Outs.m_Hdss)
		return HdsCrypto_KeyKeeper_Status_Unspecified;
	if (txAggr.m_Ins.m_Hdss - txAggr.m_Outs.m_Hdss != pTx->m_Krn.m_Fee)
		return HdsCrypto_KeyKeeper_Status_Unspecified;

	// hash all visible params
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	secp256k1_sha256_write_Num(&sha, pTx->m_Krn.m_hMin);
	secp256k1_sha256_write_Num(&sha, pTx->m_Krn.m_hMax);
	secp256k1_sha256_write_Num(&sha, pTx->m_Krn.m_Fee);

	HdsCrypto_UintBig hv;
	secp256k1_scalar_get_b32(hv.m_pVal, &txAggr.m_sk);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	// derive keys
	static const char szSalt[] = "hw-wlt-split";
	HdsCrypto_NonceGenerator ng;
	HdsCrypto_NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &hv);

	secp256k1_scalar kKrn, kNonce;
	HdsCrypto_NonceGenerator_NextScalar(&ng, &kKrn);
	HdsCrypto_NonceGenerator_NextScalar(&ng, &kNonce);
	SECURE_ERASE_OBJ(ng);

	KernelUpdateKeys(&pTx->m_Krn, &kKrn, &kNonce, 0);

	HdsCrypto_TxKernel_getID(&pTx->m_Krn, &hv);

	int res = HdsCrypto_KeyKeeper_ConfirmSpend(0, 0, 0, &pTx->m_Krn, &hv);
	if (HdsCrypto_KeyKeeper_Status_Ok != res)
		return res;

	HdsCrypto_Signature_SignPartial(&pTx->m_Krn.m_Signature, &hv, &kKrn, &kNonce);

	TxAggrToOffset(&txAggr, &kKrn, pTx);

	return HdsCrypto_KeyKeeper_Status_Ok;
}

//////////////////////////////
// KeyKeeper - Receive + Send common stuff
static void GetPaymentConfirmationMsg(HdsCrypto_UintBig* pRes, const HdsCrypto_UintBig* pSender, const HdsCrypto_UintBig* pKernelID, HdsCrypto_Amount amount, HdsCrypto_AssetID nAssetID)
{
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	HASH_WRITE_STR(sha, "PaymentConfirmation");
	secp256k1_sha256_write(&sha, pKernelID->m_pVal, sizeof(pKernelID->m_pVal));
	secp256k1_sha256_write(&sha, pSender->m_pVal, sizeof(pSender->m_pVal));
	secp256k1_sha256_write_Num(&sha, amount);

	if (nAssetID)
	{
		HASH_WRITE_STR(sha, "asset");
		secp256k1_sha256_write_Num(&sha, nAssetID);
	}

	secp256k1_sha256_finalize(&sha, pRes->m_pVal);
}

static void GetWalletIDKey(const HdsCrypto_KeyKeeper* p, HdsCrypto_WalletIdentity nKey, secp256k1_scalar* pKey, HdsCrypto_UintBig* pID)
{
	// derive key
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "kid");

	const uint32_t nType = FOURCC_FROM_STR(tRid);

	secp256k1_sha256_write_Num(&sha, nKey);
	secp256k1_sha256_write_Num(&sha, nType);
	secp256k1_sha256_write_Num(&sha, 0);
	secp256k1_sha256_finalize(&sha, pID->m_pVal);

	HdsCrypto_Kdf_Derive_SKey(&p->m_MasterKey, pID, pKey);
	HdsCrypto_Sk2Pk(pID, pKey);
}

//////////////////////////////
// KeyKeeper - ReceiveTx
int HdsCrypto_KeyKeeper_SignTx_Receive(const HdsCrypto_KeyKeeper* p, HdsCrypto_TxCommon* pTx, HdsCrypto_TxMutualInfo* pMut)
{
	TxAggr txAggr;
	if (!TxAggregate(p, pTx, &txAggr))
		return HdsCrypto_KeyKeeper_Status_Unspecified;

	if (txAggr.m_Ins.m_Hdss != txAggr.m_Outs.m_Hdss)
	{
		if (txAggr.m_Ins.m_Hdss > txAggr.m_Outs.m_Hdss)
			return HdsCrypto_KeyKeeper_Status_Unspecified; // not receiving

		if (txAggr.m_Ins.m_Assets != txAggr.m_Outs.m_Assets)
			return HdsCrypto_KeyKeeper_Status_Unspecified; // mixed

		txAggr.m_AssetID = 0;
		txAggr.m_Outs.m_Assets = txAggr.m_Outs.m_Hdss - txAggr.m_Ins.m_Hdss;
	}
	else
	{
		if (txAggr.m_Ins.m_Assets >= txAggr.m_Outs.m_Assets)
			return HdsCrypto_KeyKeeper_Status_Unspecified; // not receiving

		assert(txAggr.m_AssetID);
		txAggr.m_Outs.m_Assets -= txAggr.m_Ins.m_Assets;
	}

	// Hash *ALL* the parameters, make the context unique
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);

	HdsCrypto_UintBig hv;
	HdsCrypto_TxKernel_getID(&pTx->m_Krn, &hv); // not a final ID yet

	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_write_CompactPoint(&sha, &pTx->m_Krn.m_Signature.m_NoncePub);

	uint8_t nFlag = 0; // not nonconventional
	secp256k1_sha256_write(&sha, &nFlag, sizeof(nFlag));
	secp256k1_sha256_write(&sha, pMut->m_Peer.m_pVal, sizeof(pMut->m_Peer.m_pVal));
	secp256k1_sha256_write_Num(&sha, pMut->m_MyIDKey);

	secp256k1_scalar_get_b32(hv.m_pVal, &txAggr.m_sk);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));

	secp256k1_sha256_write_Num(&sha, txAggr.m_Outs.m_Assets); // the value being-received
	secp256k1_sha256_write_Num(&sha, txAggr.m_AssetID);

	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	// derive keys
	static const char szSalt[] = "hw-wlt-rcv";
	HdsCrypto_NonceGenerator ng;
	HdsCrypto_NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &hv);

	secp256k1_scalar kKrn, kNonce;
	HdsCrypto_NonceGenerator_NextScalar(&ng, &kKrn);
	HdsCrypto_NonceGenerator_NextScalar(&ng, &kNonce);
	SECURE_ERASE_OBJ(ng);

	if (!KernelUpdateKeys(&pTx->m_Krn, &kKrn, &kNonce, 1))
		return HdsCrypto_KeyKeeper_Status_Unspecified;

	HdsCrypto_TxKernel_getID(&pTx->m_Krn, &hv); // final ID
	HdsCrypto_Signature_SignPartial(&pTx->m_Krn.m_Signature, &hv, &kKrn, &kNonce);

	TxAggrToOffset(&txAggr, &kKrn, pTx);

	if (pMut->m_MyIDKey)
	{
		// sign
		HdsCrypto_UintBig hvID;
		GetWalletIDKey(p, pMut->m_MyIDKey, &kKrn, &hvID);
		GetPaymentConfirmationMsg(&hvID, &pMut->m_Peer, &hv, txAggr.m_Outs.m_Assets, txAggr.m_AssetID);
		HdsCrypto_Signature_Sign(&pMut->m_PaymentProofSignature, &hvID, &kKrn);
	}

	return HdsCrypto_KeyKeeper_Status_Ok;
}

//////////////////////////////
// KeyKeeper - SendTx
int HdsCrypto_KeyKeeper_SignTx_Send(const HdsCrypto_KeyKeeper* p, HdsCrypto_TxCommon* pTx, HdsCrypto_TxMutualInfo* pMut, HdsCrypto_TxSenderParams* pSnd)
{
	TxAggr txAggr;
	if (!TxAggregate(p, pTx, &txAggr))
		return HdsCrypto_KeyKeeper_Status_Unspecified;

	if (IsUintBigZero(&pMut->m_Peer))
		return HdsCrypto_KeyKeeper_Status_UserAbort; // conventional transfers must always be signed

	if (txAggr.m_Ins.m_Hdss < txAggr.m_Outs.m_Hdss)
		return HdsCrypto_KeyKeeper_Status_Unspecified; // not sending
	txAggr.m_Ins.m_Hdss -= txAggr.m_Outs.m_Hdss;

	if (txAggr.m_Ins.m_Assets != txAggr.m_Outs.m_Assets)
	{
		if (txAggr.m_Ins.m_Assets < txAggr.m_Outs.m_Assets)
			return HdsCrypto_KeyKeeper_Status_Unspecified; // not sending

		if (txAggr.m_Ins.m_Hdss != pTx->m_Krn.m_Fee)
			return HdsCrypto_KeyKeeper_Status_Unspecified; // balance mismatch, the lost amount must go entirely to fee

		txAggr.m_Ins.m_Assets -= txAggr.m_Outs.m_Assets;
	}
	else
	{
		if (txAggr.m_Ins.m_Hdss <= pTx->m_Krn.m_Fee)
			return HdsCrypto_KeyKeeper_Status_Unspecified; // not sending

		txAggr.m_Ins.m_Assets = txAggr.m_Ins.m_Hdss - pTx->m_Krn.m_Fee;
		txAggr.m_AssetID = 0;
	}

	secp256k1_scalar kKrn, kNonce;
	HdsCrypto_UintBig hvMyID, hv;
	GetWalletIDKey(p, pMut->m_MyIDKey, &kNonce, &hvMyID);

	if (pSnd->m_iSlot >= HdsCrypto_KeyKeeper_getNumSlots())
		return HdsCrypto_KeyKeeper_Status_Unspecified;

	HdsCrypto_KeyKeeper_ReadSlot(pSnd->m_iSlot, &hv);
	HdsCrypto_Kdf_Derive_SKey(&p->m_MasterKey, &hv, &kNonce);

	// during negotiation kernel height and commitment are adjusted. We should only commit to the Fee
	secp256k1_sha256_t sha;
	secp256k1_sha256_initialize(&sha);
	secp256k1_sha256_write_Num(&sha, pTx->m_Krn.m_Fee);
	secp256k1_sha256_write(&sha, pMut->m_Peer.m_pVal, sizeof(pMut->m_Peer.m_pVal));
	secp256k1_sha256_write(&sha, hvMyID.m_pVal, sizeof(hvMyID.m_pVal));

	uint8_t nFlag = 0; // not nonconventional
	secp256k1_sha256_write(&sha, &nFlag, sizeof(nFlag));

	secp256k1_scalar_get_b32(hv.m_pVal, &txAggr.m_sk);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_write_Num(&sha, txAggr.m_Ins.m_Assets);
	secp256k1_sha256_write_Num(&sha, txAggr.m_AssetID);

	secp256k1_scalar_get_b32(hv.m_pVal, &kNonce);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	static const char szSalt[] = "hw-wlt-snd";
	HdsCrypto_NonceGenerator ng;
	HdsCrypto_NonceGenerator_Init(&ng, szSalt, sizeof(szSalt), &hv);
	HdsCrypto_NonceGenerator_NextScalar(&ng, &kKrn);
	SECURE_ERASE_OBJ(ng);

	// derive tx token
	secp256k1_sha256_initialize(&sha);
	HASH_WRITE_STR(sha, "tx.token");

	secp256k1_scalar_get_b32(hv.m_pVal, &kKrn);
	secp256k1_sha256_write(&sha, hv.m_pVal, sizeof(hv.m_pVal));
	secp256k1_sha256_finalize(&sha, hv.m_pVal);

	if (IsUintBigZero(&hv))
		hv.m_pVal[_countof(hv.m_pVal) - 1] = 1;

	if (IsUintBigZero(&pSnd->m_UserAgreement))
	{
		int res = HdsCrypto_KeyKeeper_ConfirmSpend(txAggr.m_Ins.m_Assets, txAggr.m_AssetID, &pMut->m_Peer, &pTx->m_Krn, 0);
		if (HdsCrypto_KeyKeeper_Status_Ok != res)
			return res;

		pSnd->m_UserAgreement = hv;

		KernelUpdateKeys(&pTx->m_Krn, &kKrn, &kNonce, 0);

		return HdsCrypto_KeyKeeper_Status_Ok;
	}

	if (memcmp(pSnd->m_UserAgreement.m_pVal, hv.m_pVal, sizeof(hv.m_pVal)))
		return HdsCrypto_KeyKeeper_Status_Unspecified; // incorrect user agreement token

	HdsCrypto_TxKernel_getID(&pTx->m_Krn, &hv);

	// verify payment confirmation signature
	GetPaymentConfirmationMsg(&hvMyID, &hvMyID, &hv, txAggr.m_Ins.m_Assets, txAggr.m_AssetID);

	HdsCrypto_FlexPoint fp;
	fp.m_Compact.m_X = pMut->m_Peer;
	fp.m_Compact.m_Y = 0;
	fp.m_Flags = HdsCrypto_FlexPoint_Compact;

	if (!HdsCrypto_Signature_IsValid(&pMut->m_PaymentProofSignature, &hvMyID, &fp))
		return HdsCrypto_KeyKeeper_Status_Unspecified;

	// 2nd user confirmation request. Now the kernel is complete, its ID is calculated
	int res = HdsCrypto_KeyKeeper_ConfirmSpend(txAggr.m_Ins.m_Assets, txAggr.m_AssetID, &pMut->m_Peer, &pTx->m_Krn, &hvMyID);
	if (HdsCrypto_KeyKeeper_Status_Ok != res)
		return res;

	// Regenerate the slot (BEFORE signing), and sign
	HdsCrypto_KeyKeeper_RegenerateSlot(pSnd->m_iSlot);

	TxImportSubtract(&kNonce, &pTx->m_Krn.m_Signature.m_k);
	HdsCrypto_TxKernel_getID(&pTx->m_Krn, &hv); // final ID
	HdsCrypto_Signature_SignPartial(&pTx->m_Krn.m_Signature, &hv, &kKrn, &kNonce);

	TxImportSubtract(&kKrn, &pTx->m_kOffset);
	TxAggrToOffset(&txAggr, &kKrn, pTx);

	return HdsCrypto_KeyKeeper_Status_Ok;
}
