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

#include "wallet/core/base_tx_builder.h"
#include "wallet/core/base_transaction.h"

namespace hds::wallet
{
    class LockTxBuilder : public BaseTxBuilder
    {
    public:
        LockTxBuilder(BaseTransaction& tx, Amount amount, Amount fee);

        Transaction::Ptr CreateTransaction() override;
        Height GetMaxHeight() const override;

        void LoadSharedParameters();
        bool CreateSharedUTXOProofPart2(bool isHdsOwner);
        bool CreateSharedUTXOProofPart3(bool isHdsOwner);

        ECC::RangeProof::Confidential::Part2 GetRangeProofInitialPart2() const;
        const ECC::RangeProof::Confidential& GetSharedProof() const;
        const ECC::RangeProof::Confidential::MultiSig& GetProofPartialMultiSig() const;
        ECC::Point::Native GetPublicSharedBlindingFactor() const;

    private:

        void AddSharedOutput();
        void LoadPeerOffset();

        const ECC::uintBig& GetSharedSeed() const;
        const ECC::Scalar::Native& GetSharedBlindingFactor() const;
        const ECC::RangeProof::CreatorParams& GetProofCreatorParams(bool isHdsOwner);

        ECC::Point::Native GetSharedCommitment();

        ECC::Scalar::Native m_SharedBlindingFactor;
        ECC::NoLeak<ECC::uintBig> m_SharedSeed;
        Coin m_SharedCoin;
        ECC::RangeProof::Confidential m_SharedProof;

        // deduced values, 
        boost::optional<ECC::RangeProof::CreatorParams> m_CreatorParams;
        ECC::RangeProof::Confidential::MultiSig m_ProofPartialMultiSig;
    };
}