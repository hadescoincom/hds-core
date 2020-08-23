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
#include "assets_kdf_utils.h"

namespace hds::wallet
{
    PeerID GetAssetOwnerID(const Key::IKdf::Ptr& masterKdf, const std::string& strMeta)
    {
        Asset::Metadata meta;
        meta.m_Value = toByteBuffer(strMeta);
        meta.UpdateHash();

        PeerID ownerID = 0UL;
        meta.get_Owner(ownerID, *masterKdf);

        return ownerID;
    }

    std::vector<Input::Ptr> GenerateAssetInputs(const Key::IKdf::Ptr& masterKdf, const CoinIDList& coins)
    {
        std::vector<hds::Input::Ptr> inputs;
        inputs.reserve(coins.size());
        for (const auto &cid : coins)
        {
            inputs.emplace_back();
            inputs.back().reset(new hds::Input);

            ECC::Scalar::Native sk;
            hds::CoinID::Worker(cid).Create(sk, inputs.back()->m_Commitment, *cid.get_ChildKdf(masterKdf));
        }
        return inputs;
    }

    std::vector<Output::Ptr> GenerateAssetOutputs(const Key::IKdf::Ptr& masterKdf, Height minHeight, const CoinIDList& coins)
    {
        std::vector<Output::Ptr> outputs;
        outputs.reserve(coins.size());
        for (const auto& cid : coins)
        {
            outputs.emplace_back();
            outputs.back().reset(new Output);

            ECC::Scalar::Native sk;
            outputs.back()->Create(minHeight, sk, *cid.get_ChildKdf(masterKdf), cid, *masterKdf);
        }
        return outputs;
    }

    ECC::Scalar::Native GetExcess(const Key::IKdf::Ptr& masterKdf, const CoinIDList& inputs, const CoinIDList& outputs)
    {
        // Excess = Sum(input blinfing factors) - Sum(output blinfing factors) - offset
        ECC::Point commitment;
        ECC::Scalar::Native blindingFactor;
        ECC::Scalar::Native excess = Zero;

        for (const auto& coinID : outputs)
        {
            CoinID::Worker(coinID).Create(blindingFactor, commitment, *coinID.get_ChildKdf(masterKdf));
            excess += blindingFactor;
        }

        excess = -excess;
        for (const auto& coinID : inputs)
        {
            CoinID::Worker(coinID).Create(blindingFactor, commitment, *coinID.get_ChildKdf(masterKdf));
            excess += blindingFactor;
        }

        return excess;
    }

    ECC::Scalar::Native SignAssetKernel(const Key::IKdf::Ptr& masterKdf,
            const CoinIDList& inputs,
            const CoinIDList& outputs,
            const std::string& strMeta,
            TxKernelAssetControl& kernel)
    {
        Key::Index skIdx = 0;
        ECC::GenRandom(&skIdx, sizeof skIdx);

        ECC::Scalar::Native kernelSk;
        masterKdf->DeriveKey(kernelSk, Key::ID(skIdx, Key::Type::Kernel, skIdx));

        Asset::Metadata meta;
        meta.m_Value = toByteBuffer(strMeta);
        meta.UpdateHash();

        kernel.Sign(kernelSk, *masterKdf, meta);
        kernelSk = -kernelSk;

        auto excess = GetExcess(masterKdf, inputs, outputs);
        excess += kernelSk;

        return excess;
    }
}
