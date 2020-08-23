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

#include "node/node.h"

class TxGenerator
{
public:
	using Inputs = std::vector<hds::Input>;
public:
	TxGenerator(hds::Key::IKdf& kdf);

	void GenerateInputInTx(hds::Height h, hds::Amount v, hds::Key::Type keyType = hds::Key::Type::Coinbase, uint32_t ind = 0);
	void GenerateOutputInTx(hds::Height h, hds::Amount v, hds::Key::Type keyType = hds::Key::Type::Regular, bool isPublic = false, uint32_t ind = 0);
	void GenerateKernel(hds::Height h, hds::Amount fee = 0, uint32_t ind = 0);
	void GenerateKernel();

	const hds::proto::NewTransaction& GetTransaction();
	bool IsValid() const;

	void Sort();
	void SortInputs();
	void SortOutputs();
	void SortKernels();

	void ZeroOffset();

	Inputs GenerateInputsFromOutputs();

private:
	hds::Key::IKdf& m_Kdf;
	hds::proto::NewTransaction m_MsgTx;
	ECC::Scalar::Native m_Offset;
};
