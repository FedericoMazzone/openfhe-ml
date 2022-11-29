//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================


#include "openfhe.h"

using namespace lbcrypto;


/**
 * Compute (plaintext) vector-matrix multiplication.
 * @param vector input vector
 * @param matrix input matrix
 * @return vector-matrix product
 */
std::vector<int64_t> vectorMatrixMult(
    std::vector<int64_t> vector,
    std::vector<std::vector<int64_t>> matrix
);


/**
 * Compute the product between an encrypted vector and a plaintext matrix.
 * The naive algorithm with the recursive-sum inner product implementation is
 * used.
 * The output is automatically masked.
 * Matrix packing approach from Kim et al. Logistic regression model training
 * based on the approximate homomorphic encryption. 
 * Alternate packing approach from Sav et al. Poseidon: Privacy-preserving
 * federated neural network learning.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vectorC encrypted input vector
 * @param matrix (plaintext) input matrix
 * @param packing true for column-wise, false for row-wise
 * @param numRowsPrevMatrix only needed for row-wise packing
 * @param masking whether you want the output ciphertext to contain only the
 * output value in the first positions, and 0s in the other positions
 * @param transposing only for column-wise packing, whether you want the output
 * vector to be transposed (in terms of packing) and so be ready for a new
 * column-wise pack multiplication
 * @return encrypted vector-matrix product
 */
Ciphertext<DCRTPoly> vectorMatrixMultPackCP(
    CryptoContext<DCRTPoly> cryptoContext,
    PublicKey<DCRTPoly> publicKey,
    Ciphertext<DCRTPoly> vectorC,
    std::vector<std::vector<int64_t>> matrix,
    bool packing = true,
    int numRowsPrevMatrix = -1,
    bool masking = true,
    bool transposing = true
);
