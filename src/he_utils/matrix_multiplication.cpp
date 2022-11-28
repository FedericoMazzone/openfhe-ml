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

/*
    Matrix multiplication.
*/

#include "matrix_multiplication.h"

#include <iostream>


/**
 * Generate random vector of size length, with values in [-maxValue, maxValue).
 * @param length desired length of the vector
 * @param maxValue absolute maximum value of the coefficients
 * @return random vector
 */
std::vector<int64_t> genRandVect(
        size_t length,
        int64_t maxValue
    )
{
    std::srand(unsigned(std::time(nullptr)));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<int64_t> vector(length);
    std::generate(vector.begin(), vector.end(), myrand);
    return vector;
}


/**
 * Generate random matrix of size (rows x cols), with values in [-maxValue,
 * maxValue).
 * @param rows desired number of rows
 * @param cols desired number of columns
 * @param maxValue absolute maximum value of the coefficients
 * @return random matrix
 */
std::vector<std::vector<int64_t>> genRandMatrix(
        size_t rows,
        size_t cols,
        int64_t maxValue
    )
{
    std::srand(unsigned(std::time(nullptr)));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<std::vector<int64_t>> matrix(rows, std::vector<int64_t>(cols));
    for (size_t i = 0; i < rows; i++)
        std::generate(matrix[i].begin(), matrix[i].end(), myrand);
    return matrix;
}


/**
 * Transpose the given matrix.
 * @param matrix input matrix
 * @return transposed matrix
 */
std::vector<std::vector<int64_t>> transpose(
        std::vector<std::vector<int64_t>> matrix
    )
{
    std::vector<std::vector<int64_t>> matrixT(
        matrix[0].size(),
        std::vector<int64_t>(matrix.size())
    );
    for (size_t i = 0; i < matrix[0].size(); i++) 
        for (size_t j = 0; j < matrix.size(); j++)
            matrixT[i][j] = matrix[j][i];
    return matrixT;
}


/**
 * Compute the least power of two greater or equal than the input value.
 * @param n input value
 * @return least power of two >= n
 */
size_t nextPowerOf2(
        size_t n
    )
{
    if (n == 0 || n == 1) return 1;
    else return 1 << ((int) log2(n - 1) + 1);
}


/**
 * Resize the input matrix to reach the desired number of rows and columns, by
 * padding with 0s if necessary.
 * @param matrix input matrix
 * @param numRows output's number of rows
 * @param numCols output's number of columns
 * @return resized matrix
 */
std::vector<std::vector<int64_t>> resizeMatrix(
        std::vector<std::vector<int64_t>> matrix,
        size_t numRows,
        size_t numCols
    )
{
    for (auto &row : matrix) row.resize(numCols, 0);
    matrix.resize(numRows, std::vector<int64_t>(numCols, 0));
    return matrix;
}


/**
 * Flatten the input matrix.
 * @param matrix input matrix
 * @param direction true for row-wise, false for column-wise
 * @return flattened matrix
 */
std::vector<int64_t> flattenMatrix(
        std::vector<std::vector<int64_t>> matrix,
        bool direction = true
    )
{
    std::vector<int64_t> res;
    if (direction)
        for (auto &row : matrix)
            res.insert(end(res), begin(row), end(row));
    else {
        for (size_t i = 0; i < matrix[0].size(); i++) 
            for (size_t j = 0; j < matrix.size(); j++)
                res.push_back(matrix[j][i]);
    }
    return res;
}


/**
 * Compute the inner product between two (plaintext) vectors.
 * @param vector1 first input vector
 * @param vector2 second input vector
 * @return inner product value
 */
int64_t innerProduct(
        std::vector<int64_t> vector1,
        std::vector<int64_t> vector2
    )
{
    int64_t inner_product = 0;
    for (size_t i = 0; i < vector1.size(); i++)
        inner_product += vector1[i] * vector2[i];
    return inner_product;
}


/**
 * Compute (plaintext) vector-matrix multiplication.
 * @param vector input vector
 * @param matrix input matrix
 * @return vector-matrix product
 */
std::vector<int64_t> vectorMatrixMult(
        std::vector<int64_t> vector,
        std::vector<std::vector<int64_t>> matrix
    )
{
    std::vector<std::vector<int64_t>> matrixT = transpose(matrix);
    std::vector<int64_t> result;
    for (size_t i = 0; i < matrixT.size(); i++) {
        int64_t innProd = innerProduct(vector, matrixT[i]);
        result.push_back(innProd);
    }
    return result;
}


/**
 * Compute the inner product between two encrypted vectors.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vector1C first encrypted input vector
 * @param vector2C second encrypted input vector
 * @param vectorLength length of the vector (in plaintext)
 * @param masking whether you want the output ciphertext to contain only the
 * output value in the first position, and 0s in the other positions
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> innerProductCC(
        CryptoContext<DCRTPoly> cryptoContext,
        PublicKey<DCRTPoly> publicKey,
        Ciphertext<DCRTPoly> vector1C,
        Ciphertext<DCRTPoly> vector2C,
        size_t vectorLength,
        bool masking = false
    )
{
    Ciphertext<DCRTPoly> v1v2C = cryptoContext->EvalMult(vector1C, vector2C);

    const std::vector<int64_t> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakePackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> innerProductC = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    for (size_t i = 0; i < vectorLength; i++)
        innerProductC = cryptoContext->EvalAdd(innerProductC, cryptoContext->EvalRotate(v1v2C, i));
    
    if (masking) {
        const std::vector<int64_t> ONE = {1};
        const Plaintext ONE_PLAINTEXT = cryptoContext->MakePackedPlaintext(ONE);
        innerProductC = cryptoContext->EvalMult(innerProductC, ONE_PLAINTEXT);
    }

    return innerProductC;
}


/**
 * Compute the inner product between an encrypted vector and a plaintext vector.
 * The naive algorithm is used.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vector1C first encrypted input vector
 * @param vector2 second (plaintext) input vector
 * @param masking whether you want the output ciphertext to contain only the
 * output value in the first position, and 0s in the other positions
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> innerProductCP(
        CryptoContext<DCRTPoly> cryptoContext,
        PublicKey<DCRTPoly> publicKey,
        Ciphertext<DCRTPoly> vector1C,
        std::vector<int64_t> vector2,
        bool masking = false
    )
{
    Plaintext vector2P  = cryptoContext->MakePackedPlaintext(vector2);

    Ciphertext<DCRTPoly> v1v2C = cryptoContext->EvalMult(vector1C, vector2P);

    const std::vector<int64_t> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakePackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> innerProductC = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    for (size_t i = 0; i < vector2.size(); i++)
        innerProductC = cryptoContext->EvalAdd(innerProductC, cryptoContext->EvalRotate(v1v2C, i));

    if (masking) {
        const std::vector<int64_t> ONE = {1};
        const Plaintext ONE_PLAINTEXT = cryptoContext->MakePackedPlaintext(ONE);
        innerProductC = cryptoContext->EvalMult(innerProductC, ONE_PLAINTEXT);
    }

    return innerProductC;
}


/**
 * Compute the inner product between an encrypted vector and a plaintext vector.
 * The recursive vector sum-up is used.
 * @param cryptoContext the crypto context
 * @param vector1C first encrypted input vector
 * @param vector2 second (plaintext) input vector
 * @param masking whether you want the output ciphertext to contain only the
 * output value in the first position, and 0s in the other positions
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> innerProductFastCP(
        CryptoContext<DCRTPoly> cryptoContext,
        Ciphertext<DCRTPoly> vector1C,
        std::vector<int64_t> vector2,
        bool masking = false
    )
{
    Plaintext vector2P  = cryptoContext->MakePackedPlaintext(vector2);

    Ciphertext<DCRTPoly> v1v2C = cryptoContext->EvalMult(vector1C, vector2P);

    for (size_t i = 0; i < log2(vector2.size()); i++)
        v1v2C = cryptoContext->EvalAdd(v1v2C, cryptoContext->EvalRotate(v1v2C, 1 << i));

    if (masking) {
        const std::vector<int64_t> ONE = {1};
        const Plaintext ONE_PLAINTEXT = cryptoContext->MakePackedPlaintext(ONE);
        v1v2C = cryptoContext->EvalMult(v1v2C, ONE_PLAINTEXT);
    }

    return v1v2C;
}


/**
 * Compute the product between an encrypted vector and a plaintext matrix.
 * The naive algorithm with the naive inner product implementation is used.
 * The output is automatically masked.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vectorC encrypted input vector
 * @param matrix (plaintext) input matrix
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> vectorMatrixMultByInnProdCP(
        CryptoContext<DCRTPoly> cryptoContext,
        PublicKey<DCRTPoly> publicKey,
        Ciphertext<DCRTPoly> vectorC,
        std::vector<std::vector<int64_t>> matrix
    )
{
    const std::vector<int64_t> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakePackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> result = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    std::vector<std::vector<int64_t>> matrixT = transpose(matrix);
    Ciphertext<DCRTPoly> innProdC;
    for (size_t i = 0; i < matrixT.size(); i++) {
        innProdC = innerProductCP(cryptoContext, publicKey, vectorC, matrixT[i], true);
        innProdC = cryptoContext->EvalRotate(innProdC, -i);
        result = cryptoContext->EvalAdd(result, innProdC);
    }
    return result;
}


/**
 * Compute the product between an encrypted vector and a plaintext matrix.
 * The naive algorithm with the recursive-sum inner product implementation is
 * used.
 * The output is automatically masked.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param vectorC encrypted input vector
 * @param matrix (plaintext) input matrix
 * @return encrypted inner product value
 */
Ciphertext<DCRTPoly> vectorMatrixMultByInnProdFastCP(
        CryptoContext<DCRTPoly> cryptoContext,
        PublicKey<DCRTPoly> publicKey,
        Ciphertext<DCRTPoly> vectorC,
        std::vector<std::vector<int64_t>> matrix
    )
{
    const std::vector<int64_t> ZERO = {0};
    const Plaintext ZERO_PLAINTEXT = cryptoContext->MakePackedPlaintext(ZERO);
    Ciphertext<DCRTPoly> result = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
    std::vector<std::vector<int64_t>> matrixT = transpose(matrix);
    Ciphertext<DCRTPoly> innProdC;
    for (size_t i = 0; i < matrixT.size(); i++) {
        innProdC = innerProductFastCP(cryptoContext, vectorC, matrixT[i], true);
        innProdC = cryptoContext->EvalRotate(innProdC, -i);
        result = cryptoContext->EvalAdd(result, innProdC);
    }
    return result;
}


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
 * @return
 */
Ciphertext<DCRTPoly> vectorMatrixMultPackCP(
        CryptoContext<DCRTPoly> cryptoContext,
        PublicKey<DCRTPoly> publicKey,
        Ciphertext<DCRTPoly> vectorC,
        std::vector<std::vector<int64_t>> matrix,
        bool packing,
        int numRowsPrevMatrix,
        bool masking,
        bool transposing
    )
{
    // Store original matrix size.
    size_t ogNumRows = matrix.size();
    size_t ogNumCols = matrix[0].size();

    // Pad and flatten the matrix.
    size_t numRows = nextPowerOf2(ogNumRows);
    size_t numCols = packing ? nextPowerOf2(ogNumCols) : nextPowerOf2(numRowsPrevMatrix);
    matrix = resizeMatrix(matrix, numRows, numCols);
    std::vector<int64_t> matrixFlat = flattenMatrix(matrix, !packing);
    Plaintext matrixFlatP  = cryptoContext->MakePackedPlaintext(matrixFlat);

    // Pad and repeat the vector.
    for (size_t i = 0; i < log2(ogNumCols); i++)
        vectorC = cryptoContext->EvalAdd(vectorC, cryptoContext->EvalRotate(vectorC, -((packing ? numRows : 1) << i)));
    
    // Multiply and sum (the result is stored in the first row of the matrix).
    Ciphertext<DCRTPoly> prod = cryptoContext->EvalMult(vectorC, matrixFlatP);
    for (size_t i = 0; i < log2(numRows); i++)
        prod = cryptoContext->EvalAdd(prod, cryptoContext->EvalRotate(prod, (packing ? 1 : numCols) << i));

    // Mask out the result.
    if (!(packing && transposing) && masking) {
        std::vector<int64_t> mask;
        if (packing) {
            for (size_t i = 0; i < numCols; i++)
                for (size_t j = 0; j < numRows; j++)
                    if (j == 0 && i < ogNumCols)
                        mask.push_back(1);
                    else
                        mask.push_back(0);
        } else {
            mask.insert(mask.end(), ogNumCols, 1);
        }
        Plaintext maskP = cryptoContext->MakePackedPlaintext(mask);
        prod = cryptoContext->EvalMult(prod, maskP);
    }

    // Transpose the result.
    // TODO: improve transposition (easy if rows >= cols)
    if (packing && transposing) {
        const std::vector<int64_t> ZERO = {0};
        const Plaintext ZERO_PLAINTEXT = cryptoContext->MakePackedPlaintext(ZERO);
        Ciphertext<DCRTPoly> res = cryptoContext->Encrypt(publicKey, ZERO_PLAINTEXT);
        std::vector<int64_t> mask = {1};
        Plaintext maskP;
        for (size_t i = 0; i < ogNumCols; i++) {
            maskP = cryptoContext->MakePackedPlaintext(mask);
            res = cryptoContext->EvalAdd(
                    res,
                    cryptoContext->EvalMult(
                        cryptoContext->EvalRotate(
                            prod,
                            i * (numRows - 1)),
                        maskP));
            mask.insert(mask.begin(), 0);
        }
        prod = res;
    }

    return prod;
}


// int main(int argc, char* argv[]) {

//     TimeVar t;
//     double processingTime(0.0);
 
//     CCParams<CryptoContextBFVRNS> parameters;
//     parameters.SetPlaintextModulus(536903681);
//     parameters.SetMultiplicativeDepth(4);
//     parameters.SetMaxRelinSkDeg(3);

//     CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
//     cryptoContext->Enable(PKE);
//     cryptoContext->Enable(KEYSWITCH);
//     cryptoContext->Enable(LEVELEDSHE);
//     cryptoContext->Enable(ADVANCEDSHE);

//     PlaintextModulus p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
//     int n = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
//     double q = cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();
//     std::cout << "Plaintext modulus (p) = " << p << std::endl;
//     std::cout << "Polynomial degree (n) = " << n << std::endl;
//     std::cout << "Ciphertext modulus bitsize (log2 q) = " << log2(q) << std::endl;

//     KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
//     if (!keyPair.good()) {
//         std::cout << "Key generation failed!" << std::endl;
//         exit(1);
//     }

//     cryptoContext->EvalMultKeysGen(keyPair.secretKey);

//     std::cout << "Generating rotation keys... ";
//     std::vector<int32_t> indexList = {};
//     for (int i = -100; i <= 100; i++) indexList.push_back(i);
//     for (int i = 0; i <= 10; i++) {
//         indexList.push_back(1 << i);
//         indexList.push_back(-(1 << i));
//     }
//     cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);
//     std::cout << "DONE" << std::endl;

//     std::cout << std::endl;

//     ////////////////////////////////////////////////////////////
//     // Inner product
//     ////////////////////////////////////////////////////////////

//     // const size_t VECTOR_LENGTH = 200;
//     // const int64_t MAX_VALUE = 100;
    
//     // std::vector<int64_t> v1 = genRandVect(VECTOR_LENGTH, MAX_VALUE);
//     // Plaintext v1P  = cryptoContext->MakePackedPlaintext(v1);

//     // std::vector<int64_t> v2 = genRandVect(VECTOR_LENGTH, MAX_VALUE);
//     // Plaintext v2P  = cryptoContext->MakePackedPlaintext(v2);

//     // std::cout << "v1 = " << v1 << std::endl;
//     // std::cout << "v2 = " << v2 << std::endl;

//     // Ciphertext<DCRTPoly> v1C = cryptoContext->Encrypt(keyPair.publicKey, v1P);
//     // Ciphertext<DCRTPoly> v2C = cryptoContext->Encrypt(keyPair.publicKey, v2P);

//     // Ciphertext<DCRTPoly> resC;
//     // Plaintext res;
//     // int64_t resInt64;

//     // TIC(t);
//     // resInt64 = innerProduct(v1, v2);
//     // processingTime = TOC(t);
//     // std::cout << "v1  * v2        = " << resInt64 << " (" << processingTime
//     //           << " ms)" << std::endl;
    
//     // TIC(t);
//     // resC = innerProductCC(cryptoContext, keyPair.publicKey, v1C, v2C, v1.size());
//     // processingTime = TOC(t);
//     // cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     // res->SetLength(1);
//     // resInt64 = res->GetPackedValue()[0];
//     // std::cout << "v1C * v2C       = " << resInt64 << " (" << processingTime
//     //           << " ms)" << std::endl;

//     // TIC(t);
//     // resC = innerProductCP(cryptoContext, keyPair.publicKey, v1C, v2);
//     // processingTime = TOC(t);
//     // cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     // res->SetLength(1);
//     // resInt64 = res->GetPackedValue()[0];
//     // std::cout << "v1C * v2        = " << resInt64 << " (" << processingTime
//     //           << " ms)" << std::endl;

//     // TIC(t);
//     // resC = innerProductFastCP(cryptoContext, v1C, v2);
//     // processingTime = TOC(t);
//     // cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     // res->SetLength(1);
//     // resInt64 = res->GetPackedValue()[0];
//     // std::cout << "v1C * v2 (fast) = " << resInt64 << " (" << processingTime
//     //           << " ms)" << std::endl;

//     ////////////////////////////////////////////////////////////
//     // Vector * matrix
//     ////////////////////////////////////////////////////////////

//     // const size_t ROWS = 5;
//     // const size_t COLS = 3;
//     // const int64_t MAX_VALUE = 100;
    
//     // std::vector<int64_t> vector = genRandVect(ROWS, MAX_VALUE);
//     // Plaintext vectorP  = cryptoContext->MakePackedPlaintext(vector);

//     // std::vector<std::vector<int64_t>> matrix = genRandMatrix(ROWS, COLS, MAX_VALUE);
    
//     // std::cout << "vector = " << vector << std::endl;
//     // std::cout << "matrix = " << matrix << std::endl;

//     // Ciphertext<DCRTPoly> vectorC = cryptoContext->Encrypt(keyPair.publicKey, vectorP);

//     // Ciphertext<DCRTPoly> resC;
//     // Plaintext res;
//     // std::vector<int64_t> resInt64, resInt64tmp;

//     // TIC(t);
//     // resInt64 = vectorMatrixMult(vector, matrix);
//     // processingTime = TOC(t);
//     // std::cout << "vector  * matrix                         = " << resInt64
//     //           << " (" << processingTime << " ms)" << std::endl;

//     // TIC(t);
//     // resC = vectorMatrixMultByInnProdCP(cryptoContext, keyPair.publicKey, vectorC, matrix);
//     // processingTime = TOC(t);
//     // cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     // res->SetLength(COLS);
//     // resInt64 = res->GetPackedValue();
//     // std::cout << "vectorC * matrix (by inner product)      = " << resInt64
//     //           << " (" << processingTime << " ms)" << std::endl;
    
//     // TIC(t);
//     // resC = vectorMatrixMultByInnProdFastCP(cryptoContext, keyPair.publicKey, vectorC, matrix);
//     // processingTime = TOC(t);
//     // cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     // res->SetLength(COLS);
//     // resInt64 = res->GetPackedValue();
//     // std::cout << "vectorC * matrix (by inner product fast) = " << resInt64
//     //           << " (" << processingTime << " ms)" << std::endl;
    
//     // TIC(t);
//     // resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, vectorC, matrix);
//     // processingTime = TOC(t);
//     // cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     // res->SetLength(COLS);
//     // resInt64 = res->GetPackedValue();
//     // std::cout << "vectorC * matrix (by column packing)     = " << resInt64
//     //           << " (" << processingTime << " ms)" << std::endl;
    
//     // TIC(t);
//     // resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, vectorC, matrix, true, -1, false, false);
//     // processingTime = TOC(t);
//     // cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     // resInt64tmp = res->GetPackedValue();
//     // resInt64.clear();
//     // for (size_t i = 0; i < COLS; i++)
//     //     resInt64.push_back(resInt64tmp[nextPowerOf2(ROWS) * i]);
//     // std::cout << "vectorC * matrix (by column packing noT) = " << resInt64
//     //           << " (" << processingTime << " ms)" << std::endl;
    
//     ////////////////////////////////////////////////////////////
//     // Vector * matrix1 * matrix2
//     ////////////////////////////////////////////////////////////

//     // If you increase the matrix sizes, then remember to also generate more
//     // rotations keys accordingly.
//     const size_t n1 = 5;
//     const size_t n2 = 3;
//     const size_t n3 = 4;
//     const int64_t MAX_VALUE = 100;
    
//     std::vector<int64_t> vector = genRandVect(n1, MAX_VALUE);
//     Plaintext vectorP  = cryptoContext->MakePackedPlaintext(vector);

//     std::vector<std::vector<int64_t>> matrix1 = genRandMatrix(n1, n2, MAX_VALUE);
//     std::vector<std::vector<int64_t>> matrix2 = genRandMatrix(n2, n3, MAX_VALUE);
    
//     std::cout << "vector  = " << vector << std::endl;
//     std::cout << "matrix1 = " << matrix1 << std::endl;
//     std::cout << "matrix2 = " << matrix2 << std::endl;

//     Ciphertext<DCRTPoly> vectorC = cryptoContext->Encrypt(keyPair.publicKey, vectorP);

//     Ciphertext<DCRTPoly> resC;
//     Plaintext res;
//     std::vector<int64_t> resInt64, resInt64tmp;

//     TIC(t);
//     resInt64 = vectorMatrixMult(vector, matrix1);
//     resInt64 = vectorMatrixMult(resInt64, matrix2);
//     processingTime = TOC(t);
//     std::cout << "vector  * matrix1 * matrix2                         = "
//               << resInt64 << " (" << processingTime << " ms)" << std::endl;
    
//     TIC(t);
//     resC = vectorMatrixMultByInnProdCP(cryptoContext, keyPair.publicKey, vectorC, matrix1);
//     resC = vectorMatrixMultByInnProdCP(cryptoContext, keyPair.publicKey, resC, matrix2);
//     processingTime = TOC(t);
//     cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     res->SetLength(n3);
//     resInt64 = res->GetPackedValue();
//     std::cout << "vectorC * matrix1 * matrix2 (by inner product)      = "
//               << resInt64 << " (" << processingTime << " ms)" << std::endl;
    
//     TIC(t);
//     resC = vectorMatrixMultByInnProdFastCP(cryptoContext, keyPair.publicKey, vectorC, matrix1);
//     resC = vectorMatrixMultByInnProdFastCP(cryptoContext, keyPair.publicKey, resC, matrix2);
//     processingTime = TOC(t);
//     cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     res->SetLength(n3);
//     resInt64 = res->GetPackedValue();
//     std::cout << "vectorC * matrix1 * matrix2 (by inner product fast) = "
//               << resInt64 << " (" << processingTime << " ms)" << std::endl;

//     TIC(t);
//     resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, vectorC, matrix1);
//     resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, resC, matrix2);
//     processingTime = TOC(t);
//     cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     res->SetLength(n3);
//     resInt64 = res->GetPackedValue();
//     std::cout << "vectorC * matrix1 * matrix2 (by column packing)     = "
//               << resInt64 << " (" << processingTime << " ms)" << std::endl;
    
//     TIC(t);
//     resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, vectorC, matrix1, true, -1, true, false);
//     resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, resC, matrix2, false, n1, true, false);
//     processingTime = TOC(t);
//     cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
//     res->SetLength(n3);
//     resInt64 = res->GetPackedValue();
//     std::cout << "vectorC * matrix1 * matrix2 (by alternate packing)  = "
//               << resInt64 << " (" << processingTime << " ms)" << std::endl;

//     return 0;
// }
