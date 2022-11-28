#include "openfhe.h"

using namespace lbcrypto;


/**
 * Generate random vector of size length, with values in [-maxValue, maxValue).
 * @param length desired length of the vector
 * @param maxValue absolute maximum value of the coefficients
 * @return random vector
 */
std::vector<int64_t> genRandVect(
        size_t length,
        int64_t maxValue
    );


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
    );


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