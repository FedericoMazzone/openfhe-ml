#include "data_utils/load_mnist.h"
#include "he_utils/matrix_multiplication.h"

#include <iostream>
#include <vector>


int main(int argc, char* argv[]) {
    
    // std::vector<std::vector<int64_t>> trainX, testX;
    // std::vector<int64_t> trainY, testY;

    // loadMNIST(trainX, trainY, testX, testY);

    // for (size_t i = 0; i < trainX.size(); i++) {
    //     std::cout << i << " ";
    //     for (auto value : trainX[i])
    //         std::cout << value;
    //     std::cout << trainY[i] << std::endl;
    // }

    // for (size_t i = 0; i < testX.size(); i++) {
    //     std::cout << i << " ";
    //     for (auto value : testX[i])
    //         std::cout << value;
    //     std::cout << testY[i] << std::endl;
    // }

    TimeVar t;
    double processingTime(0.0);
 
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(536903681);
    parameters.SetMultiplicativeDepth(4);
    parameters.SetMaxRelinSkDeg(3);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    PlaintextModulus p = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();
    int n = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    double q = cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();
    std::cout << "Plaintext modulus (p) = " << p << std::endl;
    std::cout << "Polynomial degree (n) = " << n << std::endl;
    std::cout << "Ciphertext modulus bitsize (log2 q) = " << log2(q) << std::endl;

    KeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
    if (!keyPair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    std::cout << "Generating rotation keys... ";
    std::vector<int32_t> indexList = {};
    // for (int i = -100; i <= 100; i++) indexList.push_back(i);
    for (int i = 0; i <= 20; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);
    std::cout << "DONE" << std::endl;

    std::cout << std::endl;

    //////////////////////////////////////////////////////////
    // Vector * matrix1 * matrix2
    ////////////////////////////////////////////////////////////

    // If you increase the matrix sizes, then remember to also generate more
    // rotations keys accordingly.
    const size_t n1 = 50;
    const size_t n2 = 30;
    const size_t n3 = 40;
    const int64_t MAX_VALUE = 100;
    
    std::vector<int64_t> vector = genRandVect(n1, MAX_VALUE);
    Plaintext vectorP  = cryptoContext->MakePackedPlaintext(vector);

    std::vector<std::vector<int64_t>> matrix1 = genRandMatrix(n1, n2, MAX_VALUE);
    std::vector<std::vector<int64_t>> matrix2 = genRandMatrix(n2, n3, MAX_VALUE);
    
    std::cout << "vector  = " << vector << std::endl;
    std::cout << "matrix1 = " << matrix1 << std::endl;
    std::cout << "matrix2 = " << matrix2 << std::endl;

    Ciphertext<DCRTPoly> vectorC = cryptoContext->Encrypt(keyPair.publicKey, vectorP);

    Ciphertext<DCRTPoly> resC;
    Plaintext res;
    std::vector<int64_t> resInt64, resInt64tmp;

    TIC(t);
    resInt64 = vectorMatrixMult(vector, matrix1);
    resInt64 = vectorMatrixMult(resInt64, matrix2);
    processingTime = TOC(t);
    std::cout << "vector  * matrix1 * matrix2                         = "
              << resInt64 << " (" << processingTime << " ms)" << std::endl;
    
    TIC(t);
    resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, vectorC, matrix1, true, -1, true, false);
    resC = vectorMatrixMultPackCP(cryptoContext, keyPair.publicKey, resC, matrix2, false, n1, true, false);
    processingTime = TOC(t);
    cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
    res->SetLength(n3);
    resInt64 = res->GetPackedValue();
    std::cout << "vectorC * matrix1 * matrix2 (by alternate packing)  = "
              << resInt64 << " (" << processingTime << " ms)" << std::endl;

    return 0;

}
