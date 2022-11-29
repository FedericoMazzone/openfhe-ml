#include "../data/models/NNmodel.h"
#include "data_utils/load_mnist.h"
#include "he_utils/matrix_multiplication.h"
#include "vector_utils/vector_utils.h"


/**
 * Perform plaintext prediction for a two layers NN with square activation
 * function.
 * @param w0 first layer - weights
 * @param b0 first layer - biases
 * @param w1 second layer - weights
 * @param b1 second layer - biases
 * @param x input
 * @return plaintext predition
 */
std::vector<int64_t> predictPP(
        const std::vector<std::vector<int64_t>> &w0,
        const std::vector<int64_t> &b0,
        const std::vector<std::vector<int64_t>> &w1,
        const std::vector<int64_t> &b1,
        const std::vector<int64_t> &x
    )
{
    std::vector<int64_t> r;
    r = vectorMatrixMult(x, w0);
    r = addVectors(r, b0);
    r = multVectors(r, r);
    r = vectorMatrixMult(r, w1);
    r = addVectors(r, b1);
    r = multVectors(r, r);
    return r;
}


/**
 * Perform oblivious prediction for a two layers NN with square activation
 * function, with plaintext model and encrypted input.
 * @param cryptoContext the crypto context
 * @param publicKey the public key
 * @param w0 first layer - weights
 * @param b0 first layer - biases
 * @param w1 second layer - weights
 * @param b1 second layer - biases
 * @param xC encrypted input vector
 * @return encrypted predition
 */
Ciphertext<DCRTPoly> predictCP(
        CryptoContext<DCRTPoly> cryptoContext,
        PublicKey<DCRTPoly> publicKey,
        std::vector<std::vector<int64_t>> w0,
        std::vector<int64_t> b0,
        std::vector<std::vector<int64_t>> w1,
        std::vector<int64_t> b1,
        Ciphertext<DCRTPoly> xC
    )
{
    size_t n1 = w0.size();
    size_t n2 = w1.size();
    std::vector<std::vector<int64_t>> rb0;
    rb0.push_back(b0);
    rb0 = resizeMatrix(rb0, n1, n2);
    std::vector<int64_t> nb0 = flattenMatrix(rb0, false);
    Plaintext b0P = cryptoContext->MakePackedPlaintext(nb0);
    Plaintext b1P = cryptoContext->MakePackedPlaintext(b1);
    Ciphertext<DCRTPoly> resC;
    resC = vectorMatrixMultPackCP(cryptoContext, publicKey, xC, w0, true, -1, true, false);
    resC = cryptoContext->EvalAdd(resC, b0P);
    resC = cryptoContext->EvalMultAndRelinearize(resC, resC);
    resC = vectorMatrixMultPackCP(cryptoContext, publicKey, resC, w1, false, n1, true, false);
    resC = cryptoContext->EvalAdd(resC, b1P);
    resC = cryptoContext->EvalMult(resC, resC);
    return resC;
}


int main(int argc, char* argv[]) {

    std::vector<std::vector<int64_t>> trainX, testX;
    std::vector<int64_t> trainY, testY;

    loadMNIST(trainX, trainY, testX, testY);

    int scale = 1 << 2;
    std::vector<std::vector<int64_t>> scaledW0 = scaleMatrix(W0, scale);
    std::vector<int64_t> scaledB0 = scaleVector(B0, scale);
    std::vector<std::vector<int64_t>> scaledW1 = scaleMatrix(W1, scale);
    std::vector<int64_t> scaledB1 = scaleVector(B1, scale * scale * scale);

    // printMatrix(scaledW0);
    // printVector(scaledB0);
    // printMatrix(scaledW1);
    // printVector(scaledB1);

    // int correct = 0;
    // for (int id = 0; id < 10000; id++) {
    //     auto x = testX[id];
    //     auto y = testY[id];
    //     x = predictPP(scaledW0, scaledB0, scaledW1, scaledB1, x);
    //     // printVector(x);
    //     // std::cout << argmax(x) << " " << y << std::endl;
    //     if ((int64_t) argmax(x) == y)
    //         correct += 1;
    // }
    // std::cout << 1.0 * correct / 10000 << std::endl;

    TimeVar t;
    double processingTime(0.0);
 
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(536903681);
    parameters.SetMultiplicativeDepth(6);
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
    for (int i = 0; i <= 12; i++) {
        indexList.push_back(1 << i);
        indexList.push_back(-(1 << i));
    }
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);
    std::cout << "DONE" << std::endl;

    std::cout << std::endl;

    bool correctPrediction = true;
    for (int id = 0; id < 10000 && correctPrediction; id++) {
        
        auto x = testX[id];
    
        std::vector<int64_t> predictionPP = predictPP(scaledW0, scaledB0, scaledW1, scaledB1, x);

        Plaintext xP = cryptoContext->MakePackedPlaintext(x);
        Ciphertext<DCRTPoly> xC = cryptoContext->Encrypt(keyPair.publicKey, xP);
        TIC(t);
        Ciphertext<DCRTPoly> resC = predictCP(cryptoContext, keyPair.publicKey, scaledW0, scaledB0, scaledW1, scaledB1, xC);
        processingTime = TOC(t);
        Plaintext res;
        cryptoContext->Decrypt(keyPair.secretKey, resC, &res);
        size_t n3 = scaledW1[0].size();
        res->SetLength(n3);
        std::vector<int64_t> predictionCP = res->GetPackedValue();

        correctPrediction = std::equal(predictionPP.begin(), predictionPP.end(), predictionCP.begin());

        std::cout << "Prediction " << id << " - "
                  << (correctPrediction ? "CORRECT" : "ERROR")
                  << " (" << processingTime << " ms)" << std::endl;
    
    }

    return 0;

}
