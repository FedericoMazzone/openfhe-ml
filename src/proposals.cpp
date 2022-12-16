#include "openfhe.h"

#include <iostream>

using namespace lbcrypto;



/**
 * Proposal for overloading Decrypt method with one that returns a Plaintext
 * (instead of passing it as a reference and returning a decrypt result).
 * It should go inside CryptoContextImpl class.
 */
template <typename Element>
Plaintext Decrypt(
    CryptoContext<Element> cc,
    const PrivateKey<Element> &s,
    const Ciphertext<Element> &c
)
{
    Plaintext plaintext;
    cc->Decrypt(s, c, &plaintext);
    // consider checking decryption result and throwing an exception here
    return plaintext;
}




/**
 * Proposal for utility method to decrypt and print decryption on the fly.
 * It should go inside CryptoContextImpl class.
 */
template <typename Element>
inline void printDecryption(
    CryptoContext<Element> cc,
    const PrivateKey<Element> &s,
    const Ciphertext<Element> &c,
    const size_t length = 0,
    const std::string label = ""
)
{
    try {
        Plaintext plaintext = Decrypt(cc, s, c);
        if (length > 0) plaintext->SetLength(length);
        std::cout << "Decryption " << label << " [level " << c->GetLevel()
                << "] " << plaintext;
    } catch (const std::exception& e) {
        std::cout << "Decryption " << label << " [level " << c->GetLevel()
                << "] failed" << std::endl;
    }
}



/**
 * Proposal for shifting operators for Ciphertext.
 * They should go inside CiphertextImpl class.
*/
template <typename Element>
Ciphertext<Element> operator<<(const Ciphertext<Element>& a, int32_t index) {
    return a->GetCryptoContext()->EvalRotate(a, index);
}

template <typename Element>
Ciphertext<Element> operator>>(const Ciphertext<Element>& a, int32_t index) {
    return a->GetCryptoContext()->EvalRotate(a, -index);
}







int main(int argc, char* argv[]) {

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(50);
    // parameters.SetBatchSize(16);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> kp = cc->KeyGen();

    cc->EvalMultKeysGen(kp.secretKey);

    std::vector<int32_t> indexList = {};
    for (int i = -10; i <= 10; i++) indexList.push_back(i);
    cc->EvalRotateKeyGen(kp.secretKey, indexList);

    std::vector<double> v = {1., 2., 3., 4., 5.};
    Plaintext vP = cc->MakeCKKSPackedPlaintext(v);

    Ciphertext<DCRTPoly> c = cc->Encrypt(kp.publicKey, vP);

    Plaintext plaintext = Decrypt(cc, kp.secretKey, c);
    plaintext->SetLength(vP->GetLength());
    std::cout << plaintext;

    printDecryption(cc, kp.secretKey, c, vP->GetLength(), "v");
    printDecryption(cc, kp.secretKey, c * c, vP->GetLength(), "v");
    printDecryption(cc, kp.secretKey, c << 3, vP->GetLength() - 3, "v << 3");

    // Before: a bit cumbersome.
    Ciphertext<DCRTPoly> rotatedC = cc->EvalRotate(c, -2);
    Plaintext plaintextTmp;
    cc->Decrypt(kp.secretKey, rotatedC, &plaintextTmp);
    plaintextTmp->SetLength(vP->GetLength() + 2);
    std::cout << "Decryption v >> 2 " << plaintextTmp;

    // After: useful to check things on the fly.
    printDecryption(cc, kp.secretKey, c >> 2, vP->GetLength() + 2, "v >> 2");

    return 0;
    
}
