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
  Bootstrapping for BFV. Following the approach of Mouchet et al. "Multiparty
  Homomorphic Encryption from Ring-Learning-with-Errors"
 */

#include "openfhe.h"
#include "vector_utils/vector_utils.h"

using namespace lbcrypto;


/**
 * Aggregate a list of public key shares into a master public key.
 * @param cc the crypto context
 * @param pkShare vector of public key shares
 * @return master public key (aggregation of all the shares)
 */
PublicKey<DCRTPoly> aggregatePkShares(
    const CryptoContext<DCRTPoly> &cc,
    const std::vector<PublicKey<DCRTPoly>> &pkShare
)
{
    PublicKey<DCRTPoly> masterPk(std::make_shared<PublicKeyImpl<DCRTPoly>>(cc));

    const DCRTPoly a = pkShare[0]->GetPublicElements()[1];

    const auto paramsPK = cc->GetCryptoParameters()->GetParamsPK();
    DCRTPoly b = DCRTPoly(paramsPK, Format::EVALUATION, true);
    for (size_t i = 0; i < pkShare.size(); i++)
        b += pkShare[i]->GetPublicElements()[0];
    
    masterPk->SetPublicElementAtIndex(0, std::move(b));
    masterPk->SetPublicElementAtIndex(1, std::move(a));

    return masterPk;
}


/**
 * Calculate and return lower bound that can be encoded with the plaintext
 * modulus the number to encode MUST be greater than this value.
 * @param p the plaintext modulus
 * @return floor(-p/2)
 */
inline int64_t LowBound(
    const PlaintextModulus p 
)
{
    uint64_t half = p >> 1;
    bool odd = (p & 0x1) == 1;
    int64_t bound = -1 * half;
    if (odd)
        bound--;
    return bound;
}


/**
 * Calculate and return upper bound that can be encoded with the plaintext
 * modulus the number to encode MUST be less than or equal to this value.
 * @param p the plaintext modulus
 * @return floor(p/2)
 */
inline int64_t HighBound(
    const PlaintextModulus p 
)
{
    return p >> 1;
}


/**
 * Generate message uniformely at random.
 * @param cc the crypto context
 * @return the random message
 */
std::vector<int64_t> genRandMessage(
    const CryptoContext<DCRTPoly> &cc
)
{
    const PlaintextModulus p = cc->GetCryptoParameters()->GetPlaintextModulus();
    const int n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    std::vector<int64_t> v = genRandVect(n, HighBound(p));
    return v;
}


/**
 * Multiply (in place) a polynomial by Delta := q / t.
 * @param cc the crypto context
 * @param value the polynomial
 */
void timesDelta(
    const CryptoContext<DCRTPoly> &cc,
    DCRTPoly &value
)
{
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();
    auto encParams = elementParams;
    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        encParams = cryptoParams->GetParamsQr();
        value.SetFormat(Format::COEFFICIENT);
        Poly bigPtxt = value.CRTInterpolate();
        DCRTPoly plain(bigPtxt, encParams);
        value = plain;
        tInvModq = cryptoParams->GettInvModqr();
    }
    value.SetFormat(Format::COEFFICIENT);
    NativeInteger NegQModt       = cryptoParams->GetNegQModt();
    NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon();
    if (cryptoParams->GetEncryptionTechnique() == EXTENDED) {
        NegQModt       = cryptoParams->GetNegQrModt();
        NegQModtPrecon = cryptoParams->GetNegQrModtPrecon();
    }
    const NativeInteger t = cryptoParams->GetPlaintextModulus();
    value.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
    value.SetFormat(Format::EVALUATION);
}


/**
 * Multiply a polynomial by t / q and round it.
 * @param cc the crypto context
 * @param value the polynomial
 * @return scaled and rounded polynomial
 */
DCRTPoly scaleAndRound(
    const CryptoContext<DCRTPoly> &cc,
    DCRTPoly value
)
{
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(
        cc->GetCryptoParameters());

    Plaintext plaintext = cc->MakePackedPlaintext({0});
    NativePoly poly = plaintext->GetElement<NativePoly>();

    if (cryptoParams->GetMultiplicationTechnique() == HPS ||
        cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ ||
        cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED)
    {
        poly = value.ScaleAndRound(
                cryptoParams->GetPlaintextModulus(),
                cryptoParams->GettQHatInvModqDivqModt(),
                cryptoParams->GettQHatInvModqDivqModtPrecon(),
                cryptoParams->GettQHatInvModqBDivqModt(),
                cryptoParams->GettQHatInvModqBDivqModtPrecon(),
                cryptoParams->GettQHatInvModqDivqFrac(),
                cryptoParams->GettQHatInvModqBDivqFrac()
            );
    } else {
        poly = value.ScaleAndRound(
                cryptoParams->GetModuliQ(),
                cryptoParams->GetPlaintextModulus(),
                cryptoParams->Gettgamma(),
                cryptoParams->GettgammaQHatInvModq(),
                cryptoParams->GettgammaQHatInvModqPrecon(),
                cryptoParams->GetNegInvqModtgamma(),
                cryptoParams->GetNegInvqModtgammaPrecon()
            );
    }

    auto result = DecryptResult(poly.GetLength());
    plaintext->SetScalingFactorInt(result.scalingFactorInt);
    plaintext->Decode();

    return plaintext->GetElement<DCRTPoly>();
}


/**
 * Generate uniformly random polynomial.
 * @param cc the crypto context
 * @return random polynomial
 */
DCRTPoly genRandPoly(
    const CryptoContext<DCRTPoly> &cc
)
{
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();

    DCRTPoly::DugType dug;
    DCRTPoly randPoly(dug, elementParams, Format::EVALUATION);

    return randPoly;
}


/**
 * Create new ciphertext.
 * @param cc the crypto context
 * @return new ciphertext
 */
Ciphertext<DCRTPoly> newCiphertext(
    const CryptoContext<DCRTPoly> &cc,
    const DCRTPoly &c0,
    const DCRTPoly &c1
)
{
    Ciphertext<DCRTPoly> ciphertext(std::make_shared<CiphertextImpl<DCRTPoly>>(cc));

    Plaintext dummyP = cc->MakePackedPlaintext({0});
    ciphertext->SetElements({std::move(c0), std::move(c1)});
    ciphertext->SetEncodingType(dummyP->GetEncodingType());
    ciphertext->SetScalingFactor(dummyP->GetScalingFactor());
    ciphertext->SetScalingFactorInt(dummyP->GetScalingFactorInt());
    ciphertext->SetDepth(dummyP->GetDepth());
    ciphertext->SetLevel(dummyP->GetLevel());
    ciphertext->SetSlots(dummyP->GetSlots());

    return ciphertext;
}


/**
 * Generate modified decryption shares for the encryption-to-share protocol.
 * @param cc the crypto context
 * @param ciphertext the ciphertext
 * @param privateKeyShare a private key share
 * @param modDecShare variable to store the modified decryption share
 * @return message share
 */
std::vector<int64_t> enc2ShareMain(
    const CryptoContext<DCRTPoly> &cc,
    const Ciphertext<DCRTPoly> ciphertext,
    const PrivateKey<DCRTPoly> privateKeyShare,
    DCRTPoly &modDecShare
)
{
    // m_i
    std::vector<int64_t> msgShare = genRandMessage(cc);
    Plaintext msgShareP = cc->MakePackedPlaintext(msgShare);
    DCRTPoly msgSharePoly = msgShareP->GetElement<DCRTPoly>();

    // Delta * m_i
    timesDelta(cc, msgSharePoly);

    // h_i := s_i * c[1] + e_i
    auto decShare = cc->MultipartyDecryptMain({ciphertext}, privateKeyShare);
    DCRTPoly hi = decShare[0]->GetElements()[0];

    // h_i - Delta * m_i
    modDecShare = hi - msgSharePoly;

    return msgShare;
}


/**
 * Generate the final message share for the encryption-to-share protocol.
 * @param cc the crypto context
 * @param ciphertext the ciphertext
 * @param privateKeyShare a private key share
 * @param modDecShare vector of modified decryption shares from the other
 * parties
 * @return message share
 */
std::vector<int64_t> enc2ShareLead(
    const CryptoContext<DCRTPoly> &cc,
    ConstCiphertext<DCRTPoly> ciphertext,
    const PrivateKey<DCRTPoly> privateKeyShare,
    const std::vector<DCRTPoly> &modDecShare
)
{
    std::vector<DCRTPoly> cv = ciphertext->GetElements();
    
    // c = (c[0] + sum(i > 0)(h_i), c[1])
    for (const DCRTPoly &mds : modDecShare)
        cv[0] += mds;
    Ciphertext<DCRTPoly> modifiedCiphertext = ciphertext->Clone();
    modifiedCiphertext->SetElements({cv[0], cv[1]});

    // m_0 = Decrypt(s_0, c)
    Plaintext msgShareP;
    cc->Decrypt(privateKeyShare, modifiedCiphertext, &msgShareP);
    std::vector<int64_t> msgShare = msgShareP->GetPackedValue();

    return msgShare;
}


/**
 * Generate ciphertext share for the share-to-encryption protocol.
 * @param cc the crypto context
 * @param privateKeyShare a private key share
 * @param msgShare a message share
 * @param commPoly common polynomial
 * @return encryption share
 */
DCRTPoly share2EncGen(
    const CryptoContext<DCRTPoly> &cc,
    const PrivateKey<DCRTPoly> &privateKeyShare,
    const std::vector<int64_t> &msgShare,
    const DCRTPoly &commPoly
)
{
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    const auto elementParams = cryptoParams->GetElementParams();

    // m_i
    Plaintext msgShareP = cc->MakePackedPlaintext(msgShare);
    DCRTPoly msgSharePoly = msgShareP->GetElement<DCRTPoly>();

    // Delta * m_i
    timesDelta(cc, msgSharePoly);

    // s_i
    const DCRTPoly& s = privateKeyShare->GetPrivateElement();
    uint32_t sizeQ  = s.GetParams()->GetParams().size();
    uint32_t sizeQl = elementParams->GetParams().size();

    // e_i
    const auto ns = cryptoParams->GetNoiseScale();
    const DCRTPoly::DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    DCRTPoly e(dgg, elementParams, Format::EVALUATION);

    // Delta * m_i - s_i * a + e_i
    DCRTPoly encShare;
    if (sizeQl != sizeQ) {
        // Clone secret key because we need to drop towers.
        DCRTPoly scopy(s);
        uint32_t diffQl = sizeQ - sizeQl;
        scopy.DropLastElements(diffQl);
        encShare = msgSharePoly - commPoly * scopy + ns * e;
    }
    else {
        // Use secret key as is
        encShare = msgSharePoly - commPoly * s + ns * e;
    }

    return encShare;
}


/**
 * Aggregate ciphertext shares for the share-to-encryption protocol.
 * @param cc the crypto context
 * @param encShare vector of encryption shares
 * @param commPoly common polynomial
 * @return ciphertext
 */
Ciphertext<DCRTPoly> share2EncAggr(
    const CryptoContext<DCRTPoly> &cc,
    const std::vector<DCRTPoly> &encShare,
    const DCRTPoly &commPoly
)
{
    DCRTPoly c0 = encShare[0];
    for (size_t i = 1; i < encShare.size(); i++)
        c0 += encShare[i];
    
    Ciphertext<DCRTPoly> ciphertext = newCiphertext(cc, c0, commPoly);

    return ciphertext;
}


// Functions to simulate multiparty protocols are defined here.
namespace protocol {

    /**
     * Multiparty key generation protocol.
     * @param cc the crypto context
     * @param s_out vector to store secret key shares
     * @param pk_out variable to store the master public key
     */
    void multipartyKeyGen(
        const CryptoContext<DCRTPoly> &cc,
        std::vector<PrivateKey<DCRTPoly>> &s_out,
        PublicKey<DCRTPoly> &pk_out
    )
    {
        const size_t N = s_out.size();

        // KeyPair<DCRTPoly> kp = cc->KeyGen();
        // s_out[0] = kp.secretKey;
        // for (size_t i = 1; i < N; i++) {
        //     // kp.publicKey = partial sum of public keys so far (a * s[i] - e)
        //     kp = cc->MultipartyKeyGen(kp.publicKey);
        //     s_out[i] = kp.secretKey;
        // }
        // pk_out = kp.publicKey;

        std::vector<PublicKey<DCRTPoly>> pkShare(N);
        KeyPair<DCRTPoly> kp = cc->KeyGen();
        pkShare[0] = kp.publicKey;
        s_out[0] = kp.secretKey;
        for (size_t i = 1; i < N; i++) {
            kp = cc->MultipartyKeyGen(kp.publicKey, false, true);
            pkShare[i] = kp.publicKey;
            s_out[i] = kp.secretKey;
        }
        pk_out = aggregatePkShares(cc, pkShare);
    }


    /**
     * Multiparty multiplication evaluation key generation protocol.
     * @param cc the crypto context
     * @param s vector of secret key shares
     * @param pk master public key
     */
    void multipartyEvalMultKeyGen(
        const CryptoContext<DCRTPoly> &cc,
        const std::vector<PrivateKey<DCRTPoly>> &s,
        const PublicKey<DCRTPoly> &pk
    )
    {
        // // evalmult key share for P0
        // auto evalMultKey0 = cc->KeySwitchGen(s[0], s[0]);
        // // evalmult key share for P1
        // auto evalMultKey1 = cc->MultiKeySwitchGen(s[1], s[1], evalMultKey0);
        // // evalmult key share for P2
        // auto evalMultKey2 = cc->MultiKeySwitchGen(s[2], s[2], evalMultKey1);

        // // joint evalmult key for (s0 + s1 + s2)
        // auto evalMult012 = cc->MultiAddEvalKeys(evalMultKey0, evalMultKey1, pk->GetKeyTag());
        // evalMult012 = cc->MultiAddEvalKeys(evalMult012, evalMultKey2, pk->GetKeyTag());
        // // joint evalmult key for s0 * (s0 + s1 + s2)
        // auto evalMult0012 = cc->MultiMultEvalKey(s[0], evalMult012, pk->GetKeyTag());
        // // joint evalmult key for s1 * (s0 + s1 + s2)
        // auto evalMult1012 = cc->MultiMultEvalKey(s[1], evalMult012, pk->GetKeyTag());
        // // joint evalmult key for s2 * (s0 + s1 + s2)
        // auto evalMult2012 = cc->MultiMultEvalKey(s[2], evalMult012, pk->GetKeyTag());
        // // joint evalmult key for (s0 + s1) * (s0 + s1)
        // auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMult0012, evalMult1012, evalMult012->GetKeyTag());
        // evalMultFinal = cc->MultiAddEvalMultKeys(evalMultFinal, evalMult2012, evalMult012->GetKeyTag());

        // cc->InsertEvalMultKey({evalMultFinal});

        const size_t N = s.size();

        EvalKey<DCRTPoly> evalMultKeyShare = cc->KeySwitchGen(s[0], s[0]);
        EvalKey<DCRTPoly> evalMultKey = evalMultKeyShare;
        for (size_t i = 1; i < N; i++) {
            evalMultKeyShare = cc->MultiKeySwitchGen(s[i], s[i], evalMultKey);
            evalMultKey = cc->MultiAddEvalKeys(evalMultKey, evalMultKeyShare, pk->GetKeyTag());
        }

        evalMultKeyShare = cc->MultiMultEvalKey(s[0], evalMultKey, pk->GetKeyTag());
        EvalKey<DCRTPoly> evalMultFinal = evalMultKeyShare;
        for (size_t i = 1; i < N; i++) {
            evalMultKeyShare = cc->MultiMultEvalKey(s[i], evalMultKey, pk->GetKeyTag());
            evalMultFinal = cc->MultiAddEvalMultKeys(evalMultFinal, evalMultKeyShare, evalMultKey->GetKeyTag());
        }

        cc->InsertEvalMultKey({evalMultFinal});
    }


    /**
     * Multiparty rotation key generation protocol.
     * @param cc the crypto context
     * @param s vector of secret key shares
     * @param pk master public key
     * @param indices vector of rotation indices
     */
    void multipartyRotKeyGen(
        const CryptoContext<DCRTPoly> &cc,
        const std::vector<PrivateKey<DCRTPoly>> &s,
        const PublicKey<DCRTPoly> &pk,
        const std::vector<int32_t> &indices
    )
    {
        const size_t N = s.size();

        cc->EvalRotateKeyGen(s[0], indices);
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> evalRotateKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalAutomorphismKeyMap(s[0]->GetKeyTag()));
        std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> evalRotateKeysJoin = evalRotateKeys;
        for (size_t i = 1; i < N; i++) {
            evalRotateKeys = cc->MultiEvalAtIndexKeyGen(s[i], evalRotateKeys, indices, pk->GetKeyTag());
            evalRotateKeysJoin = cc->MultiAddEvalAutomorphismKeys(evalRotateKeysJoin, evalRotateKeys, pk->GetKeyTag());
        }
        
        cc->InsertEvalAutomorphismKey(evalRotateKeysJoin);
    }


    /**
     * Multiparty decryption protocol.
     * @param cc the crypto context
     * @param s vector of secret key shares
     * @param c the ciphertext
     * @return the plaintext
     */
    Plaintext multipartyDecrypt(
        const CryptoContext<DCRTPoly> &cc,
        const std::vector<PrivateKey<DCRTPoly>> &s,
        const Ciphertext<DCRTPoly> &c
    )
    {
        Plaintext result;
        const size_t N = s.size();
        std::vector<Ciphertext<DCRTPoly>> decryptionShare(N);

        // s[i] * c[1] + e
        auto partialDec = cc->MultipartyDecryptLead({c}, s[0]);
        decryptionShare[0] = partialDec[0];
        for (size_t i = 1; i < N; i++) {
            partialDec = cc->MultipartyDecryptMain({c}, s[i]);
            decryptionShare[i] = partialDec[0];
        }

        cc->MultipartyDecryptFusion(decryptionShare, &result);

        return result;
    }


    /**
     * Multiparty bootstrapping protocol.
     * @param cc the crypto context
     * @param s vector of secret key shares
     * @param ciphertext the ciphertext
     * @return refreshed ciphertext
     */
    Ciphertext<DCRTPoly> bootstrap_not_working(
        const CryptoContext<DCRTPoly> &cc,
        const std::vector<PrivateKey<DCRTPoly>> &s,
        const Ciphertext<DCRTPoly> &ciphertext
    )
    {
        const size_t N = s.size();
        DCRTPoly a = genRandPoly(cc);

        std::vector<DCRTPoly> h0Share(N);
        std::vector<DCRTPoly> h1Share(N);
        std::vector<int64_t> msgShare;
        for (size_t i = 0; i < N; i++) {
            msgShare = enc2ShareMain(cc, ciphertext, s[i], h0Share[i]);
            h1Share[i] = share2EncGen(cc, s[i], msgShare, a);
        }

        DCRTPoly h0 = h0Share[0];
        DCRTPoly h1 = h1Share[0];
        for (size_t i = 1; i < N; i++) {
            h0 += h0Share[i];
            h1 += h1Share[i];
        }

        // c0
        DCRTPoly c0 = ciphertext->GetElements()[0];

        // Something wrong here -->
        // [(t / q) * (c0 + h0)]
        c0 = scaleAndRound(cc, c0);

        // [(t / q) * (c0 + h0)] * Delta
        timesDelta(cc, c0);
        // <--

        // [(t / q) * (c0 + h0)] * Delta + h1
        Ciphertext<DCRTPoly> bsCiphertext = newCiphertext(cc, c0 + h1, a);

        return bsCiphertext;

    }


    /**
     * Multiparty bootstrapping protocol.
     * @param cc the crypto context
     * @param s vector of secret key shares
     * @param ciphertext the ciphertext
     * @return refreshed ciphertext
     */
    Ciphertext<DCRTPoly> bootstrap(
        const CryptoContext<DCRTPoly> &cc,
        const std::vector<PrivateKey<DCRTPoly>> &s,
        const Ciphertext<DCRTPoly> &ciphertext
    )
    {
        const size_t N = s.size();
        DCRTPoly a = genRandPoly(cc);

        std::vector<DCRTPoly> h0Share(N - 1);
        std::vector<DCRTPoly> h1Share(N);
        std::vector<int64_t> msgShare;
        for (size_t i = 1; i < N; i++) {
            msgShare = enc2ShareMain(cc, ciphertext, s[i], h0Share[i - 1]);
            h1Share[i] = share2EncGen(cc, s[i], msgShare, a);
        }
        msgShare = enc2ShareLead(cc, ciphertext, s[0], h0Share);
        h1Share[0] = share2EncGen(cc, s[0], msgShare, a);
        Ciphertext<DCRTPoly> bsCiphertext = share2EncAggr(cc, h1Share, a);

        return bsCiphertext;
    }

} // namespace protocol


int main(int argc, char* argv[]) {

    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    // enable features that you wish to use
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);

    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    // Output the generated parameters
    PlaintextModulus p = cc->GetCryptoParameters()->GetPlaintextModulus();
    int n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    double q = cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble();
    const auto cryptoParamsTmp = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
    
    std::cout << std::endl;
    std::cout << "Plaintext modulus (p) = " << p << std::endl;
    std::cout << "Polynomial degree (n) = " << n << std::endl;
    std::cout << "Ciphertext modulus bitsize (log2 q) = " << log2(q) << std::endl;
    std::cout << "Plaintext Lower Bound (excluded): " << LowBound(p) << std::endl;
    std::cout << "Plaintext Higher Bound (included): " << HighBound(p) << std::endl;
    std::cout << "Secret Key Distribution: " << cryptoParamsTmp->GetSecretKeyDist() << std::endl;
    std::cout << "Encryption Technique: " << cryptoParamsTmp->GetEncryptionTechnique() << std::endl;
    std::cout << "Multiplication Technique: " << cryptoParamsTmp->GetMultiplicationTechnique() << std::endl;
    std::cout << "Scaling Technique: " << cryptoParamsTmp->GetScalingTechnique() << std::endl;
    std::cout << "Digit Size: " << cryptoParamsTmp->GetDigitSize() << std::endl;

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////
    
    std::vector<int64_t> v = {1, 2, 3, 4, 5};
    Plaintext vP = cc->MakePackedPlaintext(v);

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////

    // Number of players
    const size_t N = (argc > 1) ? atoi(argv[1]) : 5;
    std::cout << "N = " << N << std::endl;

    std::vector<PrivateKey<DCRTPoly>> s(N);
    PublicKey<DCRTPoly> pk;
    protocol::multipartyKeyGen(cc, s, pk);

    std::cout << "Secret Share[0] -> Number of Elements: "
              << s[0]->GetPrivateElement().GetNumOfElements()
              << std::endl << std::endl;

    protocol::multipartyEvalMultKeyGen(cc, s, pk);

    std::vector<int32_t> indices = {-2, -1, 1, 2};
    protocol::multipartyRotKeyGen(cc, s, pk, indices);

    // cc->EvalSumKeyGen(s[0]);
    // auto evalSumKeys = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(s[0]->GetKeyTag()));
    // auto evalSumKeysB = cc->MultiEvalSumKeyGen(s[1], evalSumKeys, pk->GetKeyTag());
    // auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, pk->GetKeyTag());
    // cc->InsertEvalSumKey(evalSumKeysJoin);

    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> vC = cc->Encrypt(pk, vP);

    ////////////////////////////////////////////////////////////
    // Homomorphic Operations
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> vaddC = cc->EvalAdd(vC, vC);
    Ciphertext<DCRTPoly> vmultC = cc->EvalMult(vC, vC);
    Ciphertext<DCRTPoly> vmult2C = cc->EvalMult(vmultC, vC);
    Ciphertext<DCRTPoly> vshiftC = cc->EvalRotate(vC, 2);

    ////////////////////////////////////////////////////////////
    // Decryption
    ////////////////////////////////////////////////////////////

    std::cout << "Original " << vP << std::endl;

    Plaintext vDP = protocol::multipartyDecrypt(cc, s, vC);
    vDP->SetLength(vP->GetLength());
    std::cout << "Decryption v " << vDP << std::endl;

    Plaintext vaddDP = protocol::multipartyDecrypt(cc, s, vaddC);
    vaddDP->SetLength(vP->GetLength());
    std::cout << "Decryption v + v " << vaddDP << std::endl;

    Plaintext vmultDP = protocol::multipartyDecrypt(cc, s, vmultC);
    vmultDP->SetLength(vP->GetLength());
    std::cout << "Decryption v ^ 2 " << vmultDP << std::endl;

    Plaintext vmult2DP = protocol::multipartyDecrypt(cc, s, vmult2C);
    vmult2DP->SetLength(vP->GetLength());
    std::cout << "Decryption v ^ 3 " << vmult2DP << std::endl;

    Plaintext vshiftDP = protocol::multipartyDecrypt(cc, s, vshiftC);
    vshiftDP->SetLength(vP->GetLength());
    std::cout << "Decryption v << 2 " << vshiftDP << std::endl;

    std::cout << std::endl;

    ////////////////////////////////////////////////////////////
    // Encryption to Shares
    ////////////////////////////////////////////////////////////

    std::vector<std::vector<int64_t>> share(N);
    std::vector<DCRTPoly> modDecShare(N - 1);
    for (size_t i = 1; i < N; i++)
        share[i] = enc2ShareMain(cc, vmultC, s[i], modDecShare[i - 1]);
    share[0] = enc2ShareLead(cc, vmultC, s[0], modDecShare);

    std::vector<int64_t> result = share[0];
    for (size_t i = 1; i < N; i++)
        result = addVectors(result, share[i], (int64_t) p);
    Plaintext res = cc->MakePackedPlaintext(result);
    std::cout << "Enc2Share shares sum: " << res << std::endl;

    ////////////////////////////////////////////////////////////
    // Shares to Encryption
    ////////////////////////////////////////////////////////////

    DCRTPoly commPoly = genRandPoly(cc);
    std::vector<DCRTPoly> encShare(N);
    for (size_t i = 0; i < N; i++) 
        encShare[i] = share2EncGen(cc, s[i], share[i], commPoly);
    Ciphertext<DCRTPoly> vfreshC = share2EncAggr(cc, encShare, commPoly);

    Plaintext vfreshDP = protocol::multipartyDecrypt(cc, s, vfreshC);
    vfreshDP->SetLength(vP->GetLength());
    std::cout << "Share2Enc decryption " << vfreshDP << std::endl;

    std::cout << std::endl;

    ////////////////////////////////////////////////////////////
    // Bootstrapping
    ////////////////////////////////////////////////////////////

    Ciphertext<DCRTPoly> vbsC = protocol::bootstrap(cc, s, vmultC);
    Plaintext vbsDP = protocol::multipartyDecrypt(cc, s, vbsC);
    vbsDP->SetLength(vP->GetLength());
    std::cout << "Bootstrapping " << vbsDP << std::endl;

    Ciphertext<DCRTPoly> vmult2bsC = cc->EvalMult(vbsC, vC);

    Plaintext vmult2bsDP = protocol::multipartyDecrypt(cc, s, vmult2bsC);
    vmult2bsDP->SetLength(vP->GetLength());
    std::cout << "Decryption v ^ 3 (bootstrapping) " << vmult2bsDP << std::endl;

    std::cout << std::endl;

    return 0;
}
