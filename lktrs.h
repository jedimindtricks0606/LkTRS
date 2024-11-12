#ifndef LKTRS_H
#define LKTRS_H

#include <gmp.h>
#include <pbc/pbc.h>
#include <string>
#include <vector>
#include <map>
#include <utility>
#include "accumulator.h"

class LkTRS {
private:
    // PBC parameters
    const char* param_str;

    // System parameters
    pairing_t pairing;
    element_t g, h, u;        // Generators
    element_t g0, g1, g2;     // Random elements in G1
    element_t u_t;            // H'(issue)
    mpz_t p;                  // Prime order
    std::string issue;        // Current transaction round
    int k;                    // Maximum signing times

    // Accumulator
    Accumulator* acc = nullptr;

    // Helper functions
    void hash_to_Zp(element_t result, const std::string& input);
    void hash_to_Gp(element_t result, const std::string& input);

public:
    struct PublicKey {
        element_t u_i;
        element_t y_i;
    };

    struct SecretKey {
        element_t x_i;
        element_t s_i;
        element_t t_i;
    };

    // xi,si,ti,yi,cnti,wi
    struct SPK {
        SecretKey sk;
        int cnt;
        element_t w;
        std::string spk_generate(); // todo
        bool spk_verify(const std::string& spk); // todo
    };

    struct Signature {
        element_t V;          // Accumulator value
        element_t S;          // One-time pass
        element_t T;          // Tracing tag
        element_t R;          // Challenge
        SPK spk;              // SPK - Signature Proof of Knowledge
    };

    // Constructor
    LkTRS(const char* param_str, int max_signs);
    ~LkTRS();

    // Main interface methods
    bool Setup(size_t lambda);

    std::pair<PublicKey, SecretKey> KeyGen();

    bool Join(PublicKey& pk_j, Signature& sigma,
              element_t& V_out, element_t& w_i_out);

    bool Exit(PublicKey& pk_j, Signature& sigma,
              element_t& V_out);

    Signature RSign(const SecretKey& sk_i,
                    const std::vector<PublicKey>& L,
                    const std::string& message,
                    int cnt_i,
                    element_t& nym_out);

    bool RVer(const std::vector<PublicKey>& L,
              const std::string& message,
              const element_t nym,
              const Signature& sigma);

    bool Link(const std::string& m1, const element_t nym1, const Signature& sigma1,
              const std::string& m2, const element_t nym2, const Signature& sigma2);

    PublicKey kTrace( element_t nym1,  element_t nym2, 
                      std::string& m1,  Signature& sigma1,
                      std::string& m2,  Signature& sigma2);

private:
    // Helper method to compute accumulator
    void compute_accumulator(element_t result, const std::vector<PublicKey>& pks);

    // Helper method to compute witness
    void compute_witness(element_t result, const std::vector<PublicKey>& pks,
                         const PublicKey& excluded_pk);
};

#endif