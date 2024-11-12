#include "lktrs.h"
#include <iostream>

void LkTRS::hash_to_Zp(element_t result, const std::string& input) {
    // 使用输入字符串的简单哈希
    unsigned char hash[32] = {0};  // 用于存储哈希值

    // 一个简单的哈希实现
    for(size_t i = 0; i < input.length(); i++) {
        hash[i % 32] ^= input[i];
    }

    // 初始化为Zr中的元素
    element_init_Zr(result, pairing);

    // 将哈希值转换为大整数
    mpz_t z;
    mpz_init(z);
    mpz_import(z, 32, 1, 1, 0, 0, hash);

    // 将大整数转换为Zr中的元素
    element_set_mpz(result, z);

    mpz_clear(z);
}

void LkTRS::hash_to_Gp(element_t result, const std::string& input) {
    // 首先哈希到Zr
    element_t h;
    element_init_Zr(h, pairing);
    hash_to_Zp(h, input);

    // 初始化G1中的结果元素
    element_init_G1(result, pairing);

    // 使用生成元g来创建G1中的元素
    element_pow_zn(result, g, h);  // result = g^h

    element_clear(h);
}

// Constructor implementation
LkTRS::LkTRS(const char* param_str, int max_signs) {
    this->param_str = param_str;

    pairing_init_set_str(pairing, param_str);
    k = max_signs;

    element_init_G1(g, pairing);
    element_init_G2(h, pairing);
    element_init_G1(u, pairing);
    element_init_G1(g0, pairing);
    element_init_G1(g1, pairing);
    element_init_G1(g2, pairing);
    element_init_G1(u_t, pairing);

    mpz_init(p);
}

// Destructor implementation
LkTRS::~LkTRS() {
    if(acc) {
        delete acc;
        acc = nullptr;
    }

    element_clear(g);
    element_clear(h);
    element_clear(u);
    element_clear(g0);
    element_clear(g1);
    element_clear(g2);
    element_clear(u_t);
    mpz_clear(p);
    pairing_clear(pairing);
}

// Setup implementation
bool LkTRS::Setup(size_t lambda) {
    // Generate random generators
    element_random(g);
    element_random(h);
    element_random(u);

    // Generate random elements in G1
    element_random(g0);
    element_random(g1);
    element_random(g2);

    // Compute u_t = H'(issue)
    hash_to_Gp(u_t, issue);

    return true;
}

// KeyGen implementation
std::pair<LkTRS::PublicKey, LkTRS::SecretKey> LkTRS::KeyGen() {
    PublicKey pk;
    SecretKey sk;

    // Initialize elements
    element_init_Zr(sk.x_i, pairing);
    element_init_G1(pk.u_i, pairing);
    element_init_G1(pk.y_i, pairing);
    element_init_Zr(sk.s_i, pairing);
    element_init_Zr(sk.t_i, pairing);

    // Generate secret key x_i
    element_random(sk.x_i);

    // Generate random u_i and compute y_i
    element_random(pk.u_i);
    element_pow_zn(pk.y_i, pk.u_i, sk.x_i);

    // Compute s_i and t_i
    std::string x_i_str = ""; // Convert x_i to string
    hash_to_Zp(sk.s_i, x_i_str + issue + "0");
    hash_to_Zp(sk.t_i, x_i_str + issue + "1");

    return std::make_pair(pk, sk);
}

bool LkTRS::Join(PublicKey& pk_j, Signature& sigma,
                 element_t& V_out, element_t& w_i_out) {
    if(!acc) {
        acc = new Accumulator(param_str);
    }
    // Add the new user's public key to the accumulator
    try {
        acc->set_accumulator_value(sigma.V);
        acc->add_user(pk_j.u_i);
        acc->get_accumulator_value(V_out);
        acc->get_witness(pk_j.u_i, w_i_out);
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return false;
    }
    return true;
}

bool LkTRS::Exit(PublicKey& pk_j, Signature& sigma,
                 element_t& V_out) {
    if(!acc) {
        acc = new Accumulator(param_str);
    }
    // Remove the user's public key from the accumulator
    try {
        acc->set_accumulator_value(sigma.V);
        acc->remove_user(pk_j.u_i);
        acc->get_accumulator_value(V_out);
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return false;
    }
    return true;
}

bool LkTRS::Link(const std::string& m1, const element_t nym1, const Signature& sigma1,
                 const std::string& m2, const element_t nym2, const Signature& sigma2) {
    // simply check if the presudonyms are the same
    return nym1 == nym2;
}

LkTRS::PublicKey LkTRS::kTrace(element_t nym1, element_t nym2, 
                         std::string& m1,  Signature& sigma1,
                         std::string& m2,  Signature& sigma2) { 
    // Step 1: If the pseudonyms are different, return an invalid public key
    if (element_cmp(nym1, nym2) != 0) {
        return PublicKey();  // Return an empty PublicKey as an indication of invalid case
    }

    // Step 2: Check if the signature components are different (S1 != S2)
    if (element_cmp(sigma1.S, sigma2.S) != 0) {
        // Signatures have not exceeded the usage limit, return "legal"
        return PublicKey();  // Return an empty PublicKey for legal cases
    }

    // Step 3: If S1 == S2, calculate the public key of the signer and trace it
    // Compute y_i using the formula y_i = ((T1^R2) / (T2^R1)) ^ (R2 - R1)^(-1)
    element_t y_i;
    element_init_G1(y_i, pairing);

    // First, compute the intermediate values (T1^R2) and (T2^R1)
    element_t term1, term2, inv_R_diff;
    element_init_G1(term1, pairing);
    element_init_G1(term2, pairing);
    element_init_Zr(inv_R_diff, pairing);

    // Compute (T1^R2)
    element_pow_zn(term1, sigma1.T, sigma2.R);  // T1^R2
    // Compute (T2^R1)
    element_pow_zn(term2, sigma2.T, sigma1.R);  // T2^R1

    // Compute (R2 - R1)^(-1)
    element_sub(inv_R_diff, sigma2.R, sigma1.R);  // R2 - R1
    element_invert(inv_R_diff, inv_R_diff);  // (R2 - R1)^(-1)

    // Compute y_i = ((T1^R2) / (T2^R1))^(R2 - R1)^(-1)
    element_div(term1, term1, term2);  // (T1^R2) / (T2^R1)
    element_pow_zn(y_i, term1, inv_R_diff);  // y_i = ((T1^R2) / (T2^R1)) ^ (R2 - R1)^(-1)

    // Clean up intermediate elements
    element_clear(term1);
    element_clear(term2);
    element_clear(inv_R_diff);

    // Step 4: Return the public key (u_i, y_i)
    // PublicKey contains the user public key and computed y_i
    PublicKey pk;
    element_set(pk.y_i, y_i); // u_i here is random
    return pk;
}


