#include "lktrs.h"
#include <iostream>

int main() {
    // PBC Type A参数
    const char* param = "type a\n"
                        "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
                        "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
                        "r 730750818665451621361119245571504901405976559617\n"
                        "exp2 159\n"
                        "exp1 107\n"
                        "sign1 1\n"
                        "sign0 1\n";

    // 创建LkTRS实例
    LkTRS scheme(param, 5);  // k = 5表示最大签名次数

    // 初始化系统
    if (!scheme.Setup(256)) {
        std::cout << "Setup failed" << std::endl;
        return 1;
    }

    // 生成密钥对（生成账户）
    auto [pk, sk] = scheme.KeyGen();
    std::cout << "Key generation successful" << std::endl;

    // 生成n对密钥...

    // 构建一个由n个用户组成的环

    // 签名

    // 验证

    return 0;
}

