cmake_minimum_required(VERSION 3.10)
project(LkTRS)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找必要的包
find_library(PBC_LIBRARY NAMES pbc)
find_library(GMP_LIBRARY NAMES gmp)

# 查找头文件目录
find_path(PBC_INCLUDE_DIR pbc/pbc.h)
find_path(GMP_INCLUDE_DIR gmp.h)

# 添加可执行文件
add_executable(lktrs 
    spk.cpp
    lktrs.cpp 
    accumulator.cpp
    main.cpp
)

# 包含目录
target_include_directories(lktrs PRIVATE
        ${PBC_INCLUDE_DIR}
        ${GMP_INCLUDE_DIR}
        )

# 链接库
target_link_libraries(lktrs
        ${PBC_LIBRARY}
        ${GMP_LIBRARY}
        )

# 如果在 Unix-like 系统上需要数学库
if(UNIX)
    target_link_libraries(lktrs m)
endif()

# 设置编译选项
if(CMAKE_COMPILER_IS_GNUCXX)
    target_compile_options(lktrs PRIVATE -Wall -Wextra)
endif()