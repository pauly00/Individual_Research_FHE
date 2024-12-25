// 연습용 코드 (ms seal)
#pragma once

#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// 1번 BFV 기본 예제
void example_bfv_basics();

// 2번 인코더 예제
void example_encoders();

// 3번 레벨 예제
void example_levels();

// 4번 BGV 기본 예제 (스킵)
void example_bgv_basics();

// 5번 CKKS 기본 예제
void example_ckks_basics();

// 6번 회전 예제
void example_rotation();

// 7번 직렬화 예제 (스킵)
void example_serialization();

// 8번 성능 테스트 예제 (스킵)
void example_performance_test();


// 헤더 함수: 예제 제목을 배너 형식으로 출력
inline void print_example_banner(std::string title)
{
    if (!title.empty())
    {
        std::size_t title_length = title.length();
        std::size_t banner_length = title_length + 2 * 10; // 배너의 총 길이 계산
        std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+"; // 상단 라인 생성
        std::string banner_middle = "|" + std::string(9, ' ') + title + std::string(9, ' ') + "|"; // 타이틀 출력

        // 배너 출력
        std::cout << std::endl << banner_top << std::endl << banner_middle << std::endl << banner_top << std::endl;
    }
}


// 헤더 함수: SEALContext의 파라미터를 출력
inline void print_parameters(const seal::SEALContext& context)
{
    auto& context_data = *context.key_context_data(); // 현재 컨텍스트 데이터 가져오기

    // 스킴 이름 확인
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV"; // BFV 스킴
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS"; // CKKS 스킴
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV"; // BGV 스킴
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }

    // 파라미터 출력
    std::cout << "/" << std::endl;
    std::cout << "| 암호화 파라미터 :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    // 계수 모듈러스 크기 출력
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    // BFV 스킴일 경우 plain_modulus 출력
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}


// 헤더 함수: parms_id를 ostream에 출력
inline std::ostream& operator<<(std::ostream& stream, seal::parms_id_type parms_id)
{
    // 현재 cout의 포맷 정보 저장
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    // 16진수로 parms_id 출력
    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
        << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    // 이전 포맷 정보 복원
    std::cout.copyfmt(old_fmt);

    return stream;
}


// 헤더 함수: 부동 소수점 벡터 출력
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    // std::cout의 포맷 정보 저장
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size(); // 벡터 크기 가져오기

    std::cout << std::fixed << std::setprecision(prec); // 소수점 자릿수 설정
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n"); // 벡터 전체 출력
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size)); // 출력할 사이즈로 벡터 크기 조정
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ","; // 앞부분 출력
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n"); // 뒷부분 출력
        }
    }
    std::cout << std::endl;

    // 이전 포맷 정보 복원
    std::cout.copyfmt(old_fmt);
}


// 헤더 함수: 행렬 출력
template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    std::size_t print_size = 5; // 출력할 열 크기

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ","; // 첫 번째 행 출력
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ","; // 두 번째 행 출력
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
}

// 헤더 함수: 행 번호 출력
inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}

// 헤더 함수: 값을 16진수 문자열로 변환
inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1)); // 값 변환
}
