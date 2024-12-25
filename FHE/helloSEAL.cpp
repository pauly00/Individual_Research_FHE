// 연습용 코드(ms seal)
#include "examples.h"

using namespace std;
using namespace seal;

// 1번. 간단한 연산 수행
void example_bfv_basics()
{
    print_example_banner("Example: BFV Basics");

    // BFV 암호화 방식을 사용하여 암호화된 정수에 대한 간단한 계산
    EncryptionParameters parms(scheme_type::bfv); // bfv 스킴(벡터화된 연산)

    // 다항식 차수 설정 (4096)
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // 계수 모듈러스 설정
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // 평문 모듈러스 설정
    parms.set_plain_modulus(1024);

    // SEALContext 생성 및 파라미터 검증
    SEALContext context(parms);

    // 파라미터 출력
    print_line(__LINE__);
    cout << "암호화 파라미터 설정 완료" << endl;
    print_parameters(context);

    // 파라미터 유효성 검증
    cout << "파라미터 검증 결과: " << context.parameter_error_message() << endl;

    cout << endl;
    cout << "---- 4(x^2 + 1)(x + 1)^2 계산 ----" << endl;

    // 키 생성 (비밀키 및 공개키)
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // 암호화, 평가, 복호화 객체 생성
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // 예제 계산: 4x^4 + 8x^3 + 8x^2 + 8x + 4 계산
    print_line(__LINE__);
    uint64_t x = 6;
    Plaintext x_plain(uint64_to_hex_string(x));
    cout << "x = " + to_string(x) + "을 평문 다항식으로 표현: 0x" + x_plain.to_string() + "." << endl;

    // 평문 암호화
    print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "x_plain을 x_encrypted로 암호화합니다." << endl;
    encryptor.encrypt(x_plain, x_encrypted);

    // 암호문 크기 및 노이즈 예산 출력
    cout << "암호화된 x의 크기: " << x_encrypted.size() << endl;
    cout << "암호화된 x의 노이즈 예산: " << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

    // 복호화 및 결과 확인
    Plaintext x_decrypted;
    cout << "복호화된 x: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << endl;

    // (x + 1)^2 및 (x^2 + 1) 계산
    print_line(__LINE__);
    cout << "x^2 + 1 계산 중..." << endl;
    Ciphertext x_sq_plus_one;
    evaluator.square(x_encrypted, x_sq_plus_one);
    Plaintext plain_one("1");
    evaluator.add_plain_inplace(x_sq_plus_one, plain_one);

    // x^2 + 1 결과 출력
    cout << "x^2 + 1 크기: " << x_sq_plus_one.size() << endl;
    cout << "x^2 + 1 노이즈 예산: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;

    // 복호화 결과 확인
    Plaintext decrypted_result;
    cout << "복호화된 x^2 + 1: ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << endl;

    // (x + 1)^2 계산
    print_line(__LINE__);
    cout << "(x + 1)^2 계산 중..." << endl;
    Ciphertext x_plus_one_sq;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq);
    evaluator.square_inplace(x_plus_one_sq);


    // (x + 1)^2 결과 출력
    cout << "(x + 1)^2 크기: " << x_plus_one_sq.size() << endl;
    cout << "(x + 1)^2 노이즈 예산: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
    cout << "복호화된 (x + 1)^2: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << endl;

    // 최종 계산: 4(x^2 + 1)(x + 1)^2
    print_line(__LINE__);
    cout << "최종 계산: 4(x^2 + 1)(x + 1)^2" << endl;
    Ciphertext encrypted_result;
    Plaintext plain_four("4");
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);

    // 최종 결과 출력
    cout << "최종 결과 크기: " << encrypted_result.size() << endl;
    cout << "최종 결과 노이즈 예산: " << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
    cout << "노이즈 예산이 0이면 복호화가 정확하지 않을 수 있음." << endl;


    // 재선형화 키 생성 및 계산
    cout << endl;
    cout << "---- 재선형화 키 생성 및 계산 ----" << endl;
    print_line(__LINE__);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);


    // x^2 계산 및 재선형화
    cout << "x^2 계산 및 재선형화" << endl;
    Ciphertext x_squared;
    evaluator.square(x_encrypted, x_squared);
    evaluator.relinearize_inplace(x_squared, relin_keys);
    cout << "재선형화 후 x^2 크기: " << x_squared.size() << endl;

    // x^2 + 1 결과 확인
    evaluator.add_plain(x_squared, plain_one, x_sq_plus_one);
    cout << "x^2 + 1 노이즈 예산: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "복호화된 x^2 + 1: 0x" << decrypted_result.to_string() << endl;



    // (x + 1) 및 (x + 1)^2 계산 및 재선형화
    print_line(__LINE__);
    Ciphertext x_plus_one;
    cout << "(x + 1) 및 (x + 1)^2 계산 및 재선형화" << endl;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one);
    evaluator.square(x_plus_one, x_plus_one_sq);
    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys);
    cout << "(x + 1)^2 노이즈 예산: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "복호화된 (x + 1)^2: 0x" << decrypted_result.to_string() << endl;


    // 최종 결과 계산 및 재선형화
    print_line(__LINE__);
    cout << "최종 결과 계산 및 재선형화" << endl;
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    cout << "최종 결과 크기: " << encrypted_result.size() << endl;
    cout << "최종 결과 노이즈 예산: " << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;

    cout << "최종 노이즈 예산이 증가한 것을 확인할 수 있음." << endl;


    // 무효한 파라미터 예제
    print_line(__LINE__);
    cout << "무효한 파라미터 예제: x^2 + 1, 4(x^2+1)(x+1)^2 계산" << endl;
}

// 2번. 정수, 실수 연산을 위한 인코딩
void example_batch_encoder()
{
    print_example_banner("예제: 인코더 / 배치 인코더");

    // [배치 인코더] (BFV 또는 BGV 스킴에 사용)
    // N을 poly_modulus_degree라 하고, T를 plain_modulus라고 할 때, 
    // 배치는 BFV 평문 다항식을 2x(N/2) 행렬로 봄
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // 배치를 활성화하기 위해, 
    // plain_modulus는 2*poly_modulus_degree에 대해 1을 모듈로 하는 소수
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 배치가 활성화되었는지 SEALContext로부터 확인 가능
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "배치 사용 여부: " << boolalpha << qualifiers.using_batching << endl;

    // 키 생성 및 암호화, 평가, 복호화 객체 설정
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // 배치 인코더 생성
    BatchEncoder batch_encoder(context);

    // 총 슬롯 수는 poly_modulus_degree와 같음, 2x(N/2) 행렬로 구성
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "평문 행렬 행 크기: " << row_size << endl;

    // 첫 번째 행렬 데이터를 준비
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL; // 첫 번째 행
    pod_matrix[1] = 1ULL; // 두 번째 열
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL; // 두 번째 행
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "입력 행렬 데이터:" << endl;
    print_matrix(pod_matrix, row_size);

    // 행렬을 평문 다항식으로 인코딩
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "행렬 인코딩:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    // 인코딩된 결과를 디코딩하여 정확성 확인
    vector<uint64_t> pod_result;
    cout << "    + 디코딩된 행렬 데이터 ...... 정확함." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
    print_matrix(pod_result, row_size);

    // 인코딩된 평문을 암호화
    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "plain_matrix를 encrypted_matrix로 암호화." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + 암호화된 데이터의 노이즈 예산: " <<
        decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    // 두 번째 행렬 데이터 생성: 암호화된 행렬에 더하고 제곱
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1)) + 1); // 1과 2로 구성된 행렬
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "두 번째 입력 행렬 데이터:" << endl;
    print_matrix(pod_matrix2, row_size);

    // 첫 번째 암호화된 행렬에 두 번째 행렬을 더한 후 제곱 연산 수행
    print_line(__LINE__);
    cout << "행렬 합산, 제곱, 그리고 재선형화." << endl;
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    evaluator.square_inplace(encrypted_matrix);
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);

    // 결과의 노이즈 예산 확인
    cout << "    + 연산 후 노이즈 예산: " <<
        decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    // 결과를 복호화하여 행렬로 디코딩
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "결과 복호화 및 디코딩." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + 복호화된 행렬 데이터 ...... 정확함." << endl;
    print_matrix(pod_result, row_size);

    // 배치를 사용하여 효율적인 연산을 수행하지만, plain_modulus에 따른 오버플로를 주의해야 함.
}

// CKKS 인코더 함수
void example_ckks_encoder()
{
    print_example_banner("예제: 인코더 / CKKS 인코더");

    // CKKS 스킴 설정
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));

    // SEALContext 설정 및 파라미터 출력
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 키 생성
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // 암호화, 평가, 복호화 객체 생성
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, keygen.secret_key());

    // CKKS 인코더 생성 및 슬롯 수 출력
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "슬롯 수: " << slot_count << endl;

    // 입력 벡터 준비
    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    cout << "입력 벡터: " << endl;
    print_vector(input);

    // 인코딩을 위한 스케일 설정
    double scale = pow(2.0, 30);
    Plaintext plain;

    // 입력 벡터를 인코딩
    encoder.encode(input, scale, plain);

    // 인코딩 확인: 디코딩하여 입력과 비교
    vector<double> output;
    encoder.decode(plain, output);
    cout << "    + 입력 벡터 디코딩 ...... 정확함." << endl;
    print_vector(output);

    // 입력 벡터 암호화 및 연산 (제곱 후 리니어라이즈)
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);

    // 결과 스케일 및 노이즈 예산 출력
    cout << "    + 제곱된 벡터의 스케일: " << encrypted.scale() <<
        " (" << log2(encrypted.scale()) << " bits)" << endl;

    // 결과 복호화 및 디코딩
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, output);
    cout << "    + 결과 벡터 ...... 정확함." << endl;
    print_vector(output);
}

// 3번. '레벨' 및 '모듈러스 전환 체인' 개념을 설명하고 시연
void example_levels()
{
    print_example_banner("예제: 레벨");

    // BFV 스킴을 사용하여 암호화 파라미터 설정
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // 사용자 정의 계수 모듈러스 설정
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 30, 50, 50 }));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 모듈러스 전환 체인 출력
    print_line(__LINE__);
    cout << "모듈러스 전환 체인 출력" << endl;

    // key_context_data부터 시작하여 각 레벨을 출력
    auto context_data = context.key_context_data();
    cout << "----> 레벨 (체인 인덱스): " << context_data->chain_index() << " ...... key_context_data()" << endl;
    cout << "\\" << endl << " \\-->";

    // 체인에 있는 각 레벨을 순차적으로 출력
    context_data = context.first_context_data();
    while (context_data)
    {
        cout << " 레벨 (체인 인덱스): " << context_data->chain_index() << endl;
        cout << "      계수 모듈러스 소수: ";
        for (const auto& prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << endl << "\\" << endl << " \\-->";
        context_data = context_data->next_context_data();
    }
    cout << " 체인의 끝에 도달" << endl << endl;

    // 키 생성 후 각 키의 parms_id 출력
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    print_line(__LINE__);
    cout << "생성된 요소의 parms_id 출력" << endl;
    cout << "    + public_key:  " << public_key.parms_id() << endl;
    cout << "    + secret_key:  " << secret_key.parms_id() << endl;
    cout << "    + relin_keys:  " << relin_keys.parms_id() << endl;

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // 암호화된 데이터의 parms_id 출력 후 모듈러스 전환 수행
    Plaintext plain("1x^3 + 2x^2 + 3x^1 + 4");
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    cout << "    + 암호화된 데이터: " << encrypted.parms_id() << endl << endl;

    print_line(__LINE__);
    cout << "모듈러스 전환 수행 및 출력" << endl;
    context_data = context.first_context_data();
    while (context_data->next_context_data())
    {
        cout << " 레벨 (체인 인덱스): " << context_data->chain_index() << endl;
        evaluator.mod_switch_to_next_inplace(encrypted);
        context_data = context_data->next_context_data();
    }
    cout << " 체인의 끝에 도달" << endl << endl;

    // 모듈러스 전환 후 복호화 확인
    print_line(__LINE__);
    cout << "모듈러스 전환 후 복호화 확인" << endl;
    decryptor.decrypt(encrypted, plain);
    cout << "    + 복호화된 값: " << plain.to_string() << " ...... 정확함." << endl << endl;

    // 모듈러스 전환 없이 체인을 줄이는 예시
    context = SEALContext(parms, false);
    cout << "모듈러스 전환 체인 확장 비활성화 후 출력" << endl;
    print_line(__LINE__);
    context_data = context.key_context_data();
    while (context_data)
    {
        cout << " 레벨 (체인 인덱스): " << context_data->chain_index() << endl;
        context_data = context_data->next_context_data();
    }
    cout << " 체인의 끝에 도달" << endl << endl;
}

// 5번. CKKS 스킴을 사용해 다항식 평가 예제
void example_ckks_basics()
{
    print_example_banner("예제: CKKS 기본");

    // CKKS 스킴과 초기 파라미터 설정
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // 초기 스케일은 2^40으로 설정해 계산 중 안정성 유지
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 키 생성 및 암호화, 평가, 복호화 객체 설정
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // CKKS 인코더 생성 및 슬롯 개수 출력
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "슬롯 개수: " << slot_count << endl;

    // 입력 데이터 생성 (4096개의 점)
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "입력 벡터: " << endl;
    print_vector(input, 3, 7);

    // 다항식 PI*x^3 + 0.4*x + 1 계산
    cout << "다항식 PI*x^3 + 0.4*x + 1 계산 중..." << endl;

    // 상수 PI, 0.4, 1을 각각 인코딩
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    // 입력 벡터 인코딩 후 암호화
    Plaintext x_plain;
    print_line(__LINE__);
    cout << "입력 벡터 인코딩" << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    // x^2 계산 및 재선형화
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    cout << "x^2 계산 및 재선형화:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Rescale 전 x^2의 스케일: " << log2(x3_encrypted.scale()) << " 비트" << endl;

    // x^2 스케일 조정
    print_line(__LINE__);
    cout << "x^2 스케일 조정" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Rescale 후 x^2의 스케일: " << log2(x3_encrypted.scale()) << " 비트" << endl;

    // PI*x 계산 후 스케일 조정
    print_line(__LINE__);
    cout << "PI*x 계산 및 스케일 조정" << endl;
    Ciphertext x1_encrypted_coeff3;
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    cout << "    + Rescale 전 PI*x의 스케일: " << log2(x1_encrypted_coeff3.scale()) << " 비트" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "    + Rescale 후 PI*x의 스케일: " << log2(x1_encrypted_coeff3.scale()) << " 비트" << endl;

    // PI*x^3 계산 및 스케일 조정
    print_line(__LINE__);
    cout << "PI*x^3 계산 및 스케일 조정" << endl;
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Rescale 전 PI*x^3의 스케일: " << log2(x3_encrypted.scale()) << " 비트" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Rescale 후 PI*x^3의 스케일: " << log2(x3_encrypted.scale()) << " 비트" << endl;

    // 0.4*x 계산 및 스케일 조정
    print_line(__LINE__);
    cout << "0.4*x 계산 및 스케일 조정" << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "    + Rescale 전 0.4*x의 스케일: " << log2(x1_encrypted.scale()) << " 비트" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Rescale 후 0.4*x의 스케일: " << log2(x1_encrypted.scale()) << " 비트" << endl;

    // 스케일과 파라미터 정규화
    print_line(__LINE__);
    cout << "스케일을 2^40으로 정규화" << endl;
    x3_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    print_line(__LINE__);
    cout << "암호화 파라미터를 낮은 레벨로 정규화" << endl;
    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    // 최종 계산: PI*x^3 + 0.4*x + 1
    print_line(__LINE__);
    cout << "PI*x^3 + 0.4*x + 1 계산" << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    // 복호화 및 결과 출력
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "PI*x^3 + 0.4x + 1 복호화 및 디코딩" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
    }
    print_vector(true_result, 3, 7);

    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + 계산된 결과 ...... 정확함." << endl;
    print_vector(result, 3, 7);
}

// 6번. BFV, CKKS 스킴에서 벡터 연산과 회전 기능 제공.
// BFV 스킴을 BGV로 변경하면 동일한 예제를 BGV 스킴에서도 사용할 수 있음.
void example_rotation_bfv()
{
    print_example_banner("예제: 회전 / BFV에서 회전");

    // BFV 스킴 설정
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 키 생성 및 암호화, 복호화, 평가 객체 준비
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // 배치 인코더 설정
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "평문 행렬의 행 크기: " << row_size << endl;

    // 평문 행렬 입력
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "입력 평문 행렬:" << endl;
    print_matrix(pod_matrix, row_size);

    // 인코딩 후 암호화
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "인코딩 및 암호화." << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + 새 암호화된 데이터의 노이즈 예산: " << decryptor.invariant_noise_budget(encrypted_matrix) << " 비트"
        << endl;
    cout << endl;

    // 회전용 Galois 키 생성
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // 행을 왼쪽으로 3칸 회전
    print_line(__LINE__);
    cout << "행을 3칸 왼쪽으로 회전." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, 3, galois_keys);
    Plaintext plain_result;
    cout << "    + 회전 후 노이즈 예산: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " 비트" << endl;
    cout << "    + 복호화 및 디코딩 결과 확인." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // 열 회전 (행 스왑)
    print_line(__LINE__);
    cout << "열을 회전." << endl;
    evaluator.rotate_columns_inplace(encrypted_matrix, galois_keys);
    cout << "    + 회전 후 노이즈 예산: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " 비트" << endl;
    cout << "    + 복호화 및 디코딩 결과 확인." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // 행을 오른쪽으로 4칸 회전
    print_line(__LINE__);
    cout << "행을 4칸 오른쪽으로 회전." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, galois_keys);
    cout << "    + 회전 후 노이즈 예산: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " 비트" << endl;
    cout << "    + 복호화 및 디코딩 결과 확인." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // 회전은 노이즈 예산을 소비하지 않음. 다만, 큰 소수를 사용해야 성능이 보장됨.
}

// CKKS 스킴 회전 예제
void example_rotation_ckks()
{
    print_example_banner("예제: 회전 / CKKS에서 회전");

    // CKKS 스킴 설정
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree,
        { 40, 40, 40, 40, 40 }));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // 키 생성 및 암호화, 복호화, 평가 객체 준비
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // CKKS 인코더 설정
    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    cout << "슬롯 개수: " << slot_count << endl;

    // 입력 벡터 생성
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "입력 벡터:" << endl;
    print_vector(input, 3, 7);

    auto scale = pow(2.0, 50);

    print_line(__LINE__);
    cout << "인코딩 및 암호화." << endl;
    Plaintext plain;
    ckks_encoder.encode(input, scale, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    // 벡터 2칸 왼쪽으로 회전
    Ciphertext rotated;
    print_line(__LINE__);
    cout << "2칸 왼쪽으로 회전." << endl;
    evaluator.rotate_vector(encrypted, 2, galois_keys, rotated);
    cout << "    + 복호화 및 디코딩 결과 확인." << endl;
    decryptor.decrypt(rotated, plain);
    vector<double> result;
    ckks_encoder.decode(plain, result);
    print_vector(result, 3, 7);

    // CKKS 스킴에서 복소수 벡터의 복소수 켤레 연산 가능
}


int main()
{
    // SEAL 버전 출력
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    while (true)
    {
        // 실행할 수 있는 예제 목록 출력
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| 다음 예제는 주석을 참고하면서 실행해야 합니다.          |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| 예제                        | 소스 파일                 |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1. BFV 기본 예제            | 1_bfv_basics               |" << endl;
        cout << "| 2. 인코더 예제              | 2_encoder(batch, ckks)     |" << endl;
        cout << "| 3. 레벨 예제                | 3_levels                   |" << endl;
        cout << "| 5. CKKS 기본 예제           | 5_ckks_basics              |" << endl;
        cout << "| 6. 회전 예제                | 6_rotation_bfv, ckks       |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;

        // 현재 메모리 풀에서 할당된 메모리 크기 출력
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
            << "메모리 풀에서 할당된 총 메모리" << endl;

        int selection = 0;
        bool valid = true;
        do
        {
            cout << endl << "> 실행할 예제 선택 (1 ~ 6) 또는 종료 (0): ";
            if (!(cin >> selection))
            {
                valid = false;
            }
            else if (selection < 0 || selection > 6)
            {
                valid = false;
            }
            else
            {
                valid = true;
            }
            if (!valid)
            {
                cout << "  [Beep~~] 올바른 옵션을 선택하세요: 0 ~ 6" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);

        // 선택한 예제 실행
        switch (selection)
        {
        case 1:
            example_bfv_basics();
            break;

        case 2:
            example_batch_encoder();
            cout << "\n";
            example_ckks_encoder();
            break;

        case 3:
            example_levels();
            break;

        case 5:
            example_ckks_basics();
            break;

        case 6:
            example_rotation_bfv();
            cout << "\n";
            example_rotation_ckks();
            break;

        case 0:
            return 0;

        default:
            cout << "잘못 입력했습니다." << "\n";
        }
    }

    return 0;
}