// ������ �ڵ�(ms seal)
#include "examples.h"

using namespace std;
using namespace seal;

// 1��. ������ ���� ����
void example_bfv_basics()
{
    print_example_banner("Example: BFV Basics");

    // BFV ��ȣȭ ����� ����Ͽ� ��ȣȭ�� ������ ���� ������ ���
    EncryptionParameters parms(scheme_type::bfv); // bfv ��Ŵ(����ȭ�� ����)

    // ���׽� ���� ���� (4096)
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // ��� ��ⷯ�� ����
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // �� ��ⷯ�� ����
    parms.set_plain_modulus(1024);

    // SEALContext ���� �� �Ķ���� ����
    SEALContext context(parms);

    // �Ķ���� ���
    print_line(__LINE__);
    cout << "��ȣȭ �Ķ���� ���� �Ϸ�" << endl;
    print_parameters(context);

    // �Ķ���� ��ȿ�� ����
    cout << "�Ķ���� ���� ���: " << context.parameter_error_message() << endl;

    cout << endl;
    cout << "---- 4(x^2 + 1)(x + 1)^2 ��� ----" << endl;

    // Ű ���� (���Ű �� ����Ű)
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // ��ȣȭ, ��, ��ȣȭ ��ü ����
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // ���� ���: 4x^4 + 8x^3 + 8x^2 + 8x + 4 ���
    print_line(__LINE__);
    uint64_t x = 6;
    Plaintext x_plain(uint64_to_hex_string(x));
    cout << "x = " + to_string(x) + "�� �� ���׽����� ǥ��: 0x" + x_plain.to_string() + "." << endl;

    // �� ��ȣȭ
    print_line(__LINE__);
    Ciphertext x_encrypted;
    cout << "x_plain�� x_encrypted�� ��ȣȭ�մϴ�." << endl;
    encryptor.encrypt(x_plain, x_encrypted);

    // ��ȣ�� ũ�� �� ������ ���� ���
    cout << "��ȣȭ�� x�� ũ��: " << x_encrypted.size() << endl;
    cout << "��ȣȭ�� x�� ������ ����: " << decryptor.invariant_noise_budget(x_encrypted) << " bits" << endl;

    // ��ȣȭ �� ��� Ȯ��
    Plaintext x_decrypted;
    cout << "��ȣȭ�� x: ";
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << endl;

    // (x + 1)^2 �� (x^2 + 1) ���
    print_line(__LINE__);
    cout << "x^2 + 1 ��� ��..." << endl;
    Ciphertext x_sq_plus_one;
    evaluator.square(x_encrypted, x_sq_plus_one);
    Plaintext plain_one("1");
    evaluator.add_plain_inplace(x_sq_plus_one, plain_one);

    // x^2 + 1 ��� ���
    cout << "x^2 + 1 ũ��: " << x_sq_plus_one.size() << endl;
    cout << "x^2 + 1 ������ ����: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;

    // ��ȣȭ ��� Ȯ��
    Plaintext decrypted_result;
    cout << "��ȣȭ�� x^2 + 1: ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << endl;

    // (x + 1)^2 ���
    print_line(__LINE__);
    cout << "(x + 1)^2 ��� ��..." << endl;
    Ciphertext x_plus_one_sq;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one_sq);
    evaluator.square_inplace(x_plus_one_sq);


    // (x + 1)^2 ��� ���
    cout << "(x + 1)^2 ũ��: " << x_plus_one_sq.size() << endl;
    cout << "(x + 1)^2 ������ ����: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
    cout << "��ȣȭ�� (x + 1)^2: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << endl;

    // ���� ���: 4(x^2 + 1)(x + 1)^2
    print_line(__LINE__);
    cout << "���� ���: 4(x^2 + 1)(x + 1)^2" << endl;
    Ciphertext encrypted_result;
    Plaintext plain_four("4");
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);

    // ���� ��� ���
    cout << "���� ��� ũ��: " << encrypted_result.size() << endl;
    cout << "���� ��� ������ ����: " << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;
    cout << "������ ������ 0�̸� ��ȣȭ�� ��Ȯ���� ���� �� ����." << endl;


    // �缱��ȭ Ű ���� �� ���
    cout << endl;
    cout << "---- �缱��ȭ Ű ���� �� ��� ----" << endl;
    print_line(__LINE__);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);


    // x^2 ��� �� �缱��ȭ
    cout << "x^2 ��� �� �缱��ȭ" << endl;
    Ciphertext x_squared;
    evaluator.square(x_encrypted, x_squared);
    evaluator.relinearize_inplace(x_squared, relin_keys);
    cout << "�缱��ȭ �� x^2 ũ��: " << x_squared.size() << endl;

    // x^2 + 1 ��� Ȯ��
    evaluator.add_plain(x_squared, plain_one, x_sq_plus_one);
    cout << "x^2 + 1 ������ ����: " << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "��ȣȭ�� x^2 + 1: 0x" << decrypted_result.to_string() << endl;



    // (x + 1) �� (x + 1)^2 ��� �� �缱��ȭ
    print_line(__LINE__);
    Ciphertext x_plus_one;
    cout << "(x + 1) �� (x + 1)^2 ��� �� �缱��ȭ" << endl;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one);
    evaluator.square(x_plus_one, x_plus_one_sq);
    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys);
    cout << "(x + 1)^2 ������ ����: " << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "��ȣȭ�� (x + 1)^2: 0x" << decrypted_result.to_string() << endl;


    // ���� ��� ��� �� �缱��ȭ
    print_line(__LINE__);
    cout << "���� ��� ��� �� �缱��ȭ" << endl;
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    cout << "���� ��� ũ��: " << encrypted_result.size() << endl;
    cout << "���� ��� ������ ����: " << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;

    cout << "���� ������ ������ ������ ���� Ȯ���� �� ����." << endl;


    // ��ȿ�� �Ķ���� ����
    print_line(__LINE__);
    cout << "��ȿ�� �Ķ���� ����: x^2 + 1, 4(x^2+1)(x+1)^2 ���" << endl;
}

// 2��. ����, �Ǽ� ������ ���� ���ڵ�
void example_batch_encoder()
{
    print_example_banner("����: ���ڴ� / ��ġ ���ڴ�");

    // [��ġ ���ڴ�] (BFV �Ǵ� BGV ��Ŵ�� ���)
    // N�� poly_modulus_degree�� �ϰ�, T�� plain_modulus��� �� ��, 
    // ��ġ�� BFV �� ���׽��� 2x(N/2) ��ķ� ��
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // ��ġ�� Ȱ��ȭ�ϱ� ����, 
    // plain_modulus�� 2*poly_modulus_degree�� ���� 1�� ���� �ϴ� �Ҽ�
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // ��ġ�� Ȱ��ȭ�Ǿ����� SEALContext�κ��� Ȯ�� ����
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "��ġ ��� ����: " << boolalpha << qualifiers.using_batching << endl;

    // Ű ���� �� ��ȣȭ, ��, ��ȣȭ ��ü ����
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // ��ġ ���ڴ� ����
    BatchEncoder batch_encoder(context);

    // �� ���� ���� poly_modulus_degree�� ����, 2x(N/2) ��ķ� ����
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "�� ��� �� ũ��: " << row_size << endl;

    // ù ��° ��� �����͸� �غ�
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL; // ù ��° ��
    pod_matrix[1] = 1ULL; // �� ��° ��
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL; // �� ��° ��
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "�Է� ��� ������:" << endl;
    print_matrix(pod_matrix, row_size);

    // ����� �� ���׽����� ���ڵ�
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "��� ���ڵ�:" << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);

    // ���ڵ��� ����� ���ڵ��Ͽ� ��Ȯ�� Ȯ��
    vector<uint64_t> pod_result;
    cout << "    + ���ڵ��� ��� ������ ...... ��Ȯ��." << endl;
    batch_encoder.decode(plain_matrix, pod_result);
    print_matrix(pod_result, row_size);

    // ���ڵ��� ���� ��ȣȭ
    Ciphertext encrypted_matrix;
    print_line(__LINE__);
    cout << "plain_matrix�� encrypted_matrix�� ��ȣȭ." << endl;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + ��ȣȭ�� �������� ������ ����: " <<
        decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    // �� ��° ��� ������ ����: ��ȣȭ�� ��Ŀ� ���ϰ� ����
    vector<uint64_t> pod_matrix2;
    for (size_t i = 0; i < slot_count; i++)
    {
        pod_matrix2.push_back((i & size_t(0x1)) + 1); // 1�� 2�� ������ ���
    }
    Plaintext plain_matrix2;
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    cout << endl;
    cout << "�� ��° �Է� ��� ������:" << endl;
    print_matrix(pod_matrix2, row_size);

    // ù ��° ��ȣȭ�� ��Ŀ� �� ��° ����� ���� �� ���� ���� ����
    print_line(__LINE__);
    cout << "��� �ջ�, ����, �׸��� �缱��ȭ." << endl;
    evaluator.add_plain_inplace(encrypted_matrix, plain_matrix2);
    evaluator.square_inplace(encrypted_matrix);
    evaluator.relinearize_inplace(encrypted_matrix, relin_keys);

    // ����� ������ ���� Ȯ��
    cout << "    + ���� �� ������ ����: " <<
        decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

    // ����� ��ȣȭ�Ͽ� ��ķ� ���ڵ�
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "��� ��ȣȭ �� ���ڵ�." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_result);
    cout << "    + ��ȣȭ�� ��� ������ ...... ��Ȯ��." << endl;
    print_matrix(pod_result, row_size);

    // ��ġ�� ����Ͽ� ȿ������ ������ ����������, plain_modulus�� ���� �����÷θ� �����ؾ� ��.
}

// CKKS ���ڴ� �Լ�
void example_ckks_encoder()
{
    print_example_banner("����: ���ڴ� / CKKS ���ڴ�");

    // CKKS ��Ŵ ����
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40 }));

    // SEALContext ���� �� �Ķ���� ���
    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Ű ����
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    // ��ȣȭ, ��, ��ȣȭ ��ü ����
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, keygen.secret_key());

    // CKKS ���ڴ� ���� �� ���� �� ���
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "���� ��: " << slot_count << endl;

    // �Է� ���� �غ�
    vector<double> input{ 0.0, 1.1, 2.2, 3.3 };
    cout << "�Է� ����: " << endl;
    print_vector(input);

    // ���ڵ��� ���� ������ ����
    double scale = pow(2.0, 30);
    Plaintext plain;

    // �Է� ���͸� ���ڵ�
    encoder.encode(input, scale, plain);

    // ���ڵ� Ȯ��: ���ڵ��Ͽ� �Է°� ��
    vector<double> output;
    encoder.decode(plain, output);
    cout << "    + �Է� ���� ���ڵ� ...... ��Ȯ��." << endl;
    print_vector(output);

    // �Է� ���� ��ȣȭ �� ���� (���� �� ���Ͼ������)
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);

    // ��� ������ �� ������ ���� ���
    cout << "    + ������ ������ ������: " << encrypted.scale() <<
        " (" << log2(encrypted.scale()) << " bits)" << endl;

    // ��� ��ȣȭ �� ���ڵ�
    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, output);
    cout << "    + ��� ���� ...... ��Ȯ��." << endl;
    print_vector(output);
}

// 3��. '����' �� '��ⷯ�� ��ȯ ü��' ������ �����ϰ� �ÿ�
void example_levels()
{
    print_example_banner("����: ����");

    // BFV ��Ŵ�� ����Ͽ� ��ȣȭ �Ķ���� ����
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    // ����� ���� ��� ��ⷯ�� ����
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 50, 30, 30, 50, 50 }));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // ��ⷯ�� ��ȯ ü�� ���
    print_line(__LINE__);
    cout << "��ⷯ�� ��ȯ ü�� ���" << endl;

    // key_context_data���� �����Ͽ� �� ������ ���
    auto context_data = context.key_context_data();
    cout << "----> ���� (ü�� �ε���): " << context_data->chain_index() << " ...... key_context_data()" << endl;
    cout << "\\" << endl << " \\-->";

    // ü�ο� �ִ� �� ������ ���������� ���
    context_data = context.first_context_data();
    while (context_data)
    {
        cout << " ���� (ü�� �ε���): " << context_data->chain_index() << endl;
        cout << "      ��� ��ⷯ�� �Ҽ�: ";
        for (const auto& prime : context_data->parms().coeff_modulus())
        {
            cout << prime.value() << " ";
        }
        cout << endl << "\\" << endl << " \\-->";
        context_data = context_data->next_context_data();
    }
    cout << " ü���� ���� ����" << endl << endl;

    // Ű ���� �� �� Ű�� parms_id ���
    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    print_line(__LINE__);
    cout << "������ ����� parms_id ���" << endl;
    cout << "    + public_key:  " << public_key.parms_id() << endl;
    cout << "    + secret_key:  " << secret_key.parms_id() << endl;
    cout << "    + relin_keys:  " << relin_keys.parms_id() << endl;

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // ��ȣȭ�� �������� parms_id ��� �� ��ⷯ�� ��ȯ ����
    Plaintext plain("1x^3 + 2x^2 + 3x^1 + 4");
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);
    cout << "    + ��ȣȭ�� ������: " << encrypted.parms_id() << endl << endl;

    print_line(__LINE__);
    cout << "��ⷯ�� ��ȯ ���� �� ���" << endl;
    context_data = context.first_context_data();
    while (context_data->next_context_data())
    {
        cout << " ���� (ü�� �ε���): " << context_data->chain_index() << endl;
        evaluator.mod_switch_to_next_inplace(encrypted);
        context_data = context_data->next_context_data();
    }
    cout << " ü���� ���� ����" << endl << endl;

    // ��ⷯ�� ��ȯ �� ��ȣȭ Ȯ��
    print_line(__LINE__);
    cout << "��ⷯ�� ��ȯ �� ��ȣȭ Ȯ��" << endl;
    decryptor.decrypt(encrypted, plain);
    cout << "    + ��ȣȭ�� ��: " << plain.to_string() << " ...... ��Ȯ��." << endl << endl;

    // ��ⷯ�� ��ȯ ���� ü���� ���̴� ����
    context = SEALContext(parms, false);
    cout << "��ⷯ�� ��ȯ ü�� Ȯ�� ��Ȱ��ȭ �� ���" << endl;
    print_line(__LINE__);
    context_data = context.key_context_data();
    while (context_data)
    {
        cout << " ���� (ü�� �ε���): " << context_data->chain_index() << endl;
        context_data = context_data->next_context_data();
    }
    cout << " ü���� ���� ����" << endl << endl;
}

// 5��. CKKS ��Ŵ�� ����� ���׽� �� ����
void example_ckks_basics()
{
    print_example_banner("����: CKKS �⺻");

    // CKKS ��Ŵ�� �ʱ� �Ķ���� ����
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // �ʱ� �������� 2^40���� ������ ��� �� ������ ����
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Ű ���� �� ��ȣȭ, ��, ��ȣȭ ��ü ����
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

    // CKKS ���ڴ� ���� �� ���� ���� ���
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "���� ����: " << slot_count << endl;

    // �Է� ������ ���� (4096���� ��)
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "�Է� ����: " << endl;
    print_vector(input, 3, 7);

    // ���׽� PI*x^3 + 0.4*x + 1 ���
    cout << "���׽� PI*x^3 + 0.4*x + 1 ��� ��..." << endl;

    // ��� PI, 0.4, 1�� ���� ���ڵ�
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    // �Է� ���� ���ڵ� �� ��ȣȭ
    Plaintext x_plain;
    print_line(__LINE__);
    cout << "�Է� ���� ���ڵ�" << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    // x^2 ��� �� �缱��ȭ
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    cout << "x^2 ��� �� �缱��ȭ:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Rescale �� x^2�� ������: " << log2(x3_encrypted.scale()) << " ��Ʈ" << endl;

    // x^2 ������ ����
    print_line(__LINE__);
    cout << "x^2 ������ ����" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Rescale �� x^2�� ������: " << log2(x3_encrypted.scale()) << " ��Ʈ" << endl;

    // PI*x ��� �� ������ ����
    print_line(__LINE__);
    cout << "PI*x ��� �� ������ ����" << endl;
    Ciphertext x1_encrypted_coeff3;
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    cout << "    + Rescale �� PI*x�� ������: " << log2(x1_encrypted_coeff3.scale()) << " ��Ʈ" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "    + Rescale �� PI*x�� ������: " << log2(x1_encrypted_coeff3.scale()) << " ��Ʈ" << endl;

    // PI*x^3 ��� �� ������ ����
    print_line(__LINE__);
    cout << "PI*x^3 ��� �� ������ ����" << endl;
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Rescale �� PI*x^3�� ������: " << log2(x3_encrypted.scale()) << " ��Ʈ" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Rescale �� PI*x^3�� ������: " << log2(x3_encrypted.scale()) << " ��Ʈ" << endl;

    // 0.4*x ��� �� ������ ����
    print_line(__LINE__);
    cout << "0.4*x ��� �� ������ ����" << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "    + Rescale �� 0.4*x�� ������: " << log2(x1_encrypted.scale()) << " ��Ʈ" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Rescale �� 0.4*x�� ������: " << log2(x1_encrypted.scale()) << " ��Ʈ" << endl;

    // �����ϰ� �Ķ���� ����ȭ
    print_line(__LINE__);
    cout << "�������� 2^40���� ����ȭ" << endl;
    x3_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    print_line(__LINE__);
    cout << "��ȣȭ �Ķ���͸� ���� ������ ����ȭ" << endl;
    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    // ���� ���: PI*x^3 + 0.4*x + 1
    print_line(__LINE__);
    cout << "PI*x^3 + 0.4*x + 1 ���" << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    // ��ȣȭ �� ��� ���
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "PI*x^3 + 0.4x + 1 ��ȣȭ �� ���ڵ�" << endl;
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
    cout << "    + ���� ��� ...... ��Ȯ��." << endl;
    print_vector(result, 3, 7);
}

// 6��. BFV, CKKS ��Ŵ���� ���� ����� ȸ�� ��� ����.
// BFV ��Ŵ�� BGV�� �����ϸ� ������ ������ BGV ��Ŵ������ ����� �� ����.
void example_rotation_bfv()
{
    print_example_banner("����: ȸ�� / BFV���� ȸ��");

    // BFV ��Ŵ ����
    EncryptionParameters parms(scheme_type::bfv);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Ű ���� �� ��ȣȭ, ��ȣȭ, �� ��ü �غ�
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // ��ġ ���ڴ� ����
    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "�� ����� �� ũ��: " << row_size << endl;

    // �� ��� �Է�
    vector<uint64_t> pod_matrix(slot_count, 0ULL);
    pod_matrix[0] = 0ULL;
    pod_matrix[1] = 1ULL;
    pod_matrix[2] = 2ULL;
    pod_matrix[3] = 3ULL;
    pod_matrix[row_size] = 4ULL;
    pod_matrix[row_size + 1] = 5ULL;
    pod_matrix[row_size + 2] = 6ULL;
    pod_matrix[row_size + 3] = 7ULL;

    cout << "�Է� �� ���:" << endl;
    print_matrix(pod_matrix, row_size);

    // ���ڵ� �� ��ȣȭ
    Plaintext plain_matrix;
    print_line(__LINE__);
    cout << "���ڵ� �� ��ȣȭ." << endl;
    batch_encoder.encode(pod_matrix, plain_matrix);
    Ciphertext encrypted_matrix;
    encryptor.encrypt(plain_matrix, encrypted_matrix);
    cout << "    + �� ��ȣȭ�� �������� ������ ����: " << decryptor.invariant_noise_budget(encrypted_matrix) << " ��Ʈ"
        << endl;
    cout << endl;

    // ȸ���� Galois Ű ����
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // ���� �������� 3ĭ ȸ��
    print_line(__LINE__);
    cout << "���� 3ĭ �������� ȸ��." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, 3, galois_keys);
    Plaintext plain_result;
    cout << "    + ȸ�� �� ������ ����: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " ��Ʈ" << endl;
    cout << "    + ��ȣȭ �� ���ڵ� ��� Ȯ��." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // �� ȸ�� (�� ����)
    print_line(__LINE__);
    cout << "���� ȸ��." << endl;
    evaluator.rotate_columns_inplace(encrypted_matrix, galois_keys);
    cout << "    + ȸ�� �� ������ ����: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " ��Ʈ" << endl;
    cout << "    + ��ȣȭ �� ���ڵ� ��� Ȯ��." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // ���� ���������� 4ĭ ȸ��
    print_line(__LINE__);
    cout << "���� 4ĭ ���������� ȸ��." << endl;
    evaluator.rotate_rows_inplace(encrypted_matrix, -4, galois_keys);
    cout << "    + ȸ�� �� ������ ����: "
        << decryptor.invariant_noise_budget(encrypted_matrix) << " ��Ʈ" << endl;
    cout << "    + ��ȣȭ �� ���ڵ� ��� Ȯ��." << endl;
    decryptor.decrypt(encrypted_matrix, plain_result);
    batch_encoder.decode(plain_result, pod_matrix);
    print_matrix(pod_matrix, row_size);

    // ȸ���� ������ ������ �Һ����� ����. �ٸ�, ū �Ҽ��� ����ؾ� ������ �����.
}

// CKKS ��Ŵ ȸ�� ����
void example_rotation_ckks()
{
    print_example_banner("����: ȸ�� / CKKS���� ȸ��");

    // CKKS ��Ŵ ����
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree,
        { 40, 40, 40, 40, 40 }));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    // Ű ���� �� ��ȣȭ, ��ȣȭ, �� ��ü �غ�
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

    // CKKS ���ڴ� ����
    CKKSEncoder ckks_encoder(context);

    size_t slot_count = ckks_encoder.slot_count();
    cout << "���� ����: " << slot_count << endl;

    // �Է� ���� ����
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);
    }
    cout << "�Է� ����:" << endl;
    print_vector(input, 3, 7);

    auto scale = pow(2.0, 50);

    print_line(__LINE__);
    cout << "���ڵ� �� ��ȣȭ." << endl;
    Plaintext plain;
    ckks_encoder.encode(input, scale, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    // ���� 2ĭ �������� ȸ��
    Ciphertext rotated;
    print_line(__LINE__);
    cout << "2ĭ �������� ȸ��." << endl;
    evaluator.rotate_vector(encrypted, 2, galois_keys, rotated);
    cout << "    + ��ȣȭ �� ���ڵ� ��� Ȯ��." << endl;
    decryptor.decrypt(rotated, plain);
    vector<double> result;
    ckks_encoder.decode(plain, result);
    print_vector(result, 3, 7);

    // CKKS ��Ŵ���� ���Ҽ� ������ ���Ҽ� �ӷ� ���� ����
}


int main()
{
    // SEAL ���� ���
    cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
    while (true)
    {
        // ������ �� �ִ� ���� ��� ���
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| ���� ������ �ּ��� �����ϸ鼭 �����ؾ� �մϴ�.          |" << endl;
        cout << "+---------------------------------------------------------+" << endl;
        cout << "| ����                        | �ҽ� ����                 |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;
        cout << "| 1. BFV �⺻ ����            | 1_bfv_basics               |" << endl;
        cout << "| 2. ���ڴ� ����              | 2_encoder(batch, ckks)     |" << endl;
        cout << "| 3. ���� ����                | 3_levels                   |" << endl;
        cout << "| 5. CKKS �⺻ ����           | 5_ckks_basics              |" << endl;
        cout << "| 6. ȸ�� ����                | 6_rotation_bfv, ckks       |" << endl;
        cout << "+----------------------------+----------------------------+" << endl;

        // ���� �޸� Ǯ���� �Ҵ�� �޸� ũ�� ���
        size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
        cout << "[" << setw(7) << right << megabytes << " MB] "
            << "�޸� Ǯ���� �Ҵ�� �� �޸�" << endl;

        int selection = 0;
        bool valid = true;
        do
        {
            cout << endl << "> ������ ���� ���� (1 ~ 6) �Ǵ� ���� (0): ";
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
                cout << "  [Beep~~] �ùٸ� �ɼ��� �����ϼ���: 0 ~ 6" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            }
        } while (!valid);

        // ������ ���� ����
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
            cout << "�߸� �Է��߽��ϴ�." << "\n";
        }
    }

    return 0;
}