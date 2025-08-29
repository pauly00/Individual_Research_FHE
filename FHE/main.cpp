#include <iostream>
#include "seal/seal.h"
#include <fstream> // 파일 입출력
#include <sstream> // 문자열 스트림
#include <vector>
#include <string>


using namespace std;
using namespace seal;


// 전력 사용량 데이터 저장 구조체
struct EnergyData {
	int year;
	int month;
	double usage;
};

// 함수 선언
bool runBFV();
bool runCKKS();

// 암호화 함수
void encryptEnergyData(vector<EnergyData>&, vector<Ciphertext>&, Encryptor&, BatchEncoder&);
void encryptEnergyDataCKKS(vector<EnergyData>&, vector<Ciphertext>&, Encryptor&, CKKSEncoder&);

// 데이터 분석
void partialSummation(vector<Ciphertext>&, Evaluator&, BatchEncoder&, GaloisKeys&, Decryptor&);
void detectAnomalies(vector<Ciphertext>&, Evaluator&, Decryptor&, BatchEncoder&, GaloisKeys&);

string filename;
int data_choice; // 1 = 전기, 2 = 가스


// 시계열 분석
void predictAR(vector<Ciphertext>&, Evaluator&, Decryptor&, CKKSEncoder&, Encryptor&, GaloisKeys&);
void predictARMA(vector<Ciphertext>&, Evaluator&, Decryptor&, CKKSEncoder&, Encryptor&, GaloisKeys&);
void predictARIMA(vector<Ciphertext>&, Evaluator&, Decryptor&, CKKSEncoder&, Encryptor&, GaloisKeys&);
void predictSARIMA(vector<Ciphertext>&, Evaluator&, Decryptor&, CKKSEncoder&, Encryptor&, GaloisKeys&);


// 메인 함수
int main() {
	while (true) {
		int scheme_choice;
		cout << "Select encryption scheme (1: BFV for integer, 2: CKKS for real, -1: Exit): ";
		cin >> scheme_choice;

		if (scheme_choice == 1) {
			runBFV(); // 정수
		}
		else if (scheme_choice == 2) {
			runCKKS();  // 실수
		}
		else if (scheme_choice == -1) {
			cout << "Exiting..." << endl;
			break; // 종료
		}
		else {
			cout << "Invalid choice." << endl;
		}
	}
	return 0;
}


// CSV 파일을 읽어서 데이터를 저장하는 함수
vector<EnergyData> loadEnergyData(const string& filename) {
	vector<EnergyData> data; // 데이터 저장
	ifstream file(filename); // 파일 열기
	string line; // 한 줄씩 읽기

	getline(file, line); // 해더 무시

	while (getline(file, line)) { // 한 줄씩 읽어서
		stringstream ss(line); // 문자열 스트림 생성
		string token; // 토큰
		EnergyData entry; // 데이터 저장

		getline(ss, token, ','); // 년도 읽기
		entry.year = stoi(token); // 정수로 변환하여 저장

		getline(ss, token, ','); // 월 읽기
		entry.month = stoi(token); // 정수로 변환하여 저장

		getline(ss, token, ','); // 사용량 읽기
		entry.usage = stod(token); // 실수로 변환하여 저장

		data.push_back(entry); // 데이터 저장
	}

	file.close();
	return data;
}

// 에너지 사용량 데이터 암호화 함수
void encryptEnergyData(vector<EnergyData>& data, vector<Ciphertext>& encrypted_data, Encryptor& encryptor, BatchEncoder& encoder) {
	// 열 데이터 초기화
	vector<uint64_t> year_col(encoder.slot_count()); // 년도
	vector<uint64_t> month_col(encoder.slot_count()); // 월
	vector<uint64_t> usage_col(encoder.slot_count()); // 사용량

	Plaintext plain_year, plain_month, plain_usage;

	// 데이터를 열 단위로
	for (size_t i = 0; i < min(data.size(), encoder.slot_count()); ++i) {
		year_col[i] = static_cast<uint64_t>(data[i].year);
		month_col[i] = static_cast<uint64_t>(data[i].month);
		usage_col[i] = static_cast<uint64_t>(data[i].usage);
	}

	// 인코딩
	encoder.encode(year_col, plain_year);
	encoder.encode(month_col, plain_month);
	encoder.encode(usage_col, plain_usage);

	// 암호화
	Ciphertext encrypted_year, encrypted_month, encrypted_usage;
	encryptor.encrypt(plain_year, encrypted_year);
	encryptor.encrypt(plain_month, encrypted_month);
	encryptor.encrypt(plain_usage, encrypted_usage);

	encrypted_data.push_back(encrypted_year);
	encrypted_data.push_back(encrypted_month);
	encrypted_data.push_back(encrypted_usage);
}

// 에너지 사용량 데이터 암호화 함수(실수)
void encryptEnergyDataCKKS(vector<EnergyData>& data, vector<Ciphertext>& encrypted_data, Encryptor& encryptor, CKKSEncoder& encoder) {
	// 열 데이터 초기화
	vector<double> year_col(encoder.slot_count()); // 년도
	vector<double> month_col(encoder.slot_count()); // 월
	vector<double> usage_col(encoder.slot_count()); // 사용량

	Plaintext plain_year, plain_month, plain_usage;

	// 데이터를 열 단위로
	for (size_t i = 0; i < min(data.size(), encoder.slot_count()); ++i) {
		year_col[i] = static_cast<double>(data[i].year);
		month_col[i] = static_cast<double>(data[i].month);
		usage_col[i] = data[i].usage; // 실수 그대로 저장
	}

	// 인코딩
	double scale = pow(2.0, 40); // 스케일링 팩터 설정
	encoder.encode(year_col, scale, plain_year);
	encoder.encode(month_col, scale, plain_month);
	encoder.encode(usage_col, scale, plain_usage);

	// 암호화
	Ciphertext encrypted_year, encrypted_month, encrypted_usage;
	encryptor.encrypt(plain_year, encrypted_year);
	encryptor.encrypt(plain_month, encrypted_month);
	encryptor.encrypt(plain_usage, encrypted_usage);

	encrypted_data.push_back(encrypted_year);
	encrypted_data.push_back(encrypted_month);
	encrypted_data.push_back(encrypted_usage);
}

// BFV 실행 함수(정수)
bool runBFV() {
	string filename = "한국소비자원_에너지 사용량 (전기)_20250228.csv"; // 데이터 업데이트
	cout << "Used data: " << filename << endl;

	vector<EnergyData> data = loadEnergyData(filename);
	cout << "BFV Data loaded: " << data.size() << " entries" << endl;

	// BFV 스킴 설정
	EncryptionParameters parms(scheme_type::bfv);
	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	// 암호화 컨텍스트 생성
	SEALContext context(parms);
	KeyGenerator keygen(context);
	PublicKey public_key;
	SecretKey secret_key = keygen.secret_key();
	keygen.create_public_key(public_key);

	// 암호화, 평가, 복호화, 인코딩 객체 생성
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);
	Decryptor decryptor(context, secret_key);
	BatchEncoder encoder(context);

	// 회전 연산
	GaloisKeys gal_keys;
	keygen.create_galois_keys(gal_keys);

	// 암호화
	vector<Ciphertext> encrypted_data;
	encryptEnergyData(data, encrypted_data, encryptor, encoder);

	cout << "Data encrypted: " << encrypted_data.size() << " entries" << endl;

	// 분석 기능 실행
	while (true) {
		int choice;
		cout << "Choose the analysis type (1: Partial Summation, 2: Detect Anomalies, -1: Back): ";
		cin >> choice;

		switch (choice) {
		case 1:
			partialSummation(encrypted_data, evaluator, encoder, gal_keys, decryptor);
			break;
		case 2:
			detectAnomalies(encrypted_data, evaluator, decryptor, encoder, gal_keys);
			break;
		case -1:
			return false; // 종료
		default:
			cout << "Invalid choice" << endl;
		}
	}
}

// 1. 특정 구간의 월별 사용량 합산 (BFV 스킴)
void partialSummation(vector<Ciphertext>& encrypted_data, Evaluator& evaluator, BatchEncoder& encoder, GaloisKeys& gal_keys, Decryptor& decryptor) {
	Ciphertext& encrypted_years = encrypted_data[0]; // 년 데이터
	Ciphertext& encrypted_months = encrypted_data[1]; // 월 데이터
	Ciphertext& encrypted_usages = encrypted_data[2]; // 사용량 데이터
	int start; // 시작 인덱스
	cout << "Enter the start index of the range(starting from 0): ";
	cin >> start;
	int end = start + 2;

	// 구간 합산을 위한 초기화
	Ciphertext partial_sum = encrypted_usages;
	Plaintext plain_zero;
	encoder.encode(vector<uint64_t>(encoder.slot_count(), 0ULL), plain_zero); // 0으로 초기화
	evaluator.add_plain_inplace(partial_sum, plain_zero); // 0으로 초기화

	// start부터 end까지 회전하며 값 추가
	for (int i = start; i < end; i++) {
		Ciphertext rotated_usage;
		evaluator.rotate_rows(encrypted_usages, start - i, gal_keys, rotated_usage); // 회전
		evaluator.add_inplace(partial_sum, rotated_usage); // 합산
	}

	// 결과 복호화
	Plaintext plain_result;
	decryptor.decrypt(partial_sum, plain_result);

	vector<uint64_t> decoded_result;
	encoder.decode(plain_result, decoded_result);


	// 년도와 월 데이터 복호화
	Plaintext plain_years, plain_months;
	decryptor.decrypt(encrypted_years, plain_years);
	decryptor.decrypt(encrypted_months, plain_months);

	vector<uint64_t> decoded_years(encoder.slot_count());
	vector<uint64_t> decoded_months(encoder.slot_count());
	encoder.decode(plain_years, decoded_years);
	encoder.decode(plain_months, decoded_months);


	cout << "Total usage from slot " << decoded_years[start] << "-"
		<< decoded_months[start] << " to " << decoded_years[end] << "-" << decoded_months[end]
		<< ": " << decoded_result[start] << " kWh" << endl;
}

// 2. 비정상 패턴 탐지 (전력 사용량 급증) (BFV 스킴)
void detectAnomalies(vector<Ciphertext>& encrypted_data, Evaluator& evaluator, Decryptor& decryptor, BatchEncoder& encoder, GaloisKeys& gal_keys) {
	Ciphertext& encrypted_years = encrypted_data[0]; // 년 데이터
	Ciphertext& encrypted_months = encrypted_data[1]; // 월 데이터
	Ciphertext& encrypted_usages = encrypted_data[2]; // 사용량 데이터

	// 사용량 데이터 로테이션 (1칸 왼쪽으로 이동)
	Ciphertext rotated_usages;
	evaluator.rotate_rows(encrypted_usages, -1, gal_keys, rotated_usages);

	// 사용량 차이 계산
	Ciphertext diff;
	evaluator.sub(encrypted_usages, rotated_usages, diff);

	// 결과 복호화 및 디코딩
	Plaintext plain_diff;
	decryptor.decrypt(diff, plain_diff);
	vector<uint64_t> decoded_diff(encoder.slot_count());
	encoder.decode(plain_diff, decoded_diff);

	// 년도와 월 데이터 복호화
	Plaintext plain_years, plain_months;
	decryptor.decrypt(encrypted_years, plain_years);
	decryptor.decrypt(encrypted_months, plain_months);

	vector<uint64_t> decoded_years(encoder.slot_count());
	vector<uint64_t> decoded_months(encoder.slot_count());
	encoder.decode(plain_years, decoded_years);
	encoder.decode(plain_months, decoded_months);

	// 결과 출력
	for (size_t i = 1; i < encoder.slot_count(); ++i) {
		if (decoded_years[i] == 0 && decoded_months[i] == 0) {
			// null 데이터가 발견되면 종료
			break;
		}

		// 음수 처리
		int64_t signed_diff = static_cast<int64_t>(decoded_diff[i]);
		uint64_t plain_modulus = 1ULL << 20; // 환경에 맞는 평문 모듈러스 설정
		if (signed_diff > static_cast<int64_t>(plain_modulus / 2)) {
			signed_diff -= static_cast<int64_t>(plain_modulus);
		}

		// 결과 출력
		cout << "Year: " << decoded_years[i] << ", Month: " << decoded_months[i] << ", Result: ";
		if (signed_diff < 0) {
			cout << "Normal (Negative)" << endl;
		}
		else if (decoded_diff[i] >= 50000) {
			cout << "Abnormal" << endl;
		}
		else {
			cout << "Normal" << endl;
		}
	}
}


// CKKS 실행 함수(실수)
bool runCKKS() {

	cout << "Choose dataset\n";
	cout << "1. 전기 에너지 사용량 (정수)\n";
	cout << "2. 가스 에너지 사용량 (실수)\n: ";
	cin >> data_choice;

	while (true) {
		if (data_choice == 1) {
			filename = "한국소비자원_에너지 사용량 (전기)_20250228.csv";
			break;
		}
		else if (data_choice == 2) {
			filename = "한국소비자원_에너지 사용량 (가스)_20250228.csv";
			break;
		}
		else {
			cout << "Invalid choice." << endl;
		}
	}

	cout << "Used data: " << filename << endl;

	vector<EnergyData> data = loadEnergyData(filename);
	cout << "CKKS data loaded: " << data.size() << " entries" << endl;

	// CKKS 파라미터 설정
	EncryptionParameters parms(scheme_type::ckks);
	size_t poly_modulus_degree = 8192*2; // 8192의 배수로 설정
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40,40, 40, 40,40, 60 })); // 계수 모듈러스 설정

	// 암호화 컨텍스트 생성
	SEALContext context(parms);
	KeyGenerator keygen(context);
	PublicKey public_key;
	SecretKey secret_key = keygen.secret_key();
	keygen.create_public_key(public_key);

	// 암호화, 평가, 복호화, 인코딩 객체 생성
	Encryptor encryptor(context, public_key);
	Decryptor decryptor(context, secret_key);
	Evaluator evaluator(context);
	CKKSEncoder encoder(context);

	double scale = pow(2.0, 40); // 스케일링 팩터 설정

	// 데이터 인코딩 및 암호화
	vector<double> usage_vec(encoder.slot_count(), 0.0);
	for (size_t i = 0; i < min(data.size(), encoder.slot_count()); ++i) {
		usage_vec[i] = data[i].usage;
	}

	// 인코딩 및 암호화
	Plaintext plain;
	encoder.encode(usage_vec, scale, plain);

	// 암호화
	Ciphertext encrypted;
	encryptor.encrypt(plain, encrypted);

	// 복호화 및 확인
	Plaintext decrypted_plain;
	decryptor.decrypt(encrypted, decrypted_plain);

	// 디코딩
	vector<double> decoded;
	encoder.decode(decrypted_plain, decoded);

	// 회전 연산
	GaloisKeys gal_keys;
	keygen.create_galois_keys(gal_keys);

	// 암호화
	vector<Ciphertext> encrypted_data;
	encryptEnergyDataCKKS(data, encrypted_data, encryptor, encoder);

	cout << "Data encrypted: " << encrypted_data.size() << " entries" << endl;

	// 분석 기능 실행
	while (true) {
		int choice;
		cout << "Choose the analysis type (1: AR, 2: ARMA, 3: ARIMA, 4: SARIMA, -1: Back to main): ";
		cin >> choice;

		switch (choice) {
		case 1:
			predictAR(encrypted_data, evaluator, decryptor, encoder, encryptor, gal_keys);
			break;
		case 2:
			predictARMA(encrypted_data, evaluator, decryptor, encoder, encryptor, gal_keys);
			break;
		case 3:
			predictARIMA(encrypted_data, evaluator, decryptor, encoder, encryptor, gal_keys);
			break;
		case 4:
			predictSARIMA(encrypted_data, evaluator, decryptor, encoder, encryptor, gal_keys);
			break;
		case -1:
			return true; // 종료
		default:
			cout << "Invalid choice" << endl;
		}
	}
}


// 시계열 분석 함수들
// 1) AR(2)
void predictAR(vector<Ciphertext>& encrypted_data, Evaluator& evaluator, Decryptor& decryptor,
	CKKSEncoder& encoder, Encryptor& encryptor, GaloisKeys& gal_keys) {
	Ciphertext& encrypted_years = encrypted_data[0];
	Ciphertext& encrypted_months = encrypted_data[1];
	Ciphertext& encrypted_usages = encrypted_data[2];

	size_t slot_count = encoder.slot_count(); // 슬롯 개수
	double scale = pow(2.0, 40); // 스케일링 팩터 설정

	// 계수 설정: 인코딩만 필요
	double phi1 = 0.73, phi2 = -0.58, c = 265315.8; // 전기
	if (filename.find("가스") != string::npos) {
		phi1 = 0.83; phi2 = -0.63; c = 8321.9;
	}

	// 계수 인코딩
	Plaintext plain_phi1, plain_phi2, plain_c;
	encoder.encode(vector<double>(slot_count, phi1), scale, plain_phi1); // φ₁
	encoder.encode(vector<double>(slot_count, phi2), scale, plain_phi2); // φ₂
	encoder.encode(vector<double>(slot_count, c), scale, plain_c); // c


	// 예측 대상 초기값 준비: y_t, y_{t-1}
	Ciphertext y_t = encrypted_usages; // 최신 값
	Ciphertext y_t_1 = encrypted_usages; // 이전 값
	evaluator.rotate_vector_inplace(y_t, -1, gal_keys); // y_{t-1} 위치로 정렬
	evaluator.rotate_vector_inplace(y_t_1, -2, gal_keys); // y_{t-2} 위치로 정렬

	vector<Ciphertext> forecasts; // 예측 결과 저장

	for (int i = 0; i < 6; ++i) {
		Ciphertext temp1, temp2;

		Plaintext phi1_temp; // φ₁
		encoder.encode(vector<double>(slot_count, phi1), y_t.scale(), phi1_temp); // 인코딩
		evaluator.mod_switch_to_inplace(phi1_temp, y_t.parms_id()); // 파라미터 ID 맞춤
		evaluator.multiply_plain(y_t, phi1_temp, temp1); // y_t * φ₁
		evaluator.rescale_to_next_inplace(temp1); // 레벨 조정

		Plaintext phi2_temp; // φ₂
		encoder.encode(vector<double>(slot_count, phi2), y_t_1.scale(), phi2_temp);
		evaluator.mod_switch_to_inplace(phi2_temp, y_t_1.parms_id());
		evaluator.multiply_plain(y_t_1, phi2_temp, temp2); // y_{t-1} * φ₂
		evaluator.rescale_to_next_inplace(temp2);

		evaluator.mod_switch_to_inplace(temp2, temp1.parms_id()); // temp2의 파라미터 ID를 temp1에 맞춤
		temp2.scale() = temp1.scale(); // temp2의 스케일을 temp1에 맞춤

		Plaintext c_temp; // c
		encoder.encode(vector<double>(slot_count, c), temp1.scale(), c_temp);
		evaluator.mod_switch_to_inplace(c_temp, temp1.parms_id());

		evaluator.add_plain_inplace(temp1, c_temp); // temp1 += c
		evaluator.add_inplace(temp1, temp2); // temp1 += temp2

		forecasts.push_back(temp1);

		// 다음 예측을 위한 입력값 업데이트
		if (i >= 1) { // i가 1 이상이면 이전 예측값을 사용
			y_t_1 = forecasts[i - 1]; // 이전 예측값을 y_{t-1}으로 설정
			y_t = forecasts[i]; // 현재 예측값을 y_t으로 설정
		}
		else { // i가 0이면 초기값 사용
			y_t_1 = y_t;
			y_t = temp1;
		}
	}

	// 연도, 월 복호화
	Plaintext plain_years, plain_months;
	decryptor.decrypt(encrypted_years, plain_years);
	decryptor.decrypt(encrypted_months, plain_months);

	vector<double> decoded_years, decoded_months;
	encoder.decode(plain_years, decoded_years);
	encoder.decode(plain_months, decoded_months);

	int last_valid_index = -1; // 마지막 유효한 인덱스 찾기
	for (int i = static_cast<int>(decoded_years.size()) - 1; i >= 0; --i) { // 뒤에서부터 유효한 년, 월 찾기
		if (decoded_years[i] > 0 && decoded_months[i] >= 1 && decoded_months[i] <= 12) {
			last_valid_index = i; // 유효한 인덱스 찾으면 저장
			break;
		}
	}

	if (last_valid_index == -1) {
		cerr << "[Error] No valid date found in decoded slots." << endl;
		return;
	}

	// 예측 시작 시점: 마지막 유효한 년, 월의 다음 달
	int year = static_cast<int>(round(decoded_years[last_valid_index]));
	int month = static_cast<int>(round(decoded_months[last_valid_index]));

	// 예측 시작 시점
	month += 0;
	if (month > 12) {
		month = 1;
		year += 1;
	}


	// 예측 결과 복호화 및 출력
	cout << "AR(2) Forecast for next 6 months:\n";
	for (int i = 0; i < 6; ++i) {
		Plaintext plain_result;
		decryptor.decrypt(forecasts[i], plain_result);
		vector<double> decoded;
		encoder.decode(plain_result, decoded);

		month += 1;
		if (month > 12) {
			month = 1;
			year += 1;
		}

		cout << "Year: " << year << ", Month: " << month
			<< ", Usage: " << static_cast<double>(decoded[0]) << " kWh" << endl;
	}
}


// 2) ARMA(2,1)
void predictARMA(vector<Ciphertext>& encrypted_data, Evaluator& evaluator, Decryptor& decryptor,
	CKKSEncoder& encoder, Encryptor& encryptor, GaloisKeys& gal_keys) {

	Ciphertext& encrypted_years = encrypted_data[0];
	Ciphertext& encrypted_months = encrypted_data[1];
	Ciphertext& encrypted_usages = encrypted_data[2];

	size_t slot_count = encoder.slot_count(); // 슬롯 개수
	double scale = pow(2.0, 40); // 스케일링 팩터 설정

	// 계수 설정
	double phi1 = 0.83, phi2 = -0.63, theta1 = -0.15, c = 265315.8; // 전기
	if (filename.find("가스") != string::npos) {
		phi1 = 0.70; phi2 = -0.58; theta1 = -0.21; c = 8321.9;
	}

	// 계수 인코딩
	Plaintext plain_phi1, plain_phi2, plain_theta1, plain_c; // φ₁, φ₂, θ₁, c
	encoder.encode(vector<double>(slot_count, phi1), scale, plain_phi1);
	encoder.encode(vector<double>(slot_count, phi2), scale, plain_phi2);
	encoder.encode(vector<double>(slot_count, theta1), scale, plain_theta1);
	encoder.encode(vector<double>(slot_count, c), scale, plain_c);

	// 초기 입력값 준비
	Ciphertext y_t = encrypted_usages; // 최신 값
	Ciphertext y_t_1 = encrypted_usages; // 이전 값
	evaluator.rotate_vector_inplace(y_t, -1, gal_keys); // y_{t-1} 위치로 정렬
	evaluator.rotate_vector_inplace(y_t_1, -2, gal_keys); // y_{t-2} 위치로 정렬

	Plaintext zero_plain; // 0으로 초기화
	encoder.encode(vector<double>(slot_count, 0.0), scale, zero_plain); // 인코딩
	Ciphertext last_error; // 잔차 암호화
	encryptor.encrypt(zero_plain, last_error);

	vector<Ciphertext> forecasts; // 예측 결과 저장
	for (int i = 0; i < 6; ++i) {
		Ciphertext term1, term2, term3; // 각 항의 결과 저장

		Plaintext phi1_temp; // φ₁ * y_t
		encoder.encode(vector<double>(slot_count, phi1), y_t.scale(), phi1_temp); // 인코딩
		evaluator.mod_switch_to_inplace(phi1_temp, y_t.parms_id()); // 파라미터 ID 맞춤
		evaluator.multiply_plain(y_t, phi1_temp, term1);
		evaluator.rescale_to_next_inplace(term1); // 레벨 조정

		Plaintext phi2_temp; // φ₂ * y_{t-1}
		encoder.encode(vector<double>(slot_count, phi2), y_t_1.scale(), phi2_temp);
		evaluator.mod_switch_to_inplace(phi2_temp, y_t_1.parms_id());
		evaluator.multiply_plain(y_t_1, phi2_temp, term2);
		evaluator.rescale_to_next_inplace(term2);

		Plaintext theta_temp; // θ₁ * last_error
		encoder.encode(vector<double>(slot_count, theta1), last_error.scale(), theta_temp);
		evaluator.mod_switch_to_inplace(theta_temp, last_error.parms_id());
		evaluator.multiply_plain(last_error, theta_temp, term3);
		evaluator.rescale_to_next_inplace(term3);

		evaluator.mod_switch_to_inplace(term2, term1.parms_id()); // term2의 파라미터 ID를 term1에 맞춤
		evaluator.mod_switch_to_inplace(term3, term1.parms_id()); // term3의 파라미터 ID를 term1에 맞춤
		term2.scale() = term1.scale(); // term2의 스케일을 term1에 맞춤
		term3.scale() = term1.scale();

		Plaintext c_temp; // c
		encoder.encode(vector<double>(slot_count, c), term1.scale(), c_temp);
		evaluator.mod_switch_to_inplace(c_temp, term1.parms_id()); // term1의 파라미터 ID에 맞춤

		evaluator.add_plain_inplace(term1, c_temp); // term1 += c
		evaluator.add_inplace(term1, term2); // term1 += term2
		evaluator.add_inplace(term1, term3); // term1 += term3

		forecasts.push_back(term1);

		y_t_1 = y_t; // y_{t-1} 업데이트
		y_t = term1; // y_t 업데이트
		last_error = term1; // 잔차 업데이트
	}

	// 연도, 월 복호화
	Plaintext plain_years, plain_months;
	decryptor.decrypt(encrypted_years, plain_years);
	decryptor.decrypt(encrypted_months, plain_months);

	vector<double> decoded_years, decoded_months;
	encoder.decode(plain_years, decoded_years);
	encoder.decode(plain_months, decoded_months);

	int last_valid_index = -1; // 마지막 유효한 인덱스 찾기
	for (int i = static_cast<int>(decoded_years.size()) - 1; i >= 0; --i) { // 뒤에서부터 유효한 년, 월 찾기
		if (decoded_years[i] > 0 && decoded_months[i] >= 1 && decoded_months[i] <= 12) {
			last_valid_index = i;
			break;
		}
	}

	if (last_valid_index == -1) {
		cerr << "[Error] No valid date found in decoded slots." << endl;
		return;
	}

	// 예측 시작 시점: 마지막 유효한 년, 월의 다음 달
	int year = static_cast<int>(round(decoded_years[last_valid_index]));
	int month = static_cast<int>(round(decoded_months[last_valid_index]));

	// 예측 시작 시점
	month += 0;
	if (month > 12) {
		month = 1;
		year += 1;
	}


	// 예측 결과 복호화 및 출력
	cout << "ARMA(2,1) Forecast for next 6 months:\n";
	for (int i = 0; i < 6; ++i) {
		Plaintext plain_result;
		decryptor.decrypt(forecasts[i], plain_result);
		vector<double> decoded;
		encoder.decode(plain_result, decoded);

		month += 1;
		if (month > 12) {
			month = 1;
			year += 1;
		}

		cout << "Year: " << year << ", Month: " << month
			<< ", Usage: " << static_cast<double>(decoded[0]) << " kWh" << endl;
	}
}


// 3) ARIMA(2,1,1)
void predictARIMA(vector<Ciphertext>& encrypted_data, Evaluator& evaluator, Decryptor& decryptor,
	CKKSEncoder& encoder, Encryptor& encryptor, GaloisKeys& gal_keys) {
	Ciphertext& encrypted_years = encrypted_data[0];
	Ciphertext& encrypted_months = encrypted_data[1];
	Ciphertext& encrypted_usages = encrypted_data[2];

	size_t slot_count = encoder.slot_count();
	double scale = pow(2.0, 40);

	// 계수 설정
	double phi1 = 0.82, phi2 = -0.61, theta1 = -0.12, c = 265315.8; // 전기
	if (filename.find("가스") != string::npos) {
		phi1 = 0.68; phi2 = -0.52; theta1 = -0.18; c = 8321.9;
	}

	// 계수 인코딩
	Plaintext plain_phi1, plain_phi2, plain_theta1, plain_c; // φ₁, φ₂, θ₁, c
	encoder.encode(vector<double>(slot_count, phi1), scale, plain_phi1);
	encoder.encode(vector<double>(slot_count, phi2), scale, plain_phi2);
	encoder.encode(vector<double>(slot_count, theta1), scale, plain_theta1);
	encoder.encode(vector<double>(slot_count, c), scale, plain_c);

	// 초기 입력값 준비
	Ciphertext y_t = encrypted_usages;
	Ciphertext y_t_1 = encrypted_usages;
	evaluator.rotate_vector_inplace(y_t, -1, gal_keys);
	evaluator.rotate_vector_inplace(y_t_1, -2, gal_keys);

	Ciphertext last_error; // 잔차 초기화
	Plaintext zero_plain; // 0으로 초기화
	encoder.encode(vector<double>(slot_count, 0.0), scale, zero_plain);
	encryptor.encrypt(zero_plain, last_error);

	vector<Ciphertext> forecasts;

	for (int i = 0; i < 6; ++i) {
		Ciphertext term1, term2, term3; // 각 항의 결과 저장

		Plaintext phi1_temp, phi2_temp, theta1_temp, c_temp; // 임시 Plaintext 객체
		
		// 계수 인코딩
		encoder.encode(vector<double>(slot_count, phi1), y_t.scale(), phi1_temp); // φ₁ * y_t
		encoder.encode(vector<double>(slot_count, phi2), y_t_1.scale(), phi2_temp); // φ₂ * y_{t-1}
		encoder.encode(vector<double>(slot_count, theta1), last_error.scale(), theta1_temp); // θ₁ * last_error
		encoder.encode(vector<double>(slot_count, c), y_t.scale(), c_temp); // c

		// 계수 파라미터 ID 맞춤
		evaluator.mod_switch_to_inplace(phi1_temp, y_t.parms_id());
		evaluator.mod_switch_to_inplace(phi2_temp, y_t_1.parms_id());
		evaluator.mod_switch_to_inplace(theta1_temp, last_error.parms_id());
		evaluator.mod_switch_to_inplace(c_temp, y_t.parms_id());

		// 각 항 계산
		evaluator.multiply_plain(y_t, phi1_temp, term1); // y_t * φ₁
		evaluator.rescale_to_next_inplace(term1);

		evaluator.multiply_plain(y_t_1, phi2_temp, term2); // y_{t-1} * φ₂
		evaluator.rescale_to_next_inplace(term2); // 레벨 조정
		evaluator.mod_switch_to_inplace(term2, term1.parms_id()); // term2의 파라미터 ID를 term1에 맞춤
		term2.scale() = term1.scale(); // term2의 스케일을 term1에 맞춤

		evaluator.multiply_plain(last_error, theta1_temp, term3); // last_error * θ₁
		evaluator.rescale_to_next_inplace(term3);
		evaluator.mod_switch_to_inplace(term3, term1.parms_id());
		term3.scale() = term1.scale();

		evaluator.mod_switch_to_inplace(c_temp, term1.parms_id());
		c_temp.scale() = term1.scale();

		evaluator.add_plain_inplace(term1, c_temp); // term1 += c
		evaluator.add_inplace(term1, term2); // term1 += term2
		evaluator.add_inplace(term1, term3); // term1 += term3

		// 예측 결과 저장
		forecasts.push_back(term1);
		if (i >= 1) { // i가 1 이상이면 이전 예측값을 사용
			y_t_1 = y_t;
			y_t = term1;
		}
		else {
			y_t_1 = y_t;
			y_t = term1;
		}
		last_error = term1;
	}

	// 연도, 월 복호화
	Plaintext plain_years, plain_months;
	decryptor.decrypt(encrypted_years, plain_years);
	decryptor.decrypt(encrypted_months, plain_months);

	vector<double> decoded_years, decoded_months;
	encoder.decode(plain_years, decoded_years);
	encoder.decode(plain_months, decoded_months);

	int last_valid_index = -1;
	for (int i = static_cast<int>(decoded_years.size()) - 1; i >= 0; --i) {
		if (decoded_years[i] > 0 && decoded_months[i] >= 1 && decoded_months[i] <= 12) {
			last_valid_index = i;
			break;
		}
	}

	if (last_valid_index == -1) {
		cerr << "[Error] No valid date found in decoded slots." << endl;
		return;
	}

	// 예측 시작 시점: 마지막 유효한 년, 월의 다음 달
	int year = static_cast<int>(round(decoded_years[last_valid_index]));
	int month = static_cast<int>(round(decoded_months[last_valid_index]));

	// 예측 시작 시점
	month += 0;
	if (month > 12) {
		month = 1;
		year += 1;
	}


	// 예측 결과 복호화 및 출력
	cout << "ARIMA(2,1,1) Forecast for next 6 months:\n";
	for (int i = 0; i < 6; ++i) {
		Plaintext plain_result;
		decryptor.decrypt(forecasts[i], plain_result);
		vector<double> decoded;
		encoder.decode(plain_result, decoded);

		month += 1;
		if (month > 12) {
			month = 1;
			year += 1;
		}

		cout << "Year: " << year << ", Month: " << month
			<< ", Usage: " << static_cast<int>(decoded[0]) << " kWh" << endl;
	}
}


// 4) SARIMA(2,1,1)(1,1,1,12)
void predictSARIMA(vector<Ciphertext>& encrypted_data, Evaluator& evaluator, Decryptor& decryptor,
	CKKSEncoder& encoder, Encryptor& encryptor, GaloisKeys& gal_keys) {
	Ciphertext& encrypted_years = encrypted_data[0];
	Ciphertext& encrypted_months = encrypted_data[1];
	Ciphertext& encrypted_usages = encrypted_data[2];

	size_t slot_count = encoder.slot_count();
	double scale = pow(2.0, 40);

	double phi1 = 0.6, phi2 = -0.4, theta1 = -0.2, Phi1 = 0.5, Theta1 = -0.3, c = 265315.8; // 전기
	if (filename.find("가스") != string::npos) {
		phi1 = 0.7; phi2 = -0.5; theta1 = -0.25; Phi1 = 0.6; Theta1 = -0.35; c = 8321.9;
	}

	// 계수 인코딩
	Plaintext plain_phi1, plain_phi2, plain_theta1, plain_Phi1, plain_Theta1, plain_c;
	encoder.encode(vector<double>(slot_count, phi1), scale, plain_phi1);
	encoder.encode(vector<double>(slot_count, phi2), scale, plain_phi2);
	encoder.encode(vector<double>(slot_count, theta1), scale, plain_theta1);
	encoder.encode(vector<double>(slot_count, Phi1), scale, plain_Phi1);
	encoder.encode(vector<double>(slot_count, Theta1), scale, plain_Theta1);
	encoder.encode(vector<double>(slot_count, c), scale, plain_c);

	// 초기 입력값 준비
	Ciphertext y_t = encrypted_usages;
	Ciphertext y_t_1 = encrypted_usages;
	Ciphertext y_t_12 = encrypted_usages;
	evaluator.rotate_vector_inplace(y_t, -1, gal_keys); // y_{t-1} 위치로 정렬
	evaluator.rotate_vector_inplace(y_t_1, -2, gal_keys); // y_{t-2} 위치로 정렬
	evaluator.rotate_vector_inplace(y_t_12, -12, gal_keys); // y_{t-12} 위치로 정렬

	// 잔차 초기화
	Ciphertext last_error; // 잔차 초기화
	Plaintext zero_plain; // 0으로 초기화
	encoder.encode(vector<double>(slot_count, 0.0), scale, zero_plain);
	encryptor.encrypt(zero_plain, last_error);

	// 예측 결과 저장
	vector<Ciphertext> forecasts;
	for (int i = 0; i < 6; ++i) {
		Ciphertext term1, term2, term3, term4, term5; // 각 항의 결과 저장

		Plaintext phi1_temp, phi2_temp, theta1_temp; // 임시 Plaintext 객체
		Plaintext p_Phi1, p_Theta1, p_c; // 인코딩용 Plaintext 객체

		// 계수 인코딩
		encoder.encode(vector<double>(slot_count, phi1), y_t.scale(), phi1_temp); // φ₁ * y_t
		evaluator.mod_switch_to_inplace(phi1_temp, y_t.parms_id()); // 파라미터 ID 맞춤
		evaluator.multiply_plain(y_t, phi1_temp, term1);
		evaluator.rescale_to_next_inplace(term1); // 레벨 조정

		encoder.encode(vector<double>(slot_count, phi2), y_t_1.scale(), phi2_temp); // φ₂ * y_{t-1}
		evaluator.mod_switch_to_inplace(phi2_temp, y_t_1.parms_id());
		evaluator.multiply_plain(y_t_1, phi2_temp, term2);
		evaluator.rescale_to_next_inplace(term2);
		evaluator.mod_switch_to_inplace(term2, term1.parms_id());

		encoder.encode(vector<double>(slot_count, theta1), last_error.scale(), theta1_temp); // θ₁ * last_error
		evaluator.mod_switch_to_inplace(theta1_temp, last_error.parms_id());
		evaluator.multiply_plain(last_error, theta1_temp, term3);
		evaluator.rescale_to_next_inplace(term3);
		evaluator.mod_switch_to_inplace(term3, term1.parms_id());

		encoder.encode(vector<double>(slot_count, Phi1), y_t_12.scale(), p_Phi1); // Φ₁ * y_{t-12}
		evaluator.mod_switch_to_inplace(p_Phi1, y_t_12.parms_id());
		evaluator.multiply_plain(y_t_12, p_Phi1, term4);
		evaluator.rescale_to_next_inplace(term4);
		evaluator.mod_switch_to_inplace(term4, term1.parms_id());

		encoder.encode(vector<double>(slot_count, Theta1), last_error.scale(), p_Theta1); // Θ₁ * last_error
		evaluator.mod_switch_to_inplace(p_Theta1, last_error.parms_id());
		evaluator.multiply_plain(last_error, p_Theta1, term5);
		evaluator.rescale_to_next_inplace(term5);
		evaluator.mod_switch_to_inplace(term5, term1.parms_id());

		encoder.encode(vector<double>(slot_count, c), term1.scale(), p_c); // c
		evaluator.mod_switch_to_inplace(p_c, term1.parms_id());

		// 각 항의 파라미터 ID와 스케일 맞춤
		term2.scale() = term1.scale();
		term3.scale() = term1.scale();
		term4.scale() = term1.scale();
		term5.scale() = term1.scale();

		// 각 항 더하기
		evaluator.add_inplace(term1, term2); // term1 += term2
		evaluator.add_inplace(term1, term3);
		evaluator.add_inplace(term1, term4);
		evaluator.add_inplace(term1, term5);
		evaluator.add_plain_inplace(term1, p_c);

		forecasts.push_back(term1);

		// 다음 예측을 위한 입력값 업데이트
		y_t_1 = y_t;
		y_t = term1;
		last_error = term1;
	}

	// 연도, 월 복호화
	Plaintext plain_years, plain_months;
	decryptor.decrypt(encrypted_years, plain_years);
	decryptor.decrypt(encrypted_months, plain_months);

	vector<double> decoded_years, decoded_months;
	encoder.decode(plain_years, decoded_years);
	encoder.decode(plain_months, decoded_months);

	int last_valid_index = -1; // 마지막 유효한 인덱스 찾기
	for (int i = static_cast<int>(decoded_years.size()) - 1; i >= 0; --i) { // 뒤에서부터 유효한 년, 월 찾기
		if (decoded_years[i] > 0 && decoded_months[i] >= 1 && decoded_months[i] <= 12) {
			last_valid_index = i;
			break;
		}
	}

	if (last_valid_index == -1) {
		cerr << "[Error] No valid date found in decoded slots." << endl;
		return;
	}

	// 예측 시작 시점: 마지막 유효한 년, 월의 다음 달
	int year = static_cast<int>(round(decoded_years[last_valid_index]));
	int month = static_cast<int>(round(decoded_months[last_valid_index]));

	// 예측 시작 시점
	month += 0;
	if (month > 12) {
		month = 1;
		year += 1;
	}

	// 예측 결과 복호화 및 출력
	cout << "SARIMA(2,1,1)(1,1,1,12) Forecast for next 6 months:\n";
	for (int i = 0; i < 6; ++i) {
		Plaintext plain_result;
		decryptor.decrypt(forecasts[i], plain_result);
		vector<double> decoded;
		encoder.decode(plain_result, decoded);

		month += 1;
		if (month > 12) {
			month = 1;
			year += 1;
		}

		cout << "Year: " << year << ", Month: " << month
			<< ", Usage: " << static_cast<int>(decoded[0]) << " kWh" << endl;
	}
}