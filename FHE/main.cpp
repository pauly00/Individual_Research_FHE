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

// CSV 파일을 읽어서 데이터를 저장하는 함수
vector<EnergyData> loadEnergyData(const string& filename) {
	vector<EnergyData> data; // 데이터 저장
	ifstream file(filename); // 파일 열기
	string line; // 한 줄씩 읽기

	getline(file, line); // 첫 줄은 헤더이므로 무시

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

	file.close(); // 파일 닫기
	return data; // 데이터 반환
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

// 1. 특정 구간의 월별 사용량 합산
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

// 2. 비정상 패턴 탐지 (전력 사용량 급증)
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

int main() {
	string filename = "한국소비자원_에너지 사용량 (전기)_20240731.csv";
	cout << "Used data: " << filename << endl;

	vector<EnergyData> data = loadEnergyData(filename); // 데이터 읽기
	cout << "Data loaded: " << data.size() << " entries" << endl; // 데이터 개수 출력
	int data_size = data.size();

	// BFV 스킴 설정
	EncryptionParameters bfv_parms(scheme_type::bfv);
	size_t poly_modulus_degree = 4096; // 최대 4096개의 독립된 메시지를 암호화
	bfv_parms.set_poly_modulus_degree(poly_modulus_degree); // 다항식 모듈러스 설정
	bfv_parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree)); // 4096에 맞도록 modulus 크기 정하기
	bfv_parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20)); // 평문 모듈러스 설정


	SEALContext context(bfv_parms); // 컨텍스트 생성
	KeyGenerator keygen(context); // 키 생성
	PublicKey public_key; // 공개 키
	SecretKey secret_key = keygen.secret_key(); // 비밀키 생성
	keygen.create_public_key(public_key); // 공개키 생성

	Encryptor encryptor(context, public_key); // 암호화 객체 생성
	Evaluator evaluator(context); // 연산 객체 생성
	Decryptor decryptor(context, secret_key); // 복호화 객체 생성
	BatchEncoder encoder(context); // 인코더 객체 생성

	// 회전 키 생성
	GaloisKeys gal_keys;
	keygen.create_galois_keys(gal_keys);


	// 에너지 사용량 데이터 암호화 (년도, 월, 사용량)
	vector<Ciphertext> encrypted_data; // 암호화된 데이터
	encryptEnergyData(data, encrypted_data, encryptor, encoder); // 데이터 암호화

	// 암호화된 데이터 개수 출력(열 형태)
	cout << "Data encrypted: " << encrypted_data.size() << " entries" << endl;

	while (true) {
		int choice;
		cout << "Choose the analysis type (1: Partial Summation, 2: Detect Anomalies, -1: Exit): ";
		cin >> choice;

		switch (choice) {
		case 1:
			partialSummation(encrypted_data, evaluator, encoder, gal_keys, decryptor);
			break;
		case 2:
			detectAnomalies(encrypted_data, evaluator, decryptor, encoder, gal_keys);
			break;
		case -1:
			return 0;
		default:
			cout << "Invalid choice" << endl;
		}
	}

	return 0;
}