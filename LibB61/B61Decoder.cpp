#include <optional>
#include <filesystem>

#include "B61Decoder.h"

using namespace std;

//Dllインスタンス参照用
extern HMODULE dllModule;

B61Decoder::B61Decoder()
{
	m_pThis = this;
}

B61Decoder::~B61Decoder() {
	m_pThis = nullptr;
}

const BOOL B61Decoder::Initialize(DWORD dwRound)
{
	try {
		LoadIniFile();
		acas = AcasCard::GetSmartcardAcas(scardReaderName);
	}
	catch (exception& e) {
		cerr << e.what() << endl;
		return FALSE;
	}

	buffer.clear();
	newData.clear();
	newData.resize(BLOCK_SIZE);
	decBuffer.clear();
	decBuffer.resize(BLOCK_SIZE);

	writeSize = 0;

	try {
		acas->SetMasterKey(HexStringToBytes(masterKeyString));
	}
	catch (exception& e) {
		cerr << e.what() << endl;
		return FALSE;
	}

	return TRUE;
}

void B61Decoder::Release(void)
{
	acas.reset();
}

const BOOL B61Decoder::Decode(BYTE* pSrcBuf, const DWORD dwSrcSize, BYTE** ppDstBuf, DWORD* pdwDstSize)
{
	try {
		buffer.insert(buffer.end(), pSrcBuf, pSrcBuf + dwSrcSize);
		readSize += dwSrcSize;

		switch (step)
		{
		case 0:
			goto STEP0;
		case 1:
			goto STEP1;
		default:
			break;
		}

		while (true) {
		STEP0:
			if (buffer.size() < 2) {
				break;
			}
			if (!TlvHelpers::IsValidTlvHeader(buffer)) {
				auto index = TlvHelpers::TryFindTlvHeaderIndex(buffer);
				if (index == nullopt) {
					break;
				}
				//cout << "Lost sync to TLV header" << endl;
				buffer.erase(buffer.begin(), buffer.begin() + index.value());
			}
			step = 1;
		STEP1:
			if (buffer.size() < 4) {
				break;
			}
			auto dataLength = MmtpPacket::GetBigEndianShort(buffer, 2) + 4;
			if (dataLength > buffer.size()) {
				break;
			}

			auto tlvdata = vector(buffer.begin(), buffer.begin() + dataLength);
			auto dataSpan = span{ tlvdata };
			TlvPacket tlvPacket(dataSpan);
			buffer.erase(buffer.begin(), buffer.begin() + dataLength);

			auto ecm = tlvPacket.GetEcm();
			if (!ecm.empty()) {
				decryptedEcm = acas->DecryptEcm(ecm);
			}

			auto tlv = tlvPacket.GetDecryptedTlv(decryptedEcm);

			if (decBuffer.size() < writeSize + tlv.size()) {
				decBuffer.resize(writeSize + tlv.size());
			}

			std::copy(tlv.begin(), tlv.end(), decBuffer.begin() + writeSize);
			writeSize += tlv.size();

			step = 0;
		}
		*ppDstBuf = &decBuffer[0];
		*pdwDstSize = (DWORD)writeSize;

	}
	catch (exception& e) {
		cerr << e.what() << endl;
		return FALSE;
	}
	writeSize = 0;
	return TRUE;
}

const BOOL B61Decoder::Flush(BYTE** ppDstBuf, DWORD* pdwDstSize)
{
	//以下はDecode()とほぼ同処理

	switch (step)
	{
	case 0:
		goto STEP0;
	case 1:
		goto STEP1;
	default:
		break;
	}
	while (buffer.size() > 0) {
		STEP0:
		if (!TlvHelpers::IsValidTlvHeader(buffer)) {
			auto index = TlvHelpers::TryFindTlvHeaderIndex(buffer);
			if (index == nullopt) {
				break;
			}
			//cout << "Lost sync to TLV header" << endl;
			buffer.erase(buffer.begin(), buffer.begin() + index.value());
		}

		STEP1:
		auto dataLength = MmtpPacket::GetBigEndianShort(buffer, 2) + 4;
		if (dataLength > buffer.size()) {
			break;
		}

		auto tlvdata = vector(buffer.begin(), buffer.begin() + dataLength);
		auto dataSpan = span{ tlvdata };
		TlvPacket tlvPacket(dataSpan);
		buffer.erase(buffer.begin(), buffer.begin() + dataLength);


		shared_ptr<DecryptedEcm> decryptedEcm = nullptr;
		auto ecm = tlvPacket.GetEcm();
		if (ecm.size() != 0) {
			decryptedEcm = acas->DecryptEcm(ecm);
		}

		auto tlv = tlvPacket.GetDecryptedTlv(decryptedEcm);

		if (decBuffer.size() < writeSize + tlv.size()) {
			decBuffer.resize(writeSize + tlv.size());
		}
		std::copy(tlv.begin(), tlv.end(), decBuffer.begin() + writeSize);

		writeSize += tlv.size();
	}
	*ppDstBuf = &decBuffer[0];
	*pdwDstSize = (DWORD)writeSize;

	return TRUE;
}

const BOOL B61Decoder::Reset(void)
{
	buffer.clear();
	newData.clear();
	newData.resize(BLOCK_SIZE);
	decBuffer.clear();
	decBuffer.resize(BLOCK_SIZE);

	readSize = 0;
	writeSize = 0;
	step = 0;

	try {
		acas.reset();
		acas = AcasCard::GetSmartcardAcas(scardReaderName);
	}
	catch (exception& e) {
		cerr << e.what() << endl;
		return FALSE;
	}

	return TRUE;
}

/// <summary>
///(モジュール名).ini ファイルのパスを取得
// ini ファイルは以下のような内容
// [CardReader]
// CardMasterKey=AABBCCDDEEFF0011223344556677889900
// SCardName=Generic Smart Card Reader Interface 0
/// </summary>
/// <returns></returns>
void B61Decoder::LoadIniFile()
{
	//INIファイル名の取得
	std::string moduleFilename;
	{
		char modulePath[MAX_PATH];
		GetModuleFileNameA(dllModule, modulePath, MAX_PATH);
		moduleFilename.assign(modulePath);
		auto lastDot = moduleFilename.find_last_of('.');
		if (lastDot != std::string::npos) {
			moduleFilename.replace(lastDot, std::string::npos, ".ini");
		}
		else {
			moduleFilename += ".ini";
		}
	}

	if (!std::filesystem::exists(moduleFilename)) {
		throw runtime_error(std::format("Cannot found ini file {0}.", moduleFilename));
	}

	const int BUF_SIZE = 512;
	char readBuffer[BUF_SIZE];
	GetPrivateProfileStringA("CardReader", "CardMasterKey", "", readBuffer, BUF_SIZE, moduleFilename.c_str());

	masterKeyString = std::string(readBuffer);
	const int KEY_SIZE = 64;
	if (masterKeyString.size() != KEY_SIZE) {
		throw runtime_error(std::format("Not match card_master_key length in {0}.", moduleFilename));
	}

	GetPrivateProfileStringA("CardReader", "SCardName", "", readBuffer, BUF_SIZE, moduleFilename.c_str());
	scardReaderName = std::string(readBuffer);
}


// hex dumpのテキストをバイト列に変換
std::vector<BYTE> B61Decoder::HexStringToBytes(const std::string& hexStr) {
	if (hexStr.length() % 2 != 0) {
		throw std::invalid_argument("Invalid HEX string length");
	}

	std::vector<BYTE> bytes;
	bytes.reserve(hexStr.length() / 2);

	for (size_t i = 0; i < hexStr.length(); i += 2) {
		BYTE byte = static_cast<BYTE>(std::stoi(hexStr.substr(i, 2), nullptr, 16));
		bytes.push_back(byte);
	}

	return bytes;
}
