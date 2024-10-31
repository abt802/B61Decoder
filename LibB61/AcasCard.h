#pragma once

#include <map>
#include <string>
#include <random>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <winscard.h>
#include <format>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "TlvPacket.h"

class AcasCard
{
public:
	static std::shared_ptr<AcasCard> GetSmartcardAcas(std::string targetReaderName)
	{
		SCARDCONTEXT context;
		LONG result = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
		if (result != SCARD_S_SUCCESS) {
			throw std::runtime_error("Failed to establish smart card context");
		}

		// スマートカードリーダーのリストを取得
		DWORD readersLen = 0;
		result = SCardListReaders(context, nullptr, nullptr, &readersLen);
		if (result != SCARD_S_SUCCESS) {
			SCardReleaseContext(context);
			throw std::runtime_error("Failed to list smart card readers");
		}

		std::vector<char> readersBuffer(readersLen);
		result = SCardListReadersA(context, nullptr, readersBuffer.data(), &readersLen);
		if (result != SCARD_S_SUCCESS) {
			SCardReleaseContext(context);
			throw std::runtime_error("Failed to list smart card readers");
		}

		std::string readerName;
		if (targetReaderName.empty()) {
			std::vector<std::string> readerNames;
			const char* reader = readersBuffer.data();
			while (*reader != '\0') {
				readerNames.push_back(reader);
				reader += strlen(reader) + 1;
			}

			// "Windows Hello"で始まるリーダーを除外
			auto itr = std::remove_if(readerNames.begin(), readerNames.end(), [](std::string name) {
				return name.find("Windows Hello") == 0;
				});
			readerNames.erase(itr, readerNames.end());

			if (readerNames.empty()) {
				SCardReleaseContext(context);
				throw std::runtime_error("No smartcard reader found");
			}

			readerName = readerNames.front();
		}
		else {
			readerName = targetReaderName;
		}

		SCARDHANDLE hCardHandle = 0;
		DWORD protocol;
		result = SCardConnectA(context, readerName.data(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &hCardHandle, &protocol);
		if (result != SCARD_S_SUCCESS) {
			SCardReleaseContext(context);
			throw std::runtime_error(std::format("Failed to connect card reader:{}", readerName));
		}

		auto acas = std::shared_ptr<AcasCard>(new AcasCard(hCardHandle, context));
		acas->Init();
		return acas;
	}

	void Init() {
		BYTE pbSendBuffer[] = { 0x90, 0x30, 0x00, 0x01, 0x00 };
		BYTE pbRecvBuffer[256];
		DWORD dwRecvLength = sizeof(pbRecvBuffer);
		SCARD_IO_REQUEST pioSendPci = { SCARD_PROTOCOL_T1, sizeof(SCARD_IO_REQUEST) };
		LONG lResult = SCardTransmit(
			hCard,
			&pioSendPci,
			pbSendBuffer,
			sizeof(pbSendBuffer),
			NULL, pbRecvBuffer,
			&dwRecvLength
		);

		if (lResult != SCARD_S_SUCCESS) {
			std::cerr << "Failed to transmit APDU: " << lResult << std::endl;
		}
		else {
			//std::cout << "APDU transmitted successfully." << std::endl;
		}
	}


	std::shared_ptr<DecryptedEcm> DecryptEcm(const std::span<BYTE>& ecm)
	{
		auto keyString = GetKeyString(ecm);
		if (decryptedEcmCache.contains(keyString)) {
			return std::make_shared<DecryptedEcm>(decryptedEcmCache[keyString]);
		}

		auto kcl = GetA0AuthKcl();

		std::vector<BYTE> sendBuffer;
		sendBuffer.reserve(5 + ecm.size());
		sendBuffer.push_back(0x90); // CLA
		sendBuffer.push_back(0x34); // INS
		sendBuffer.push_back(0x00); // P1
		sendBuffer.push_back(0x01); // P2
		sendBuffer.push_back((BYTE)ecm.size()); // Lc
		sendBuffer.insert(sendBuffer.end(), ecm.begin(), ecm.end());
		sendBuffer.push_back(0x00);	// Le

		BYTE pbRecvBuffer[256];
		DWORD dwRecvLength = sizeof(pbRecvBuffer);

		SCARD_IO_REQUEST pioSendPci = { SCARD_PROTOCOL_T1, sizeof(SCARD_IO_REQUEST) };

		LONG lResult = SCardTransmit(
			hCard,
			&pioSendPci,
			sendBuffer.data(),
			(DWORD)sendBuffer.size(),
			NULL,
			pbRecvBuffer,
			&dwRecvLength
		);
		if (lResult != SCARD_S_SUCCESS) {
			std::cerr << "Failed to transmit APDU: " << lResult << std::endl;
		}
		else {
			//std::cout << "APDU transmitted successfully." << std::endl;
		}

		auto sw1 = pbRecvBuffer[dwRecvLength - 2];
		auto sw2 = pbRecvBuffer[dwRecvLength - 1];
		if (sw1 != 0x90 || sw2 != 0x00) {
			throw std::runtime_error("ECM request failed");
		}

		auto ecmResponse = std::span{ pbRecvBuffer }.subspan(0x06, dwRecvLength - 0x06 - 2); // SW1, SW2の分を除く
		auto ecmInit = std::span{ ecm }.subspan(0x04, 0x1b - 0x04);

		std::vector<BYTE> hashData;
		hashData.reserve(kcl.size() + ecmInit.size());
		hashData.insert(hashData.end(), kcl.begin(), kcl.end());
		hashData.insert(hashData.end(), ecmInit.begin(), ecmInit.end());
		auto hash = SHA256Hash(hashData);

		for (size_t i = 0; i < hash.size(); i++) {
			hash[i] ^= ecmResponse[i];
		}

		DecryptedEcm decryptedEcm(std::span{hash}.subspan(0, 0x10), std::span{hash}.subspan(0x10));
		decryptedEcmCache[keyString] = decryptedEcm;

		//std::cout << "ECM: Odd " << GetKeyString(decryptedEcm.Odd) << " Even " << GetKeyString(decryptedEcm.Even) << std::endl;

		return std::make_shared<DecryptedEcm>(decryptedEcm);
	}

	void SetMasterKey(const std::vector<BYTE>& key) {
		masterKey.assign(key.begin(), key.end());
	}

	~AcasCard()
	{
		if (hContext != 0) {
			SCardReleaseContext(hContext);
			hContext = 0;
		}
	}

private:
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;

	std::map<std::string, DecryptedEcm> decryptedEcmCache;

	std::vector<BYTE> masterKey;

	AcasCard(SCARDHANDLE hCard, SCARDCONTEXT hContext) : hCard(hCard), hContext(hContext) {}


	std::vector<BYTE> GetA0AuthKcl()
	{
		if (masterKey.empty()) {
			throw std::runtime_error("Master key not defined.");
		}

		std::vector<BYTE> a0init(8, 0);
		std::random_device rd;	// シード生成器
		std::mt19937 gen(rd());	 // メルセンヌ・ツイスタ生成器
		std::uniform_int_distribution<> dis(0, 255);	// 0から255までの範囲の一様分布

		for (auto& byte : a0init) {
			byte = dis(gen);
		}

		//SCRAMBLEKEY SET COMMAND
		std::vector<BYTE> data = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x8A, 0xF7 };
		data.insert(data.end(), a0init.begin(), a0init.end());

		std::vector<BYTE> sendBuffer;
		sendBuffer.push_back(0x90);	// CLA
		sendBuffer.push_back(0xA0);	// INS
		sendBuffer.push_back(0x00);	// P1
		sendBuffer.push_back(0x01);	// P2
		sendBuffer.push_back((BYTE)data.size());	//Lc
		sendBuffer.insert(sendBuffer.end(), data.begin(), data.end());
		sendBuffer.push_back(0x00);	//Le

		BYTE pbRecvBuffer[256];
		DWORD dwRecvLength = sizeof(pbRecvBuffer);

		SCARD_IO_REQUEST pioSendPci = { SCARD_PROTOCOL_T1, sizeof(SCARD_IO_REQUEST) };

		LONG lResult = SCardTransmit(
			hCard,
			&pioSendPci,
			sendBuffer.data(),
			(DWORD)sendBuffer.size(),
			NULL,
			pbRecvBuffer,
			&dwRecvLength
		);
		if (lResult != SCARD_S_SUCCESS) {
			std::cerr << "Failed to transmit APDU: " << lResult << std::endl;
		}
		else {
			//std::cout << "APDU transmitted successfully." << std::endl;
		}

		auto a0response = std::span{ pbRecvBuffer }.subspan(0x06, 0x0e-0x06);
		auto sw1 = pbRecvBuffer[dwRecvLength - 2];
		auto sw2 = pbRecvBuffer[dwRecvLength - 1];
		auto a0hash = std::span{ pbRecvBuffer }.subspan(0x0e, dwRecvLength - 0x0e - 2); // SW1, SW2の分を除く

		if (sw1 != 0x90 || sw2 != 0x00) {
			throw std::runtime_error("A0 auth failed");
		}

		std::vector<BYTE> kclData;
		kclData.insert(kclData.end(), masterKey.begin(), masterKey.end());
		kclData.insert(kclData.end(), a0init.begin(), a0init.end());
		kclData.insert(kclData.end(), a0response.begin(), a0response.end());

		auto kcl = SHA256Hash(kclData);

		std::vector<BYTE> hashData;
		hashData.insert(hashData.end(), kcl.begin(), kcl.end());
		hashData.insert(hashData.end(), a0init.begin(), a0init.end());

		auto hash = SHA256Hash(hashData);

		if (!std::equal(hash.begin(), hash.end(), a0hash.begin(), a0hash.end())) {
			throw std::invalid_argument("A0 hash did not match");
		}

		return kcl;

	}

	std::string GetKeyString(const std::span<BYTE>& ecm) {
		std::ostringstream oss;
		for (size_t i = 0; i < ecm.size(); ++i) {
			if (i != 0) { oss << "-"; }
			oss << std::format("{:02X}", ecm[i]);
		}
		return oss.str();
	}

	std::vector<BYTE> SHA256Hash(const std::vector<BYTE>& data) {
		std::vector<BYTE> hash(EVP_MD_size(EVP_sha256()));
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (ctx == nullptr) {
			throw std::runtime_error("Failed to create EVP_MD_CTX");
		}

		if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("EVP_DigestInit_ex failed");
		}

		if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("EVP_DigestUpdate failed");
		}

		unsigned int length = 0;
		if (EVP_DigestFinal_ex(ctx, hash.data(), &length) != 1) {
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("EVP_DigestFinal_ex failed");
		}

		EVP_MD_CTX_free(ctx);
		hash.resize(length);
		return hash;
	}

};

