#pragma once

#include <vector>
#include <deque>
#include <array>
#include <memory>
#include <algorithm>
#include <stdexcept>
#include <span>

#include <windows.h>

#include <openssl/evp.h>



const int AES_KEY_SIZE = 16;

enum IpCompressedPacketHeaderType : BYTE
{
	PartialIPv4Header = 0x20,
	IPv4Header = 0x21,
	PartialIPv6Header = 0x60,
	NoCompressedHeader = 0x61,
};

enum EncryptionFlag : BYTE
{
	Unscrambled = 0x00,
	Reserved = 0x01,
	Even = 0x02,
	Odd = 0x03,
};

enum TlvPacketType : BYTE
{
	Undefined = 0x00,
	IPv4 = 0x01,
	IPv6 = 0x02,
	HeaderCompressed = 0x03,
	TransmissionControlSignalPacket = 0xFE,
	NullPacket = 0xFF,
};

enum MmtpPayloadType : BYTE
{
	MPU = 0x00,
	GenericObject = 0x01,
	ControlMessage = 0x02,
	RepairSymbol = 0x03,
};

struct DecryptedEcm
{
	std::vector<BYTE> Odd;
	std::vector<BYTE> Even;

	DecryptedEcm() {}
	DecryptedEcm(const std::span<BYTE>& odd, const std::span<BYTE>& even) {
		Odd.insert(Odd.end(), odd.begin(), odd.end());
		Even.insert(Even.end(), even.begin(), even.end());
	}
};

class MmtpPacket {

public:
	MmtpPacket(const std::span<BYTE>& packet)
	{
		data.insert(data.end(), packet.begin(), packet.end());
	}

	EncryptionFlag GetEncryptionFlag()
	{
		if (!HasExtensionFlag()) {
			return Unscrambled;
		}

		// Multi extension header type, cf. ARIB STD-B61
		auto headerExtensionType = GetBigEndianShort(data, 0x10);
		if ((headerExtensionType & 0x7FFF) == 0x0001) {
			if (GetBigEndianShort(data, 0x12) != 1) {
				throw std::range_error("unknown length");
			}

			return (EncryptionFlag)((data[0x14] & 0b00011000) >> 3);
		}

		return Unscrambled;
	}

	MmtpPayloadType GetPayloadType()
	{
		return (MmtpPayloadType)(data[0x1] & 0b00111111);
	}

	std::vector<BYTE> GetDecryptedMmts(DecryptedEcm& decryptedEcm)
	{
		// Remove encryption flag and encryption subsystem flag;
		auto encryptionExtensions = (BYTE)(data[0x14] & 0b11100011);

		auto decryptedPayload = GetDecryptedMmtsPayload(decryptedEcm);
		std::vector<BYTE> decryptedMmts;
		decryptedMmts.insert(decryptedMmts.end(), data.begin(), data.begin() + 0x14);
		decryptedMmts.push_back(encryptionExtensions);
		decryptedMmts.insert(decryptedMmts.end(), data.begin() + 0x15, data.begin() + 0x18 + GetExtensionLength());
		decryptedMmts.insert(decryptedMmts.end(), decryptedPayload.begin(), decryptedPayload.end());

		return decryptedMmts;
	}


	template<class T>
	static uint16_t GetBigEndianShort(const T& data, size_t index)
	{
		if (index + 1 > data.size()) {
			throw std::out_of_range("Index out of range");
		}
		return (static_cast<short>(data[index]) << 8) | data[index + 1];
	}


private:
	std::vector<BYTE> data;


	std::array<BYTE,2> GetPacketId()
	{
		return { data[2], data[3] };
	}

	std::array<BYTE, 4> GetTimeStamp()
	{
		return {data[4], data[5], data[6], data[7]};
	}

	std::array<BYTE, 4> GetPacketSequenceNumber()
	{
		return { data[8], data[9], data[0xA], data[0xB] };
	}

	std::array<BYTE, 2> GetExtensionType()
	{
		size_t offset = HasPacketCounterFlag() ? 4 : 0;
		return { data[0x0C+offset], data[0x0D + offset] };
	}

	uint16_t GetExtensionLength()
	{
		size_t offset = HasPacketCounterFlag() ? 4 : 0;
		return GetBigEndianShort(data, 0xE + offset);
	}

	bool HasExtensionFlag()
	{
		return (data[0x0] & 0b00000010) > 0;
	}

	bool IsRapFlag()
	{
		return (data[0x0] & 0b00000001) > 0;
	}

	bool HasPacketCounterFlag()
	{
		return (data[0x0] & 0b00100000) > 0;
	}

	BYTE GetScramblingSubsystem()
	{
		size_t offset = HasPacketCounterFlag() ? 4 : 0;
		return (BYTE)(data[0x14+offset] & 0b00000100) >> 2;
	}

	BYTE GetMessageAuthenticationControl()
	{
		size_t offset = HasPacketCounterFlag() ? 4 : 0;
		return (BYTE)(data[0x14+offset] & 0b00000010) >> 1;
	}

	BYTE GetScramblingInitialCounterValue()
	{
		size_t offset = HasPacketCounterFlag() ? 4 : 0;
		return (BYTE)(data[0x14+offset] & 0b00000001);
	}

	std::vector<BYTE> GetPayload()
	{
		size_t offset = HasPacketCounterFlag() ? 4 : 0;
		if (HasExtensionFlag()) {
			std::vector<BYTE> result(data.begin() + 0xC + GetExtensionLength() + 4 + offset, data.end());
			return result;
		}
		else {
			std::vector<BYTE> result(data.begin() + 0xC + offset, data.end());
			return result;
		}
	}

	std::vector<BYTE> GetDecryptedMmtsPayload(const DecryptedEcm& decryptedEcm)
	{
		if (HasPacketCounterFlag()) {
			throw std::invalid_argument("Has packet counter flag");
		}

		auto ef = GetEncryptionFlag();
		auto key = decryptedEcm.Odd;
		if (ef == Odd) { key = decryptedEcm.Odd; }
		else if (ef == Even) { key = decryptedEcm.Even; }
		else {
			throw std::invalid_argument("Encryption flag reserved");
		}

		if (GetScramblingInitialCounterValue() > 0) {
			throw std::invalid_argument("SICV not implemented");
		}

		if (GetMessageAuthenticationControl() > 0) {
			throw std::invalid_argument("MAC not implemented");
		}

		std::array<BYTE, AES_KEY_SIZE> iv;
		iv.fill(0);
		auto packetId = GetPacketId();
		std::copy(packetId.begin(), packetId.end(), iv.begin());
		auto packetSeqNum = GetPacketSequenceNumber();
		std::copy(packetSeqNum.begin(), packetSeqNum.end(), iv.begin() + 2);

		auto decryptedPayload = GetDecryptedPayload(key);
		return decryptedPayload;
	}

	std::vector<BYTE> GetDecryptedPayload(const std::span<BYTE>& key)
	{
		auto payload = GetPayload();
		auto packetId = GetPacketId();
		auto packetSequenceNumber = GetPacketSequenceNumber();

		// IVの作成
		std::vector<BYTE> iv;
		iv.insert(iv.end(), packetId.begin(), packetId.end());
		iv.insert(iv.end(), packetSequenceNumber.begin(), packetSequenceNumber.end());
		iv.insert(iv.end(), { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }); // 残りの0x0を追加


		// OpenSSLのコンテキスト初期化
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) {
			throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
		}

		// 復号化の初期化
		if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), iv.data()) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("EVP_DecryptInit_ex failed");
		}

		// 復号化の実行
		std::vector<BYTE> decryptedPayload(payload.size() - 8); // 0x8以降のペイロード
		int len;
		if (EVP_DecryptUpdate(ctx, decryptedPayload.data(), &len, payload.data() + 8, (int)(payload.size() - 8)) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("EVP_DecryptUpdate failed");
		}

		int finalLen;
		if (EVP_DecryptFinal_ex(ctx, decryptedPayload.data() + len, &finalLen) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("EVP_DecryptFinal_ex failed");
		}

		decryptedPayload.resize(len + finalLen);
		EVP_CIPHER_CTX_free(ctx);

		return decryptedPayload;
	}

};




class TlvPacket
{
public:
	TlvPacket(const std::span<BYTE>& source) {
		data.insert(data.end(), source.begin(), source.end());
	}

	std::vector<BYTE> GetEcm() {

		auto index = std::search(data.begin(), data.end(), ecmHeader.begin(), ecmHeader.end());
		if (index == data.end()) { return std::vector<BYTE>(); }

		std::vector<BYTE> result(index + 2, index + 150);
		return result;
	}

	std::vector<BYTE> GetDecryptedTlv(std::shared_ptr<DecryptedEcm> pDecryptedEcm){
		std::vector<BYTE> result;
		if (GetTlvPacketType() != HeaderCompressed) {
			return result;
		}

		auto pMmtpPacket = GetMmtpPacket();

		if (pMmtpPacket->GetEncryptionFlag() == Unscrambled) {
			return data;
		}

		if(pDecryptedEcm.get() == nullptr){
			return result;
		}

		if (pMmtpPacket->GetPayloadType() != MPU) {
			throw std::invalid_argument("Non MPU packet found");
		}

		auto tlvAndMmtpHeader = GetTlvAndMmtpHeader();
		auto decryptedMmtsPacket = pMmtpPacket->GetDecryptedMmts(*pDecryptedEcm);
		result.insert(result.end(), tlvAndMmtpHeader.begin(), tlvAndMmtpHeader.end());
		result.insert(result.end(), decryptedMmtsPacket.begin(), decryptedMmtsPacket.end());

		return result;
	}

private:
	std::vector<BYTE> data;

	const std::vector<BYTE> ecmHeader = { 0x00, 0x00, 0x93, 0x2D, 0x1E, 0x01 };

	TlvPacketType GetTlvPacketType() {
		return (TlvPacketType)data[1];
	}

	IpCompressedPacketHeaderType GetMmtpHeaderType() {
		return (IpCompressedPacketHeaderType)data[6];
	}

	std::shared_ptr<MmtpPacket> GetMmtpPacket()
	{
		auto mmtpHeaderType = GetMmtpHeaderType();
		if (mmtpHeaderType == NoCompressedHeader) {
			MmtpPacket mmtp(std::span{ data }.subspan(0x7));
			return std::make_shared<MmtpPacket>(mmtp);
		}

		if (mmtpHeaderType == PartialIPv6Header) {
			MmtpPacket mmtp(std::span{ data }.subspan(0x31));
			return std::make_shared<MmtpPacket>(mmtp);
		}

		throw std::invalid_argument("Unknown Mmtp Header type");
	}

	std::vector<BYTE> GetTlvAndMmtpHeader()
	{
		auto mmtpHeaderType = GetMmtpHeaderType();
		if (mmtpHeaderType == (BYTE)NoCompressedHeader) {
			std::vector<BYTE> result(data.begin(), data.begin() + 0x7);
			return result;
		}
		if (mmtpHeaderType == (BYTE)PartialIPv6Header) {
			std::vector<BYTE> result(data.begin(), data.begin() + 0x31);
			return result;
		}
		throw std::invalid_argument("Unknown Mmtp Header type");
	}

};
