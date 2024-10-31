#pragma once
#include <vector>
#include <deque>
#include <optional>
#include <algorithm>

#include <Windows.h>

#include "TlvPacket.h"

class TlvHelpers
{
public:
	static std::optional<size_t> TryFindTlvHeaderIndex(const std::deque<BYTE>& bytes)
	{
		const std::vector<BYTE> pattern = { TLV_HEADER, (BYTE)HeaderCompressed };
		auto itr = std::search(bytes.begin(), bytes.end(), pattern.begin(), pattern.end());
		if (itr != bytes.end()) {
			return std::distance(bytes.begin(), itr);
		}
		return std::nullopt;
	}

	static bool IsValidTlvHeader(const std::deque<BYTE>& bytes)
	{
		if (bytes.size() < 2) {
			throw std::out_of_range("Too short for TlvHeader");
		}
		auto tlvPType = (TlvPacketType)bytes[1];

		return bytes[0] == TLV_HEADER
			&& (tlvPType == Undefined
				|| tlvPType == HeaderCompressed
				|| tlvPType == IPv4
				|| tlvPType == IPv6
				|| tlvPType == NullPacket
				|| tlvPType == TransmissionControlSignalPacket);
	}

private:

	static const BYTE TLV_HEADER = 0x7f;
};

