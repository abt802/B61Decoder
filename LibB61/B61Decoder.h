#pragma once
#include <deque>
#include <vector>
#include <windows.h>

#include "IB25Decoder.h"

#include "TlvHelpers.h"
#include "TlvPacket.h"
#include "AcasCard.h"

class B61Decoder : public IB25Decoder2
{
public:
	//IB25Decoder interface
	virtual const BOOL Initialize(DWORD dwRound = 4);
	virtual void Release(void);

	virtual const BOOL Decode(BYTE* pSrcBuf, const DWORD dwSrcSize, BYTE** ppDstBuf, DWORD* pdwDstSize);
	virtual const BOOL Flush(BYTE** ppDstBuf, DWORD* pdwDstSize);
	virtual const BOOL Reset(void);

	//IB25Decoder2 interface

	virtual void DiscardNullPacket(const bool bEnable = true) {};
	virtual void DiscardScramblePacket(const bool bEnable = true) {};
	virtual void EnableEmmProcess(const bool bEnable = true) {};
	virtual void SetMulti2Round(const int32_t round = 4) {}
	virtual void SetSimdMode(const int32_t instruction = 3) {}

	virtual const DWORD GetDescramblingState(const WORD wProgramID) { return 0; }

	virtual void ResetStatistics(void) {}

	virtual const DWORD GetPacketStride(void) { return 0; }
	virtual const DWORD GetInputPacketNum(const WORD wPID = TS_INVALID_PID) { return 0; }
	virtual const DWORD GetOutputPacketNum(const WORD wPID = TS_INVALID_PID) { return 0; };
	virtual const DWORD GetSyncErrNum(void) { return 0; }
	virtual const DWORD GetFormatErrNum(void) { return 0; }
	virtual const DWORD GetTransportErrNum(void) { return 0; }
	virtual const DWORD GetContinuityErrNum(const WORD wPID = TS_INVALID_PID) { return 0; }
	virtual const DWORD GetScramblePacketNum(const WORD wPID = TS_INVALID_PID) { return 0; }
	virtual const DWORD GetEcmProcessNum(void) { return 0; }
	virtual const DWORD GetEmmProcessNum(void) { return 0; };

	//for class 

	B61Decoder(void);
	virtual ~B61Decoder(void);
	static B61Decoder* m_pThis;
private:

	const int BLOCK_SIZE = 1024 * 1024 * 10;
	std::shared_ptr<AcasCard> acas;
	std::shared_ptr<DecryptedEcm> decryptedEcm;

	std::deque<BYTE> buffer;
	std::vector<BYTE> newData;
	std::vector<BYTE> decBuffer;

	size_t readSize = 0;
	size_t writeSize = 0;

	int step = 0;

	static std::string GetMasterKeyString();
	static std::vector<BYTE> HexStringToBytes(const std::string& hexStr);

};

