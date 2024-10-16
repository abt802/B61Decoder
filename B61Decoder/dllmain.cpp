// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"

#include "IB25Decoder.h"
#include "B61Decoder.h"

//Dllインスタンス参照用
HMODULE dllModule = nullptr;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    dllModule = hModule;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        if (B61Decoder::m_pThis != nullptr) {
            B61Decoder::m_pThis->Release();
        }
        break;
    }
    return TRUE;
}

extern "C"
{
    __declspec(dllexport) IB25Decoder* CreateB25Decoder()
    {
        // インスタンス生成
        return dynamic_cast<IB25Decoder*>(new B61Decoder());
    }

    __declspec(dllexport) IB25Decoder2* CreateB25Decoder2()
    {
        // インスタンス生成
        return dynamic_cast<IB25Decoder2*>(new B61Decoder());
        return nullptr;
    }
}

// 静的メンバ初期化
B61Decoder* B61Decoder::m_pThis = nullptr;
