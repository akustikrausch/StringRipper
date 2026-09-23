#pragma once

// Some MinGW-w64 releases forward-declare this WASAPI interface without its
// definition. The FXChainPlayer backend uses GetPeakValue and __uuidof.
#ifdef __MINGW32__
#include <endpointvolume.h>

#ifndef __IAudioMeterInformation_INTERFACE_DEFINED__
#define __IAudioMeterInformation_INTERFACE_DEFINED__
MIDL_INTERFACE("C02216F6-8C67-4B5B-9D00-D008E73E0064")
IAudioMeterInformation : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE GetPeakValue(float* peak) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetMeteringChannelCount(UINT* count) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetChannelsPeakValues(UINT32 count, float* peaks) = 0;
    virtual HRESULT STDMETHODCALLTYPE QueryHardwareSupport(DWORD* mask) = 0;
};
#ifdef __CRT_UUID_DECL
__CRT_UUID_DECL(IAudioMeterInformation, 0xc02216f6, 0x8c67, 0x4b5b,
                0x9d, 0x00, 0xd0, 0x08, 0xe7, 0x3e, 0x00, 0x64)
#endif
#endif
#endif
