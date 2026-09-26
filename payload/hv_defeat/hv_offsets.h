#pragma once

#include <cstdint>

struct HvFwOffsets {
    uint32_t dmpml4i;
    uint32_t dmpdpi;
    uint32_t pml4pml4i;
    uint32_t pmap_store;
    uint32_t pmap_pm_pml4;
    uint32_t text_size;
    uint32_t hv_vcpu;
    uint32_t hv_vcpu_cpuid;
    uint64_t vmcb_core0;
    uint32_t iommu_softc;
};

// FW 1.00-1.14 (iommu_softc: 1.05-1.14; 1.00-1.02 use 0x041ED638)
inline constexpr HvFwOffsets kOffsets_1xx = {
    0x04ADF540, 0x04ADF544, 0x04ADF29C, 0x04ADF2B8, 0x020,
    0x00B30000, 0x1398, 0x128, 0,
    0x041ED648
};

// FW 2.00-2.70
inline constexpr HvFwOffsets kOffsets_2xx = {
    0x04CB3B50, 0x04CB3B54, 0x04CB38AC, 0x04CB38C8, 0x020,
    0x00B70000, 0x1398, 0x128, 0,
    0x0425D718
};

// FW 3.00-3.21: separate HV, VMCB at hardcoded PA
inline constexpr HvFwOffsets kOffsets_3xx = {
    0x03D8E4A0, 0x03D8E4A4, 0x03D8E1FC, 0x03D8E218, 0x020,
    0x00BD0000, 0, 0, 0x6290B000,
    0x033175E0
};

// FW 4.00-4.51
inline constexpr HvFwOffsets kOffsets_4xx = {
    0x03E57D00, 0x03E57D04, 0x03E57A5C, 0x03E57A78, 0x020,
    0x00C00000, 0, 0, 0x62A05000,
    0x033C7680
};

inline const HvFwOffsets* hv_offsets_for(uint32_t fw) {
    uint8_t major = (fw >> 24) & 0xFF;
    switch (major) {
    case 1: return &kOffsets_1xx;
    case 2: return &kOffsets_2xx;
    case 3: return &kOffsets_3xx;
    case 4: return &kOffsets_4xx;
    default: return nullptr;
    }
}
