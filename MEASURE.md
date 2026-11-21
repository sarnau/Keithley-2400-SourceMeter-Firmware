# Keithley 2400 — Source / Measure Subsystem (Reverse-Engineering Notes)

How the digital board drives the analog board: programming the source DACs, the block-transfer
communication engine, and the A/D measurement path. Addresses are Ghidra addresses = file offsets
in `2400-FIRMWARE.bin` (flat image, MC68332 / CPU32, big-endian). See [DATASHEETS.md](DATASHEETS.md)
(MC68332 QSM/TPU, AD7849 references), [SUMMARY.md](SUMMARY.md) (Service Manual theory of operation,
SDM cycle), and [SCPI.md](SCPI.md) for how `:SOURce`/`:MEASure`/`:READ` commands reach this code.

> **Scope honesty:** the **source / DAC write path, the analog communication engine, and the A/D
> reading computation** (SIG/REF/ZERO counts → averaged → calibrated float) are traced. What remains
> open is the **raw-count receive** from the analog board across the opto-isolators and the detailed
> SDM/trigger sequencing — noted inline in §3.4.

---

## 1. Architecture

The analog board is **galvanically isolated** from the digital board (opto-isolators). The MC68332
reaches it over two on-chip serial channels:

- **QSM QSPI** (synchronous SPI, queue RAM at `0xFFFD00`–`0xFFFD4F`) — the primary channel; clocks
  serial frames to the **AD7849BR 16-bit V/I DACs** and analog control latches across the barrier.
- **TPU channel 13** — an alternate transmit path for one block type.

The A/D is a **multi-slope charge-balance converter** controlled by gate array **U610** on the
analog board; the MPU issues a convert command and reads back phase counts.

`main()` (`0x4492`) initializes this: `CPU_HW_CONFIG_SPCR` (QSPI) and `CPU_TPU_CH13_INITIALIZE`.

```
SCPI :SOUR... / :MEAS? / :READ?  (SCPI.md)
        │
        ▼
per-target primitive (0x10Cxx)  ── busy-wait gTRANSMIT_BLOCK_DONE_FLAG
        │   build serial frame + shadow global
        ▼
COMM_TRANSMIT ─► COMM_TRANSMIT_BLOCK ─┬─ QSPI burst (SPCR/queue RAM)  ─► analog board DAC/latch
        ▲                             └─ TPU CH13 (block type 3)
        │   QSPI-complete IRQ
        └── COMM_CALLBACK_NEXT  (chain next block, or finish + done-callback)
```

---

## 2. Source / DAC write path

### 2.1 Per-target primitives (`0x10Cxx`)

One small function per analog target. Known:

| Target | Primitive | Frame builder | Shadow global |
|---|---|---|---|
| V DAC | `0x10CA6` | `FUN_00009C6E` | `gDIAGNOSTIC_KEITHLEY_BITS_VDAC` |
| I DAC | `0x10C7E` | (sibling of 9C6E) | … |
| MUX | `0x10C06` | … | … |

(also RNG / AFB / SIG / REF / ZERO targets nearby). Each primitive:

```c
do { } while (gTRANSMIT_BLOCK_DONE_FLAG != 0);   // wait for previous analog transfer
comm = build_frame(value);                       // pack frame, store shadow
COMM_TRANSMIT(comm, ...);
```

### 2.2 Frame builder (e.g. `FUN_00009C6E`, V DAC)

Packs the 16-bit value into the transmit buffer `gANALOG_CMD_FRAME` (`0x801390`):

```c
gANALOG_CMD_FRAME[0] = value >> 8;               // high byte
gANALOG_CMD_FRAME[1] = (value << 3) | 4;         // low byte + AD7849 serial framing/control bits (tag 4 = VDAC)
gDIAGNOSTIC_KEITHLEY_BITS_VDAC = value;          // shadow copy
return &COMM_TRANSMIT_STRUCT_00058bce;           // static descriptor (chained via .next)
```

**`gANALOG_CMD_FRAME` (`0x801390`, `word[41]`, spans `0x801390…0x8013e1`)** is not a fixed register
map — it is a **variable-length serial command buffer**. Each word is `(payload << 3) | tag` with the
low 3 bits selecting the destination (`0=INT 1=AFB 2=MUX 3=SYS 4=VDAC 5=IDAC 6=RNG 7=CCS`); payloads
wider than one word split into `hi=payload>>8` + `lo=(payload<<3)|tag`; a MUX payload `| 0x80` sets the
mux strobe bit. Every `ANALOG_BUILD_BLOCK_*` / `ANALOG_BUILD_FRAME_*` routine packs a *different*
ordered command list for its operation, so a given index holds different registers in different
builders (e.g. `[0]` is MUX in `ANALOG_BUILD_BLOCK_REFRESH_ALL` but SYS in
`ANALOG_BUILD_BLOCK_OUTPUT_ON_VSOURCE`). `REFRESH_ALL` packs the full register set from the
`gDIAGNOSTIC_KEITHLEY_BITS_*` shadows: `[0]`MUX `[2/3]`INT `[5]`SYS `[7]`AFB `[9/10]`RNG `[12/13]`IDAC
`[16/17]`VDAC `[19]`CCS. The longest sequences come from the `SRCI_COMPL_OUTPUTON` chain builders.

DAC values are 16-bit (`0..65535`, validated against `65535.0`); MUX / range values are 8-bit
(`0..255`, validated against `255.0`).

### 2.3 Transmit descriptor — `COMM_TRANSMIT_STRUCT`

A static descriptor per analog operation, carrying the QSPI configuration and a `next` pointer for
chaining. Fields used by `COMM_TRANSMIT_BLOCK`: `transmitPtr` (→ data buffer, e.g. `0x801390`),
`cmdPtr` (→ per-transfer QSPI command bytes = chip-select/control), `spcr0` (bits-per-transfer +
baud), `spcr1` (delays), `spcr2` (ending queue pointer = number of transfers), `pqspar` (pin
assignment), `next` (chained descriptor), `field5_0x7` (channel type: 3 = TPU, else QSPI). The V-DAC
descriptor at `0x58BCE` chains to `0x58BC8`, so a V-DAC update is a multi-block sequence.

### 2.3b `ANALOG_BUILD_FRAME_DISPATCH` — functionID → frame-builder table

`COMM_CALL_FUNCTION_ID(functionID, param2)` (`0x1415C`) selects which analog-board frame to build by
indexing **`ANALOG_BUILD_FRAME_DISPATCH`** (`0x58EAC`, `COMM_FUNC_FN *[35]`, was `PTR_ARRAY_00058EAC`)
with `functionID` (0x00–0x22) and calling it `(word functionID, byte param2) → COMM_TRANSMIT_STRUCT*`.
All 35 targets are named source-programming routines; the `_2` variants are the second/alternate form
(pulse vs DC, or model-specific):

| id | builder | id | builder |
|----|---------|----|---------|
| 0x00 | `…FRAME_INVALID_MODE_ERROR` | 0x12 | `…FRAME_SRCI_COMPL_CHAIN` |
| 0x01 | `…FRAME_SRCV_SIMPLE` | 0x13 | `…FRAME_SRCI_COMPL` |
| 0x02 | `…FRAME_SRCI_CHAIN` | 0x14 | `…FRAME_SRCI_COMPL_OUTPUTON_CHAIN` |
| 0x03 | `…FRAME_SRCV_GUARD_MODELSEL` | 0x15 | `…FRAME_SRCI_COMPL_OUTPUTON` |
| 0x04 | `…FRAME_SRCV_OUTPUTON` | 0x16 | `…FRAME_SRCV_PROT_2` |
| 0x05 | `…FRAME_SRCI_SIMPLE` | 0x17 | `…FRAME_SRCV_RANGED_GUARD_2` |
| 0x06 | `…FRAME_SRCI_RANGED_CHAIN` | 0x18 | `…FRAME_SRCV_RANGED_2` |
| 0x07 | `…FRAME_SRCI_RANGED_CHAIN_2` | 0x19 | `…FRAME_SRCI_COMPL_CHAIN_2` |
| 0x08 | `…FRAME_SRCV_SIMPLE_2` | 0x1A | `…FRAME_SRCI_COMPL_2` |
| 0x09 | `…FRAME_SRCI_CHAIN_2` | 0x1B | `…FRAME_SRCI_COMPL_OUTPUTON_CHAIN_2` |
| 0x0A | `…FRAME_SRCI_SIMPLE_2` | 0x1C | `…FRAME_SRCI_COMPL_OUTPUTON_2` |
| 0x0B | `…FRAME_SRCI_RANGED` | 0x1D | `…FRAME_SRCV_DAC_ONLY` |
| 0x0C | `…FRAME_SRCI_RANGED_2` | 0x1E | `…BLOCK_IDAC_FROM_CURRENT` |
| 0x0D | `…FRAME_SRCV_GUARD_MODELSEL_2` | 0x1F | `…BLOCK_IDAC_FROM_RANGE` |
| 0x0E | `…FRAME_SRCV_OUTPUTON_2` | 0x20 | `…BLOCK_VDAC_FROM_RANGE` |
| 0x0F | `…FRAME_SRCV_PROT` | 0x21 | `…BLOCK_RANGE_CHANGE_VSOURCE` |
| 0x10 | `…FRAME_SRCV_RANGED_GUARD` | 0x22 | `…BLOCK_RANGE_CHANGE` |
| 0x11 | `…FRAME_SRCV_RANGED` | | |

(All prefixed `ANALOG_BUILD_`. `COMM_CALL_FUNCTION_ID` also runs a fan-speed hook afterward — see §4b.)

### 2.4 `COMM_TRANSMIT` / `COMM_TRANSMIT_BLOCK`

```c
COMM_TRANSMIT(desc, flag):
    gCOMM_CALLBACK_DONE = <done callback>;
    gTRANSMIT_BLOCK_DONE_FLAG = 1;               // mark busy
    COMM_TRANSMIT_BLOCK(desc);

COMM_TRANSMIT_BLOCK(desc):
    if desc.field5_0x7 == 3:                      // --- TPU channel 13 path ---
        gCOMM_NEXT_BLOCK = desc.next; gCOMM_CALLBACK = COMM_CALLBACK_NEXT;
        CPU_TPU_CH13_00006010( frame_word );
    else:                                         // --- QSPI path (default) ---
        copy desc.cmdPtr      -> COMMAND_RAM   (QSM 0xFFFD40, command queue)
        copy desc.transmitPtr -> TRANSMIT_RAM  (QSM 0xFFFD20, transmit queue)
        PQSPAR = desc.pqspar;
        SPCR0 = (SPCR0 & 0xC300) | desc.spcr0_bits | desc.spcr0_baud;
        SPCR1 = (SPCR1 & 0x8000) | desc.spcr1;          // delays
        SPCR2 = (SPCR2 & 0xF0F0) | (desc.spcr2_endptr*0x100 - 0x100);  // queue length
        gCOMM_NEXT_BLOCK = desc.next; gCOMM_CURRENT_BLOCK = desc;
        SPSR &= 0x1F;
        SPCR1 |= 0x8000;                          // SPE: start the QSPI burst
```

### 2.5 Completion / chaining — `COMM_CALLBACK_NEXT`

Invoked from the QSPI-complete interrupt (`gCOMM_CALLBACK`):

```c
if (gCOMM_NEXT_BLOCK != NULL)
    COMM_TRANSMIT_BLOCK(gCOMM_NEXT_BLOCK);       // send next chained block
else {
    PQSPAR = 0x3B;
    gTRANSMIT_BLOCK_DONE_FLAG = 0;               // clear busy → unblocks the primitive's wait
    (*gCOMM_CALLBACK_DONE)();
}
```

So a multi-frame analog update (DAC + control latches + range) runs as **one queued,
interrupt-driven chain**; the calling primitive simply busy-waits on `gTRANSMIT_BLOCK_DONE_FLAG`.

---

## 3. Measure / A/D path

The A/D (gate array **U610**) is a **multi-slope charge-balance** converter. Each conversion yields
four 32-bit **phase counts**, stored as consecutive longs:

| Count | Address | `:DIAGnostic:KEIThley:CNT` cmdId |
|---|---|---|
| SIG1 | `0x8018B0` | `0x168` |
| SIG2 | `0x8018B4` | `0x169` |
| REF | `0x8018B8` | `0x16A` |
| ZERO | `0x8018BC` | `0x16B` |

(raw A/D register read = `:DIAGnostic:KEIThley:BITS:DATA`, cmdId `0x15F`, handler `0x26B70`.)

### 3.1 Digital averaging filter (FILTER feature)

Before the reading math, each count passes through a digital averaging filter (`FUN_00010D76`
for SIG2; a sibling at `0x10Exx` for SIG1, etc.). It accumulates each new count into a ring
`LONG_ARRAY_008042A4[]` (index `WORD_008045C6`); when the filter count `SHORT_008045C4` is reached
it averages them (sum / count, in double precision) and writes the result back to the count global.
This implements the moving / repeat average exposed via `[:SENSe]:AVERage`.

### 3.2 Reading computation — `FUN_0000C774` (`0xC774`)

The core multi-slope conversion (one of a family of per-range siblings in the mostly-undocumented
`0x00B000–0x00E134` / `0x10xxx` math region):

```c
ratio   = (SIG2 - ZERO) / (REF - ZERO);     // 0x801924 = SIG2-ZERO, 0x80192C = REF-ZERO, ratio @0x801920
gain    = (SIG2 - ZERO > 0) ? gVSENSE_GAIN_B   // cal row[1] (fit via −FS point)
                            : gVSENSE_GAIN_A;  // cal row[0] (fit via +FS point)
reading = ratio * gain + gVSENSE_OFFSET;     // + offset (cal row[2])
// NB: gains are negative, so the ratio>0 branch picks GAIN_B — "positive" is raw-count
//     polarity, not input polarity — see CALIBRATION.md §1.2 / §3.1
// overrange: |reading| vs FLOAT_00801908  -> set overflow status
```

- Result lands in the reading struct **`gREADING_ACCUM`** (`0x80847C`, `READING_RECORD`, 30 bytes):
  `.flReading` (`+4`, float) = the measured value; `.dwStatusFlags` (`+0x1A`, ulong) = status flags
  (overflow = `0x20000001`); `.systemTimeStamp` (`+0x16`, ulong); `.bCurrentRangeIndex` (`+0xC`,
  low nibble) and `.bVoltageRangeIndex` (`+0xD`, high nibble) select the active range — set by
  `ANALOG_LOAD_CURRENT_CAL` / `ANALOG_LOAD_VOLTAGE_CAL` to index `gFLOAT_ARRAY_CURR`/`_VOLT` and the
  matching `gCALIBRATION_DATA` cal rows. The remaining offsets (`+0`/`+0xE` floats, `+8`/`+0x12`
  ulongs, touched by the resistance-compute and init paths) are not yet pinned to a proven role.
- The active-range **sense calibration constants** are staged in a fixed scratch block, reloaded on
  every range change from `gCALIBRATION_DATA`: **voltage** `gVSENSE_GAIN_A` (`0x8018E4`) /
  `gVSENSE_GAIN_B` (`0x8018E8`) / `gVSENSE_OFFSET` (`0x8018EC`) via `ANALOG_LOAD_VOLTAGE_CAL`;
  **current** `gISENSE_GAIN_A` (`0x8018F4`) / `gISENSE_GAIN_B` (`0x8018F8`) / `gISENSE_OFFSET`
  (`0x8018FC`) via `ANALOG_LOAD_CURRENT_CAL`. `GAIN_A`/`GAIN_B` are the +/− polarity gains (cal rows
  `[0]`/`[1]`); the source data is the I²C-EEPROM cal set (the 88 floats decoded by
  [parse_flash.py](parse_flash.py)).
- The A/D phase sequencing (integrate SIG1/SIG2, REF, ZERO) is driven by the state machine var
  **`gADC_PHASE_STATE`** (`0x8018CE`); autoranging by **`gAUTORANGE_STATE`** (`0x8018C9`); the
  measure function/range selection by `gMEASURE_FUNC_SEL` / `gMEASURE_RANGE_SEL` /
  `gIMEAS_ENABLED` / `gVMEAS_ENABLED` (set in `MEASURE_SETUP_RANGE_AND_DISPATCH`).
- **NPLC auto-zero caching**: when `gCONFIG_0x19E.SYSTEM_AZERO_CACHING_STATE` is set, REF and ZERO
  are cached into `LONG_ARRAY_00805458[]` / `LONG_ARRAY_00805480[]` (index `0x805442`) so repeated
  same-NPLC measurements can skip re-acquiring the reference/zero phases.

### 3.3 Software floating point — Pascal runtime

The CPU32 has no FPU; all of the above uses a **`PASCAL_*` soft-float library**
(`PASCAL_LONG_TO_FLOAT`, `PASCAL_FLOAT_DIV` / `MULT` / `ADD`, `PASCAL_FLOAT_2_DOUBLE`,
`PASCAL_COMPARE_DOUBLES`, `PASCAL_DOUBLE_ADD`, `..._2_LONG`, …). The naming indicates the firmware
was built with a **Pascal compiler** + its runtime.

### 3.4 Scheduling

Acquisition is **asynchronous** — not a synchronous call inside the query handler. It runs through
the **SDM (Source-Delay-Measure) cycle** and the two-layer trigger model (see [SUMMARY.md](SUMMARY.md)
§6/§11), driven by the periodic-timer IRQ and the analog-comm callbacks. Auto-zero adds the
reference/zero phases; `A/D conversion time = NPLC × (1/line-freq) + 185 µs`. `:MEASure?` (query

The **DELAY/settle** phase of the SDM cycle is handled by `SOURCE_SETTLE_AND_SOAK` (`0xF656`): when
the source range changes, `SOURCE_APPLY_RANGE_CHANGE` loads the range-dependent settling time
`gSOURCE_SETTLE_TIME` (`0x801936`) from a ROM table (`0x5B1AC`); the soak then captures
`gSOURCE_SOAK_START_MS` (`0x80193C`) = `gSYSTEM_TIME_in_ms` and waits until
`gSOURCE_SOAK_END_MS` (`0x801940`) = start + `:SOURce:SOAK` (`SOURCE1_SOAK`), latching
`gSOURCE_SETTLED` (`0x80193A`) when done. (The programmable `:SOURce:DELay` and the auto-1 ms are
added on top — see SUMMARY.md §299.)

handler `0x266F4`) first tests an availability flag (`0x8046DE`); on "not ready" it returns error
index `0x8C`. `:READ?` = `:INITiate` + `:FETCh?`; `:READ` as a *write* jumps to the SET error stub
`0x20EEA` (query-only — see [SCPI.md](SCPI.md) §8).

> **Still open:** the raw-count *receive* from U610 across the opto-isolators. REF/ZERO are written
> via an address-register pointer inside the acquisition routine (`0x10xxx`); there are no
> QSPI-receive references, so the likely channel is the `0x0A0000` input latch (README's "one word
> of unknown data", referenced from analog descriptor tables) or a TPU input channel.

---

## 4. Key addresses

| Symbol | Address | Notes |
|---|---|---|
| `main` QSPI init | `CPU_HW_CONFIG_SPCR` | called from `main` (0x4492) |
| V-DAC primitive | `0x10CA6` | set V DAC |
| I-DAC primitive | `0x10C7E` | set I DAC |
| MUX primitive | `0x10C06` | set input mux |
| V-DAC frame builder | `0x9C6E` | packs `0x801390`, returns descriptor |
| transmit frame buffer | `gANALOG_CMD_FRAME` (`0x801390`, `word[41]`) | variable-length serial command buffer (§2.2) |
| V-DAC descriptor | `0x58BCE` | chains → `0x58BC8` |
| `COMM_TRANSMIT` | (named) | set busy flag + callback |
| `COMM_TRANSMIT_BLOCK` | (named) | QSPI / TPU-CH13 physical send |
| `COMM_CALLBACK_NEXT` | (named) | chain next block / finish |
| `gTRANSMIT_BLOCK_DONE_FLAG` | (RAM) | analog-transfer busy flag |
| `gCOMM_NEXT_BLOCK` / `gCOMM_CURRENT_BLOCK` | (RAM) | block chain |
| `gCOMM_CALLBACK` / `gCOMM_CALLBACK_DONE` | (RAM) | completion callbacks |
| QSM QSPI queue RAM | `0xFFFD00`–`0xFFFD4F` | RECEIVE/TRANSMIT/COMMAND RAM |
| QSM SPCR0/1/2, SPSR | `0xFFFC18`–`0xFFFC1F` | QSPI control/status |
| arg validator | `0x292AA` | bound-checks the numeric parameter |
| `:MEASure?` query handler | `0x266F4` | checks avail flag `0x8046DE` |
| A/D phase-count cmds | cmdId `0x168`–`0x16B` | `:DIAG:KEIT:CNT:SIG1/SIG2/REF/ZERO` |
| DAC/MUX diag cmds | cmdId `0x158`–`0x167` | `:DIAG:KEIT:BITS:*` / `:SET:*` |

---

## 4b. Runtime function-pointer slots (code-ptr cast sweep)

A decompiler-wide sweep ([SweepCodePtrCalls.py](SweepCodePtrCalls.py)) walks every function
containing a computed `CALL` and flags any decompiled line still showing a `(code *…)` cast — i.e.
an indirect call through a pointer that is **not** yet typed as a function pointer. The firmware
dispatches most of its state machines through **swappable RAM function-pointer variables** (the
`0x80xxxx` region), each written with a code address at runtime and later called indirectly.

These were all typed to kill the residual casts. The call sites prove the signatures (args/return
captured at the call), so only the proven prototype is applied:

| Function-def type | Prototype | Applied to |
|---|---|---|
| `VOIDFN`          | `void (void)`                      | 17 single RAM slots (see list below) |
| `EXECCMD_FN`      | `int (void)`                       | `FUNCPTR_EXECUTE_COMMAND` `0x8086D8` (executor pump; `ret != 0` loop) |
| `RESPONSE_FN`     | `void (undefined4)`                | `FUNCPTR_801814` `0x801814` (reading-element emitter; see note below) |
| `TEST_FN`         | `byte (void)`                      | `TEST_STRUCT.function` (+0x10); result → `gTEST_CURRENT_RETURNED_ERR` (byte) |
| `DISP_TESTPAT_FN` | `char (void)`                      | `DISPLAY_TEST_PATTERN_FUNCTABLE` `0x63922` — `*[5]` (returns char, 0x4B='K' = stop) |
| `COMM_FUNC_FN`    | `COMM_TRANSMIT_STRUCT* (word,byte)`| `ANALOG_BUILD_FRAME_DISPATCH` `0x58EAC` — `*[35]` analog frame-builder table (`COMM_CALL_FUNCTION_ID`; see §2.3b) |

**`VOIDFN *` slots** (all `void(void)` callbacks; names already carry the role):

- **Measure state machine** (set in `MEASURE_SETUP_RANGE_AND_DISPATCH`, run by
  `MEASURE_STATE_MACHINE_DISPATCH`): `0x8057EC`, `0x801380`, `0x805438`, `0x805218`, `0x808730`.
- **Source / trigger sequence steps**: `0x8045C8`, `0x8086FC` (`FUNCPTR_COMM_BUILD_RESULTSTR`),
  `0x803820`, `0x805240`, `gCOMM_CALLBACK` `0x805430`, `gCOMM_CALLBACK_DONE` `0x807E6C`,
  `0x803868`, `0x80489C`.
- **Trigger input / trace / calc2**: `0x805AA4`, `0x805804` (trace buffer), `0x807E94` (CALC2 stat).
- **GPIB level-3 ISR**: `gGPIB_EXCEPTION_LEVEL_3_CALLBACK` `0x801378` (see [GPIB.md](GPIB.md)).

**`RESPONSE_FN *` `0x801814` — return type is `void` (verified).** This slot is the per-reading
**data-element emitter**, selected by `:FORMat:DATA` / `:FORMat:BORDer` in `RESPONSE_0003a76a`:
ASCII → `RESPONSE_0003a6a4` (formats the float to a signed, comma-separated string); REAL →
`RESPONSE_0003a710` (MSB-first) or `RESPONSE_0003a73a` (LSB-first), each copying the 4-byte value
into `gRESPONSE_BUFFER`. All three targets return void, and every call site
(`RESPONSE_0003a4ee` / `_0003a5a8` / `_0003a626`, one per element bit of `FORMAT_ELEMENTS_*`)
discards the result. The decompiler previously showed a spurious `uVar1 = (*FUNCPTR_801814)()`
capture plus `return uVar1` in those callers — a D0 register-reuse artifact (D0 still held the last
format-element mask), not a real return. The three callers were retyped `uint(void)` → `void(void)`
to remove it; the `undefined4` argument is the raw 4-byte reading value (interpreted as `float` only
on the ASCII path).

**`(code *)` casts that are compiler switch jump-tables** (not function-pointer data):

- A recurring Pascal idiom — `move.w (tbl,PC,Dn*2),Dm ; jmp (tbl,PC,Dm)`, i.e. `target = tbl +
  int16(tbl[idx])` after a binary-search range check — compiles to an indirect `jmp` the Ghidra
  **decompiler cannot render as a `switch`** (it models the computed jump as a `(code *)` call;
  *"Could not recover jumptable … treating indirect jump as call"*). Neither `COMPUTED_JUMP`
  references nor a `BRANCH` flow override change the decompiled view — a known decompiler limitation.
  They are **not** function-pointer tables, so they are left as casts, but each has been **recovered
  and annotated** in the DB: `COMPUTED_JUMP` refs to every real case target (so the listing/xrefs/call
  graph show true flow), a plate comment at the `jmp`, and labels on the offset + value tables:

  | `jmp` | function / case | table | cases | dispatch |
  |---|---|---|---|---|
  | `0x141F2` | `COMM_CALL_FUNCTION_ID` | `COMM_FANSPEED_JUMPTABLE` `0x141F6` | 2 (+default) | fan-speed 63/81/100% by `gDIAGNOSTIC_KEITHLEY_BITS_RNG` |
  | `0x57CD6` | `_vsprintf` | `VSPRINTF_CONV_JUMPTABLE` `0x57CDA` | 9 | C printf `%`-conversion by format char (`E G X c d e f g i n o p s u x`) |
  | `0x3954C` | `RESPONSE_ADD_CUSTOM_TYPE` case 0xE | `RESPONSE_0xE_JUMPTABLE` `0x39550` | 10 | bit-flag code (`0x2..0x400`) → response keyword |
  | `0x39CEE` | `RESPONSE_ADD_CUSTOM_TYPE` case 0x22 | `RESPONSE_0x22_JUMPTABLE` `0x39CF2` | 17 | status code (`0x129..0xDA45`) → response string, else `BAD_FLASH` |

  (The same idiom drives the key-autorepeat classifier at `0x3D3BA`, which is degenerate — all
  entries share one target; see [DISPLAY.md](DISPLAY.md) §5.)

**`(code *)` cast that is a display artifact over typed data:**

- `KEY_EXECUTE_PRESS_FUNCTION`'s key-dispatch call. The real handler table is **`KEY_HANDLER_TABLE`**
  (`0x63936`, now typed **`VOIDFN *[180]`** = 4 keylock banks × 45 keys; unused slots point at the
  common no-op `NOP_RETURN_STUB` `0x473D0`). It sits immediately after `DISPLAY_TEST_PATTERN_FUNCTABLE`.
  **Verified:** all 180 entries point into the front-panel key-code region `0x3C000–0x48000`; the 44
  distinct non-no-op targets are the `FUNCTION_KEYCODE__*` handlers (RANGE_UP/DOWN,
  MEAS_FUNCTION, SOURCE_V/I, TRIGGER, ON_OFF, EDIT, STORE/RECALL, SWEEP, CONFIG, …). 108 slots are the
  no-op stub `NOP_RETURN_STUB` — banks 1–3 (keylock states) keep only the few keys that stay live when
  locked, every other key routed to the stub.

  **Keycode ↔ slot:** physical table index (from `0x63936`) = `keyCode − 0x3F`, i.e. the handler for
  `keyCode` K is `KEY_HANDLER_TABLE[K − 0x3F]` (bank adds `+45` per keylock state). The authoritative
  identities are the **`KEYCODE` enum** (`0x40`=NOT_PRESSED … `0x60`=FRONT/REAR). The previously
  "unknown" handlers were named from that enum (confirmed by behavior):
  `__NOT_PRESSED` (0x40), `__EDIT_VALUE` (0x42), `__LEFT_ARROW` (0x43), `__MENU` (0x44, opens
  MAIN_MENU), `__RIGHT_ARROW` (0x4A), `__EXIT` (0x4B, `MENU_GET_PARENT`/abort), `__ENTER` (0x52),
  `__LOCAL` (0x57, `SWITCH_TO_LOCAL_CONTROL`), `__CAL` (0x59, cal unlock), `__EDIT_0x5A` (0x5A).
  Keycodes **0x61–0x69** are internal/injected pseudo-keys (no silkscreen label); named by behavior:
  `_0x61_menu_select`, `_0x62_refresh_display_text`, `_0x63_clear_user_text_state`,
  `_0x64_latch_trace_feed_ctrl`, `_0x65_reset_frontpanel_defaults`, `_0x66_apply_config_unit_menu`,
  `_0x68_edit_digit_weight_cursor`, `_0x69_edit_init_cursor`. (NB: the old `_0xNN_unknown` function
  names were off by one in their hex — the real keycode is one less.) The compiler
  addresses it via `lea 0x63936` + `(-0xFC, A0, keyCode*4)`, so the decompiler **constant-folds the
  base to `0x6383A`** and anchors the call on the nearest symbol, `PTR_ARRAY_00063832` — which is a
  legitimate **`char *` string table** that `RESPONSE_ADD_CUSTOM_TYPE` indexes for enum response text.
  One symbol cannot be both a `char *` table and a function-pointer table, so the `(code *)` cast at
  the call site is a **decompiler display artifact**, not an untyped slot: the backing data is fully
  typed. The low region `0x63802–0x6391E` is the SCPI enum string tables (`PTR_ARRAY_0006380x/1a/26/32`).

After typing: **118 → 3** residual cast lines, confirmed by re-running the sweep. All three are
accounted for: two are compiler switch jump-tables (`COMM_CALL_FUNCTION_ID`, `_vsprintf`) and the
third is the `KEY_HANDLER_TABLE` display artifact over correctly-typed data. The sweep count stays 3
because the decompiler cannot render the switch idiom — but every such table (those two plus the two
inside `RESPONSE_ADD_CUSTOM_TYPE`, which the sweep's one-decompile-per-function view collapses into a
single reported line) is now recovered: real case targets exposed as `COMPUTED_JUMP` references, with
plate comments and labels. Changes are persisted in the Ghidra DB.

## 5. Relationship to the rest of the firmware

```
GPIB / RS-232  ─►  SCPI parser & dispatch  ─►  :SOUR... handler ─► DAC primitive ─► QSPI ─► analog board
   (GPIB.md)          (SCPI.md)             └─  :MEAS?/:READ? ─► SDM/trigger model ─► A/D (U610)
                                                                          │
                                       calibration constants (I²C EEPROM, parse_flash.py) ─┘
                                                                          ▼
                                                          reading ─► response builder ─► output
```

The source side is a tight DAC-over-QSPI engine; the measure side hangs off the trigger model and
the multi-slope A/D, fused with EEPROM calibration to produce the final reading.
