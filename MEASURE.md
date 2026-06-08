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

Packs the 16-bit value into the 2-word transmit buffer `WORD_ARRAY_00801390`:

```c
WORD_ARRAY_00801390[0] = value >> 8;             // high byte
WORD_ARRAY_00801390[1] = (value << 3) | 4;       // low byte + AD7849 serial framing/control bits
gDIAGNOSTIC_KEITHLEY_BITS_VDAC = value;          // shadow copy
return &STRUCT_COMM_TRANSMIT_00058BCE;           // static descriptor (chained via .next)
```

DAC values are 16-bit (`0..65535`, validated against `65535.0`); MUX / range values are 8-bit
(`0..255`, validated against `255.0`).

### 2.3 Transmit descriptor — `STRUCT_COMM_TRANSMIT`

A static descriptor per analog operation, carrying the QSPI configuration and a `next` pointer for
chaining. Fields used by `COMM_TRANSMIT_BLOCK`: `transmitPtr` (→ data buffer, e.g. `0x801390`),
`cmdPtr` (→ per-transfer QSPI command bytes = chip-select/control), `spcr0` (bits-per-transfer +
baud), `spcr1` (delays), `spcr2` (ending queue pointer = number of transfers), `pqspar` (pin
assignment), `next` (chained descriptor), `field5_0x7` (channel type: 3 = TPU, else QSPI). The V-DAC
descriptor at `0x58BCE` chains to `0x58BC8`, so a V-DAC update is a multi-block sequence.

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
gain    = (SIG2 - ZERO > 0) ? FLOAT_008018E8   // positive-polarity gain
                            : FLOAT_008018E4;  // negative-polarity gain
reading = ratio * gain + FLOAT_008018EC;     // + offset
// overrange: |reading| vs FLOAT_00801908  -> set overflow status
```

- Result lands in the reading struct **`STRUCT_30_0080847C`**: `.field1_0x4` = the float reading,
  `.field8_0x1A` = status flags (overflow = `0x20000001`).
- The active-range **calibration constants** at `0x8018E4` (neg gain) / `0x8018E8` (pos gain) /
  `0x8018EC` (offset) are loaded from the **I²C EEPROM** cal data (the 88 floats decoded by
  [parse_flash.py](parse_flash.py); each sense range has zero / +FS / −FS constants).
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
| transmit frame buffer | `WORD_ARRAY_00801390` | 2-word QSPI data |
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
