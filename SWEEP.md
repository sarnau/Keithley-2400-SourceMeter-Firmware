# SWEEP.md — Sweep engine (staircase / log / list / source-memory)

Reverse-engineering notes on the Keithley 2400 **sweep engine**: the four sweep types,
how points are generated and consumed, the point buffer, per-trigger point advance, the
source-memory pass/fail branching (binning sweep), and `:SWE:CABort`. Companion to
[TRIGGER.md](TRIGGER.md) (the SDM cycle that consumes one point per trigger),
[MEASURE.md](MEASURE.md) (the source-programming path each step drives), and the limit-test
pieces in `SUMMARY.md`. All addresses are in `2400-FIRMWARE.bin` (firmware C34).

---

## 1. Sweep types & mode selection

| Type | Selected by | Points from |
|---|---|---|
| **Linear staircase** | `SOURCE1_VOLTAGE_MODE`/`CURRENT_MODE == 1`, `SWEEP_SPACING == 0` | `start + i·step`, pre-filled |
| **Log staircase** | mode `== 1`, `SWEEP_SPACING != 0` | log-interpolated, pre-filled |
| **Custom / LIST** | mode `== 2` | the arbitrary `:SOUR:LIST:VOLT`/`:CURR` array, copied in |
| **Source-memory** | `gSWEEP_IS_MEMORY` (set by `MEASURE_SETUP_RANGE_AND_DISPATCH` @`0xba02` per source mode) | 100 saved setups, recalled per step |

The source *function* (V-source vs I-source) is `gCONFIG_0x19E.bSOURCE1_FUNCTION_MODE`
(0 = volt, 1 = curr); `BUILD_SWEEP_POINTS` has mirrored V/I branches. The first three types
pre-compute a point table (`SWEEP_POINTS_BUFFER`); source-memory does **not** use that buffer —
it steps through saved instrument setups instead (§5).

---

## 2. Point buffer — `SWEEP_POINTS_BUFFER` @`0x83a50c`

`SWEEP_POINT_STRUCT[2500]`, 8 bytes/entry:

| Off | Field | Meaning |
|---|---|---|
| +0 | `amplitude` (float) | source level for this point |
| +4 | `reserved_0x4` (short) | — |
| +6 | `currentRange` (byte) | source range index to program for this point |
| +7 | `changeSign` (byte) | polarity/sign flag |

Walked by two cursors: **`gSWEEP_POINT_PTR_A`** (`0x8018dc`, end = base + N points) and
**`gSWEEP_POINT_PTR_B`** (`0x8018d8`, the current point). `BUILD_SWEEP_POINTS` sets
`PTR_A = SWEEP_POINTS_BUFFER + <points>`, `PTR_B = SWEEP_POINTS_BUFFER`, `gSWEEP_ACTIVE = 1`.

A separate running index `gSweepPointCounter` (`0x8018d6`, renamed from `_maybe`) is used by
the per-point source-setup handlers to fetch the current amplitude; reset on
`:ABORt`/init.

---

## 3. Point generation — `BUILD_SWEEP_POINTS` @`0x29dac`

One large generator (~52 KB) that pre-fills `SWEEP_POINTS_BUFFER`. Per point it stores the
amplitude, resolves the **range** (`RANGE_FIND_VOLTAGE` / current equivalent), applies
source resolution (`SOURCE_VOLTAGE_RESOLUTION`) and a calibration factor
(`gCALIBRATION_DATA.calBlock_0xb0[range][column]`), and records the sign.

### 3.1 Linear staircase (`SWEEP_SPACING == 0`)
Loop `i = 0 .. SOURCE1_SWEEP_POINTS-1`: `amplitude[i] = START + i·STEP` (Pascal soft-float
`MULT`/`ADD`), ramping from `:SOUR:VOLT:STARt` toward `:STOP`. Fields read:
`SOURCE1_VOLTAGE_START`/`_STOP`/`_STEP` (and the current-source equivalents),
`SOURCE1_SWEEP_POINTS`.

### 3.2 Log staircase (`SWEEP_SPACING != 0`)
Uses `DOUBLE_LOG` on `START` and `STOP`: points are spaced evenly in log space, i.e.
`amplitude[i] = exp( log(start) + i·(log(stop) − log(start))/(N−1) )`, computed in double
precision then converted back to float. (`:SWE:SPACing LOGarithmic`.)

### 3.3 Custom / LIST (`VOLTAGE_MODE`/`CURRENT_MODE == 2`)
Copies the arbitrary list values into the buffer: loop `i = 0 .. gSOURCE1_LIST_VOLTAGE_POINTS`
reading from the `:SOUR:LIST:VOLT`/`:CURR` configuration array (indexed from
`SOURCE1_LIST_VOLTAGE_START`), applying the same range/resolution/cal per point. Direction =
`gSOURCE1_LIST_DIRECTION`. (The list storage array itself is the `:SOUR:LIST` config block;
its exact base is not pinned here.)

`:SWE:RANGing` (BEST/AUTO/FIXed) feeds the per-point range decision via
`SOURCE1_SWEEP_RANGING`; `:SWE:DIRection` sets `SOURCE1_SWEEP_DIRECTION` →
`gSWEEP_DIRECTION`.

---

## 4. Point advance — `SWEEP_POINT_PTR_ADVANCE` @`0xf970`

Called once per completed point from the trigger/measure-complete path
([TRIGGER.md](TRIGGER.md) §5). Two regimes:

### 4.1 Staircase / list (`!gSWEEP_IS_MEMORY`)
- **UP** (`gSWEEP_DIRECTION != 6`): `PTR_B++` until it reaches `PTR_A`; at the end wrap
  `PTR_B = SWEEP_POINTS_BUFFER` and set `gSWEEP_POINT_BOTTOM_REACHED`.
- **DOWN** (`== 6`): step `PTR_B` down from `PTR_A` toward the buffer base; at base, reload
  `PTR_B = PTR_A`.

### 4.2 Source-memory (`gSWEEP_IS_MEMORY`)
- Normally `gSWEEP_MEMORY_LOC++`, **wrapping at 100** (`if (100 < loc) loc = 1`).
- **PASS/FAIL branch (binning sweep):** if `calc2Limits[9].passLocation` or `.flag` is set,
  test the reading's limit result (`gCALC2_READING_PTR->dwStatusFlags & 0x4180300`):
  - **PASS** (no fail bits) → next location = `calc2Limits[9].passLocation`
    (`:CALC2:CLIM:PASS:SMLocation`).
  - **FAIL** → next location = `calc2Limits[9].flag` (`:CALC2:CLIM:FAIL:SMLocation`).
  (`CALCULATE2_CLIMITS_MODE` selects which polarity triggers the pass branch.)
- Advance `gSWEEP_POINT_INDEX`; terminate when `> SOURCE1_MEMORY_POINTS`
  (`gSWEEP_POINT_BOTTOM_REACHED = true`). `gSWEEP_MEMORY_LOC_ACTIVE` tracks the live
  location.

`calc2Limits[9]` is the dedicated binning limit entry (`CALC2_LIMIT_ENTRY`:
`{upperLimit, lowerLimit, passSource2, passLocation, flag}`); its `passLocation`/`flag`
fields are the memory-location redirect targets — this is the sort/bin sweep.

---

## 5. Source-memory recall

Each of 100 memory locations is a **196-byte (`0xc4`) saved instrument setup** at
`0x80df3e + loc·0xc4` (`gSweepMemData_maybe` @`0x80df68` lies inside location 0's block).
Stepping/recall:

- `SWEEP_MEMORY_POINT_CONFIGURE` @`0xeb7c` — validates the location's setup against current
  state (sense mode, function, FR switch), handles contact-check (`SYSTEM_CCHECK_STATE`), then
  recalls; may rebuild the trigger model for the new setup.
- `SWEEP_MEMORY_POINT_APPLY` @`0xeb5a` — the plain path: `SETUP_RECALL_APPLY(gSWEEP_MEMORY_LOC, true)`
  then `gCOMM_CALLBACK_DONE = SWEEP_POINT_ADVANCE`.
- `SWEEP_MEMORY_POINT_NEXT` @`0xfccc` — advance to the next memory location.

So a source-memory sweep **recalls a full saved front-panel setup** (function, range, source
level, speed, math, limits) at each step — `SETUP_RECALL_APPLY` is the `*RCL`/`:SOUR:MEM:RECall`
machinery. Config: `SOURCE1_MEMORY_START` (first location), `SOURCE1_MEMORY_POINTS` (count).

---

## 6. Per-point termination handlers — `SWEEP_SELECT_DONE_HANDLERS` @`0x13aa6`

Selects the end-of-point handler pair (`FUNCPTR_00805438` / `FUNCPTR_0080873`) from the
`SWEEP_POINT_END_*` family, keyed on: trigger count (single vs loop,
`TRIGGER_SEQUENCE1_COUNT < 2`), source auto-clear (`SOURCE1_CLEAR_AUTO` → `*_SRCCLEAR`),
timed digital-output sweep (`SWEEP_DIGOUT`), auto-zero/NPLC timing (`*_TIMED`), limit test,
math, and **abort-on-compliance** (`ABORT_ON_COMPLIANCE`). Handler variants:
`SWEEP_POINT_END_{SINGLE,LOOP,SRCCLEAR,SRCCLEAR_SINGLE,SRCCLEAR_LOOP,DIGOUT_SINGLE,DIGOUT_LOOP,
*_TIMED,TRIGOUT_ONLY}` @`0x13bf6`–`0x140fe`.

**`:SWE:CABort` (abort-on-compliance)** = `gCONFIG_0x19E.ABORT_ON_COMPLIANCE`; when set and a
sweep is active, a compliance event routes to the abort-capable end handler (ending the sweep
early). The abort message is `DOUBLELINE_TEXT_SWEEP_aborted` @`0x65094`.

---

## 7. Trigger coupling

A sweep consumes **one point per trigger**. The trigger model
([TRIGGER.md](TRIGGER.md)) runs its SDM cycle, and on measure-complete calls
`SWEEP_POINT_PTR_ADVANCE` (§4) to step the source for the next point. Point count vs trigger
count:

- `SWEEP_MEASURE_BUFFER_END_SET` @`0x1650c` sizes the run as **ARM:COUNt × TRIGger:COUNt**
  readings; for a complete sweep the trigger count should equal (or be a multiple of) the
  sweep **POINts**.
- `BUILD_SWEEP_POINTS` wires the per-point *source-setup* step into the trigger model's
  `gTRIG_STEP_*` slots (`SWEEP_POINT_SETUP_VSOURCE`/`_VSOURCE_PULSE`/`_ISOURCE`,
  `SWEEP_MEMORY_POINT_CONFIGURE`/`_NEXT`) via `TRIGGER_BUILD_MODEL_HANDLERS` — see
  [TRIGGER.md](TRIGGER.md) §3. Each trigger thus programs the next source value
  ([MEASURE.md](MEASURE.md) source path) before measuring.

Readings are auto-stored to the `:TRACe` buffer as the sweep runs (see [TRACE.md](TRACE.md)).

---

## 8. Key symbols (quick reference)

**Generation / mode:** `BUILD_SWEEP_POINTS` `0x29dac` · mode selector in
`MEASURE_SETUP_RANGE_AND_DISPATCH` `0xba02` · `SWEEP_POINTS_BUFFER` `0x83a50c`
(`SWEEP_POINT_STRUCT`, 8 B).

**Cursors / counters:** `gSWEEP_POINT_PTR_A` `0x8018dc` · `gSWEEP_POINT_PTR_B` `0x8018d8` ·
`gSweepPointCounter` `0x8018d6` · `gSweepPointCount` `0x813a5c` · `gSWEEP_POINT_INDEX`
`0x8018d0` · `gSWEEP_ACTIVE` `0x8018d3` · `gSWEEP_DIRECTION` `0x8018d4` ·
`gSWEEP_POINT_BOTTOM_REACHED` `0x801933`.

**Advance / branch:** `SWEEP_POINT_PTR_ADVANCE` `0xf970` · `SWEEP_POINT_ADVANCE` `0xe330` ·
`SWEEP_SELECT_DONE_HANDLERS` `0x13aa6`.

**Source-memory:** `gSWEEP_IS_MEMORY` `0x8018cf` · `gSWEEP_MEMORY_LOC` `0x8018d1` ·
`gSWEEP_MEMORY_LOC_ACTIVE` `0x8018d2` · memory store `0x80df3e + loc·0xc4` ·
`SWEEP_MEMORY_POINT_CONFIGURE` `0xeb7c` · `_APPLY` `0xeb5a` · `_NEXT` `0xfccc` ·
`SETUP_RECALL_APPLY`. Branch targets: `gCONFIG_0x19E.calc2Limits[9].passLocation`/`.flag`.

**Per-point source setup:** `SWEEP_POINT_SETUP_VSOURCE` `0xe3b4` / `_VSOURCE_PULSE` `0xe7c8` /
`_ISOURCE` `0xe96e` · end handlers `SWEEP_POINT_END_*` `0x13bf6`–`0x140fe`.
