# TRACE.md — Data store (`:TRACe`) & buffer statistics (`:CALCulate3`)

Reverse-engineering notes on the Keithley 2400 **reading buffer** (`:TRACe`/`:DATA`): its
storage layout, the store path in the measurement cycle, the `:TRACe` command surface,
timestamp handling, and the buffer-statistics engine (`:CALCulate3`). Companion to
[MEASURE.md](MEASURE.md) (the readings being stored) and [TRIGGER.md](TRIGGER.md) (the
SDM cycle that drives stores). All addresses are in `2400-FIRMWARE.bin` (firmware C34).

---

## 1. Buffer storage — one store, compact entries

There is **one `:TRACe` reading store**, separate from the live/SDM reading records:

| Region | Addr | Element | Purpose |
|---|---|---|---|
| **`:TRACe` store** | `gTraceStatBuffer` `0x826c8c` | 24-byte compact entry (below) | the stored-readings buffer (`:TRAC:DATA?`, `:CALC3`). |
| Live/SDM reading | `READING_RECORD[]` `0x814794` | `READING_RECORD` (30 B) | the records produced per measurement; current = `gCALC2_READING_PTR` `0x814784`, ring/base cursor `gCALC2_READING_RING_PTR` `0x81477c`. |
| Sweep points | `SWEEP_POINTS_BUFFER` `0x83a50c` | `SWEEP_POINT_STRUCT` | per-point *source* setups for a sweep (not readings). |

The store region spans `0x826c8c`…≈`0x835a0c` (≈2650 × 24 B), i.e. the documented **2500-reading**
maximum. (The "two 2500-reading buffers / 5000" figure in the manual is **not** reflected in
firmware as two physical reading stores — there is a single configurable `:TRACe` buffer plus
the distinct sweep-setup region above.)

### 1.1 Compact store entry (24 bytes, from `TRACE_BUFFER_STORE_READING`)

Each stored reading is packed into 24 bytes — a reduced form of the 30-byte live
`READING_RECORD`. The element-0 field labels (array stride `0x18`):

| Off | Addr (entry 0) | Field label | Content |
|---|---|---|---|
| +0  | `0x826c8c` | `gTraceStatBuffer`        | primary value (reading / math result, per feed) |
| +4  | `0x826c90` | `gTraceReadingField_maybe`| reading value |
| +8  | `0x826c94` | `gTraceSourceField_maybe` | source level (V or I) |
| +0xc| `0x826c98` | `gTraceRangeField_maybe`  | range index nibbles |
| +0xe| `0x826c9a` | `gTraceField_c9a_maybe`   | `systemTimeStamp` (ulong) |
| +0x12| `0x826c9e`| `gStatMeanField2_maybe`   | `dwStatusFlags` (ulong) |
| +0x16| `0x826ca2` | `gTraceUnitField_maybe`   | packed: unit, speed/accuracy, display-view |
| +0x17| `0x826ca3` | `gTraceModeField_maybe`   | packed: feed mode (`gTRACE_FEED & 3`) |

Exact sub-bit packing of the unit/mode words is as decompiled; treat the bitfield splits
as approximate.

### 1.2 Control block (`0x813a40`)

| Off | Addr | Symbol | Meaning |
|---|---|---|---|
| +0 | `0x813a40` | `gTraceStoreIndex`     | write index; `×0x18` = byte offset into the store. Wraps to 0 at capacity. |
| +4 | `0x813a44` | `gTRACE_FREE`          | fill high-index: `-1` when empty, incremented per store (so stored count = `gTRACE_FREE + 1`; stat loops run `0..gTRACE_FREE`). |
| +6 | `0x813a46` | `gTracePointsCapacity` | buffer size (`:TRAC:POINts`); the full test compares it to `gTraceStoreIndex`. |
| +8 | `0x813a48` | `gTRACE_FEED`          | feed source (§3). |
| +9 | `0x813a49` | `gTRACE_FEED_CONTROL`  | `:FEED:CONTrol` — NEXT (`1`) vs NEVer (`0`). |
| +0xa| `0x813a4a`| `gTRACE_TSTAMP_FORMAT` | `:TSTamp:FORMat` — ABSolute vs DELta. |
| +0xc| `0x813a4c`| `gTraceTimestampRef`   | first-stored-reading timestamp, for DELta (§5). |

(`gTraceStoreIndex`, `gTracePointsCapacity`, `gTraceTimestampRef` were renamed this session
from the mis-named `gFactoryResetWord_maybe` / `gExitMenuValue_maybe` / `gTimestampLong_maybe`.)

---

## 2. Store path & buffer lifecycle

The store runs off a function-pointer slot `FUNCPTR_00805804`, swapped between an idle and
an acquire handler:

| Function | Addr | Role |
|---|---|---|
| `TRACE_BUFFER_ARM`      | `0x1615a` | Reset index, set `gTRACE_FREE = -1`, clear the stat cache (`gCalc2StatValidMask = 0`); if FEED:CONTrol = NEXT, install `TRACE_BUFFER_ACQUIRE_HANDLER` and light the "reading being stored" annunciator, else `TRACE_BUFFER_IDLE_HANDLER`. |
| `TRACE_BUFFER_ACQUIRE_HANDLER` | `0x161ae` | Per completed reading: call `STORE_READING`; on success latch `gTraceTimestampRef`, set Measurement-event **BUFFER_AVAILABLE (+108)**; when `gTraceStoreIndex == gTracePointsCapacity` set **BUFFER_FULL (+109)**, reset index, and `FEED_STOP` (one-shot fill). |
| `TRACE_BUFFER_STORE_READING` | `0x16246` | Copy the selected fields from `gCALC2_READING_PTR` into `gTraceStatBuffer[gTraceStoreIndex]`; write timestamp/status/unit/mode; `gTraceStoreIndex++`, `gTRACE_FREE++`. Returns non-zero if the reading was invalid for the feed (skipped). |
| `TRACE_BUFFER_IDLE_HANDLER` | `0x161ac` | No-op (store disabled). |
| `TRACE_BUFFER_CLEAR`    | `0x160a4` | `:TRAC:CLEar` — reset index/`gTRACE_FREE`, idle handler, clear BUFFER_FULL/AVAILABLE events. |
| `TRACE_BUFFER_FEED_STOP`| `0x160ee` | End acquisition: `FEED_CONTROL = NEVer`, idle handler, drop annunciator (re-enables display if it was suppressed for store speed). |
| `TRACE_BUFFER_DISARM`   | `0x16146` | Detach the acquire handler. |
| `SWEEP_MEASURE_BUFFER_END_SET` | `0x1650c` | Compute the expected reading count = `ARM count × TRIGger count` and set the SDM reading-buffer end pointer. |

The acquire handler is invoked once per completed reading in the SDM/trigger cycle — the
same measure-complete path documented in [TRIGGER.md](TRIGGER.md) §5.

---

## 3. Feed source & control (`:TRAC:FEED` / `:FEED:CONTrol`)

`gTRACE_FEED` (`0x813a48`) selects what `STORE_READING` captures:

| Value | `:TRAC:FEED` | Stored primary value |
|---|---|---|
| 0 | NONE | (store disabled) |
| 1 | SENSe[1] | raw reading (`flReading` / `flReading2` / `flResistance`) + range |
| 2 | CALCulate[1] | math result (`reserved_init_0xe`); source level/range from config |
| 3 | CALCulate2 | CALC2 result (`reserved_init_0x12`); sub-selected by `bCALCULATE2_FEED` (2/4/5/6 = formula/range variants) |

For feeds 2/3 a reading flagged invalid (`dwStatusFlags & 0x2000000` for CALC1,
`& 0x4000000` for CALC2) is skipped (returns 1, index not advanced).

`gTRACE_FEED_CONTROL` (`0x813a49`): **NEXT** = fill once until POINts reached (the acquire
handler stops at BUFFER_FULL); **NEVer** = disabled. This is the 2400's one-shot buffer model
(no continuous circular overwrite — on full it stops rather than wrapping over live data).

---

## 4. `:TRACe` command map

| Command | Backing |
|---|---|
| `:TRAC:POINts <n>` / `?` | `gTracePointsCapacity` `0x813a46` |
| `:TRAC:DATA?` (alias `:DATA?`) | dump of `gTraceStatBuffer` entries `0..gTRACE_FREE` |
| `:TRAC:CLEar` | `TRACE_BUFFER_CLEAR` `0x160a4` |
| `:TRAC:FREE?` | available/used from `gTRACE_FREE` vs `gTracePointsCapacity` |
| `:TRAC:FEED <src>` / `?` | `gTRACE_FEED` `0x813a48` |
| `:TRAC:FEED:CONTrol NEXT\|NEVer` | `gTRACE_FEED_CONTROL` `0x813a49` (ARM via `TRACE_BUFFER_ARM`) |
| `:TRAC:TSTamp:FORMat ABSolute\|DELta` | `gTRACE_TSTAMP_FORMAT` `0x813a4a` |

Command tokens: `COMMAND_TRACE` `0x619ea`, `COMMAND_BUFFER` `0x5cf2a` (BUFFer alias),
`COMMAND_CALC3`/`COMMAND_CALCULATE3` `0x5fc16`/`0x5fc04`.

---

## 5. Timestamps

Each reading carries `READING_RECORD.systemTimeStamp` (+22, ulong) — a snapshot of the live
`gMeasureTimestamp` (`0x801944`), written by the A/D trigger paths (`ADC_TRIGGER_SIG1`/`SIG2`/
`_OR_TIMER`, `MEASURE_SCHEDULE_NEXT_TIMER`, `MEASURE_PULSE_OUTPUT_TRIGGER`). The time base is
the **1000 Hz (1 ms) system tick** (`EXCEPTION_USER_66_TIMER_IRQ_1000Hz` @`0x1455c`);
`:SYST:TIME:RESet` zeroes it.

`gTRACE_TSTAMP_FORMAT` (`0x813a4a`) chooses, when formatting (`DISPLAY_FORMAT_TIMESTAMP`
@`0x4bd76` and the response builder `RESPONSE_0003a99e`):

- **ABSolute** — the raw stored `systemTimeStamp`.
- **DELta** — relative to `gTraceTimestampRef` (`0x813a4c`), latched to the **first stored
  reading's** timestamp in `TRACE_BUFFER_ACQUIRE_HANDLER`.

---

## 6. Buffer statistics (`:CALCulate3`)

`:CALC3` computes statistics **on demand over the stored buffer** (not accumulated during
storage). `CALCULATE2_STAT_SELECT_FUNCTION` @`0x16030` maps `:CALC3:FORMat` to a function
pointer `FUNCPTR_00807e94`, invoked by `:CALC3:DATA?`:

| `:CALC3:FORMat` | Function | Addr |
|---|---|---|
| MEAN (0/4) | `CALCULATE2_STAT_MEAN` | `0x15966` |
| MINimum (1) | `CALCULATE2_STAT_MINIMUM` | `0x156e2` |
| MAXimum (2) | `CALCULATE2_STAT_MAXIMUM` | `0x1550a` |
| PKPK (3) | `CALCULATE2_STAT_PK2PK` | `0x158a2` |
| SDEViation (5) | `CALCULATE2_STAT_SDEVIATION` | `0x15c12` |
| (clear) | `CALCULATE2_STAT_CLEAR` | `0x154cc` |

Each routine loops `uVar = 0..gTRACE_FREE` over `gTraceStatBuffer`. Results are **cached** in
`gCalc2StatValidMask` (`0x805102`): bit `1` = MIN, `2` = MAX, `8` = MEAN, `0x10` = SDEV — a
set bit means the cached result is current; `TRACE_BUFFER_ARM` clears the mask so a new
acquisition forces recompute. Uninitialised slots use the Pascal-float sentinels
`0x7e951bee` (+overflow, MIN seed) and `-0x16ae412` (MAX seed).

### Accumulator / result banks (`0x800004`–`0x800047`)

| Stat | Value slots | Count slots |
|---|---|---|
| MAX | `gCalc2StatMax0_maybe` `0x800004` (+`_c`/`_e`) | `gCalc2StatMaxCount*` `0x800010`–`0x800016` |
| MIN | `gCalc2StatMin0_maybe` `0x800018` (+`_20`/`_24`) | `gCalc2StatMinCount*` `0x800028`–`0x80002e` |
| MEAN | `gCalc2StatMean_maybe` `0x800030`, `_34`, `0x800038`/`3c` | — |
| SDEV | `gCalc2StatSdev_maybe` `0x800040`, `_44` | — |

The two running pairs are **MIN {value, count}** and **MAX {value, count}**; PKPK = MAX − MIN.
MEAN is a single pass (Σx / N). SDEViation is **two-pass** (compute MEAN, then Σ(x−mean)²
over the buffer) — consistent with its much larger code size. Each stat keeps several columns
(reading / source / …) matching the compact entry's value fields.

---

## 7. Relationship to the trigger model & reading count

`SWEEP_MEASURE_BUFFER_END_SET` sizes the measurement run as **ARM:COUNt × TRIGger:COUNt**
readings (see [TRIGGER.md](TRIGGER.md) §6). The `:TRACe` store fills one reading per completed
trigger (SDM measure-complete → `TRACE_BUFFER_ACQUIRE_HANDLER`) until `gTracePointsCapacity`
(`:TRAC:POINts`) is reached, then latches **BUFFER_FULL** and stops. For a complete sweep
capture, `:TRAC:POINts` should equal the trigger/arm reading product. The store annunciator
and (optionally) display suppression during storage keep the fast store path unencumbered.

---

## 8. Key symbols (quick reference)

**Store/control:** `gTraceStatBuffer` `0x826c8c` · `gTraceStoreIndex` `0x813a40` ·
`gTRACE_FREE` `0x813a44` · `gTracePointsCapacity` `0x813a46` · `gTRACE_FEED` `0x813a48` ·
`gTRACE_FEED_CONTROL` `0x813a49` · `gTRACE_TSTAMP_FORMAT` `0x813a4a` · `gTraceTimestampRef`
`0x813a4c`.

**Store routines:** `TRACE_BUFFER_STORE_READING` `0x16246` · `TRACE_BUFFER_ACQUIRE_HANDLER`
`0x161ae` · `TRACE_BUFFER_ARM` `0x1615a` · `TRACE_BUFFER_CLEAR` `0x160a4` ·
`TRACE_BUFFER_FEED_STOP` `0x160ee` · `TRACE_BUFFER_DISARM` `0x16146` ·
`SWEEP_MEASURE_BUFFER_END_SET` `0x1650c`.

**Live readings:** `READING_RECORD[]` `0x814794` (30 B) · `gCALC2_READING_PTR` `0x814784` ·
`gCALC2_READING_RING_PTR` `0x81477c` · `gMeasureTimestamp` `0x801944`.

**Statistics:** `CALCULATE2_STAT_SELECT_FUNCTION` `0x16030` · MEAN `0x15966` / MIN `0x156e2` /
MAX `0x1550a` / PK2PK `0x158a2` / SDEV `0x15c12` / CLEAR `0x154cc` · cache
`gCalc2StatValidMask` `0x805102` · accumulators `0x800004`–`0x800047` · dispatch pointer
`FUNCPTR_00807e94`.
