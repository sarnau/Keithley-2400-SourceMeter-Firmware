# STATUS.md — IEEE-488.2 / SCPI status model

Reverse-engineering notes on the Keithley 2400 **status system**: the Status Byte and
its summary registers (Standard Event, Operation, Questionable, Measurement), the
Service-Request (SRQ) generation path, the error/event queue, and the `:STATus`/common
command surface. Companion to [GPIB.md](GPIB.md) (the TMS9914A serial-poll/SRQ hardware),
[TRIGGER.md](TRIGGER.md) (which sets the Operation-status trigger bits), and
[MEASURE.md](MEASURE.md) (the per-reading status element, distinct — see §9). All
addresses are in `2400-FIRMWARE.bin` (firmware C34).

The whole status engine is the `EventRegs_*` / `EventReg_*` family at
`0x4ee14`–`0x50018`, driven by two ROM tables and five RAM register banks.

---

## 1. Register hierarchy

```
                       ┌─────────────────────────────┐
                       │  Status Byte (STB)           │  gEvent_RootRegisters @0x8050f0
                       │  *STB? / serial poll / *SRE  │  node: gEventStruct_root @0x67612
                       └──────────────┬──────────────┘
      summary bit rolled up into STB: │
   ┌──────────────┬───────────┬───────┴────┬─────────────────┐
   │ b0 MSB(0x01) │ b3 QSB    │ b5 ESB     │ b7 OSB(0x80)    │  (b2 EAV, b4 MAV, b6 RQS/MSS)
   ▼              ▼ (0x08)    ▼ (0x20)     ▼                 │
 Measurement   Questionable  Standard     Operation          │
 Event         Status        Event(ESR)   Status             │
 @0x804800     @0x804810     @0x805824    @0x804808          ▼
 node 0x6761c  node 0x67630  node 0x67644 node 0x6764e   Error/Event Queue → b2 EAV
```

Each box is an `EVENT_REGISTERS_STRUCT` (condition/event/enable storage); each arrow is an
`EVENT_REGS_STRUCT` ROM node that names the register, its parent, and the **summary bit**
it sets in the parent when `(event & enable) ≠ 0`. All four summary registers roll up
directly into the STB (one level); the STB has no parent.

### 1.1 Storage struct — `EVENT_REGISTERS_STRUCT` (8 bytes)

| Off | Field | Meaning |
|---|---|---|
| +0 | `conditionReg`   | Live condition (`:COND?`). Tracks the real-time state; not latched. |
| +2 | `eventReg`       | Latched events (`:EVENt?` / `*ESR?`). Set on a 0→1 condition transition; cleared on read. |
| +4 | `eventEnableReg` | Enable mask (`:ENABle` / `*ESE` / `*SRE`). |
| +6 | `word_3`         | Summary-pending latch: `1` once this set's `(event & enable)` has been rolled up to the parent, to avoid re-propagating. |

### 1.2 Hierarchy node — `EVENT_REGS_STRUCT` (10 bytes, ROM)

| Off | Field | Meaning |
|---|---|---|
| +0 | `regPtr` | → the `EVENT_REGISTERS_STRUCT` storage bank. |
| +4 | `next`   | → the parent node (all summary sets → `gEventStruct_root`; root → NULL). |
| +8 | `mask`   | The bit this set occupies in the parent register (its STB summary bit). |

ROM nodes (proven `{regPtr, next, mask}`):

| Node | Addr | regPtr | STB summary bit |
|---|---|---|---|
| `gEventStruct_root` | `0x67612` | STB `0x8050f0` | — (root) |
| `gEventStructRegister_Measurement`  | `0x6761c` | MEAS `0x804800` | `0x0001` (MSB, b0) |
| `gEventStructRegister_Questionable` | `0x67630` | QUES `0x804810` | `0x0008` (QSB, b3) |
| `gEventStructRegister_Standard`     | `0x67644` | ESR  `0x805824` | `0x0020` (ESB, b5) |
| `gEventStructRegister_Operation`    | `0x6764e` | OPER `0x804808` | `0x0080` (OSB, b7) |

---

## 2. Status Byte (STB) & Service Request Enable (SRE)

`gEvent_RootRegisters` @`0x8050f0` is the STB bank (its `eventReg` holds the live STB
bits, `eventEnableReg` holds the SRE mask). Bit assignments (IEEE-488.2):

| Bit | Mask | Name | Source |
|---|---|---|---|
| 0 | `0x01` | MSB — Measurement Summary | Measurement Event roll-up |
| 1 | `0x02` | (unused) | |
| 2 | `0x04` | EAV — Error/Event Available | error/status queue push (`STATUS_QUEUE_PUSH`, `EventReg_SET_ERROR`) |
| 3 | `0x08` | QSB — Questionable Summary | Questionable roll-up |
| 4 | `0x10` | MAV — Message Available | output queue has response data |
| 5 | `0x20` | ESB — Event Summary | Standard Event (ESR) roll-up |
| 6 | `0x40` | RQS/MSS — Request/Master Summary | computed, not stored (see below) |
| 7 | `0x80` | OSB — Operation Summary | Operation roll-up |

The SRE enable mask is applied with **`0xbf`** (all STB bits except b6), because b6 is the
*summary of the others*, never itself enabled.

- **`*SRE <n>` write** → `EventRegs_SRE_Write` @`0x4f2b0`: stores `n & 0xbf` into the STB
  enable, then recomputes RQS/MSS and asserts/deasserts SRQ accordingly.
- **`*SRE?`** → `EventRegs_SRE_Read` @`0x4f3a2`: returns STB enable `& 0xbf`.
- **`*STB?` / serial poll** → `EventRegs_SerialPoll_STB_Read` @`0x4f35c`: returns the STB
  byte, OR-ing in `0x40` (MSS) when `(stb & enable & 0xbf) ≠ 0`; on RS-232 it also clears
  MAV (`0x10`) after reporting. (`*STB?` and the GPIB serial-poll share this reader.)

---

## 3. Standard Event Status Register (ESR) & ESE

`gEvent_StandardRegisters` @`0x805824`. `*ESR?` reads+clears its event reg
(`EventRegs_StatusRegister`); `*ESE`/`*ESE?` write/read its enable
(`EventRegs_EventEnableReg_SetBits` / `EventRegs_StatusEnableRegister`).

| Bit | Mask | Name | Set by (proven via `gEventRegs_BitTable`) |
|---|---|---|---|
| 0 | `0x01` | OPC — Operation Complete | `ERR_INDEX_200_OPERATION_COMPLETE` |
| 1 | `0x02` | RQC — Request Control | (not used by 2400) |
| 2 | `0x04` | QYE — Query Error | query-error codes (`-4xx`) |
| 3 | `0x08` | DDE — Device-Dependent Error | device errors: `-363` input-buffer overrun, `+5xx` cal, `+6xx` data-lost, etc. |
| 4 | `0x10` | EXE — Execution Error | execution-error codes |
| 5 | `0x20` | CME — Command Error | command-error codes |
| 6 | `0x40` | URQ — User Request | (not used) |
| 7 | `0x80` | PON — Power On | set at boot |

The error-code → ESR-bit mapping is the first ~82 entries of `gEventRegs_BitTable`
(§6); ranges observed: codes 0–3 → QYE, 4–11 → DDE, 12–33 → EXE, 34+ → CME.

---

## 4. Operation / Questionable / Measurement register sets

All three share the same mechanics (condition → latched event → enable → summary bit).
Bit assignments proven by resolving each `ERR_INDEX` through `gEventRegs_BitTable`:

### Operation Status — `gEvent_OperationRegisters` @`0x804808` (→ STB OSB, b7)

| Bit | Mask | SCPI | Status code | Set where |
|---|---|---|---|---|
| 0  | `0x0001` | Cal  | +300 Calibrating | calibration sequence |
| 3  | `0x0008` | Swp  | +303 Sweeping | trigger/sweep run ([TRIGGER.md](TRIGGER.md)) |
| 5  | `0x0020` | Trig | +305 Waiting in Trigger layer | `TRIGGER_ARM_INPUT_OR_DISPATCH` |
| 6  | `0x0040` | Arm  | +306 Waiting in Arm layer | arm-layer wait |
| 10 | `0x0400` | Idle | +310 Re-entering Idle layer | `TRIGGER_ABORT_TO_IDLE` |

### Questionable Status — `gEvent_QuestionableRegisters` @`0x804810` (→ STB QSB, b3)

| Bit | Mask | Status code |
|---|---|---|
| 8  | `0x0100` | +408 Questionable Calibration |
| 14 | `0x4000` | +414 Command Warning |

### Measurement Event — `gEvent_MeasurementRegisters` @`0x804800` (→ STB MSB, b0)

The 2400-specific set:

| Bit | Mask | Status code |
|---|---|---|
| 6 | `0x0040` | +106 Reading Available |
| 7 | `0x0080` | +107 Reading Overflow |
| 8 | `0x0100` | +108 Buffer Available |
| 9 | `0x0200` | +109 Buffer Full |

---

## 5. Transition filtering (positive-only, fixed)

**Important divergence:** firmware C34 implements a **fixed positive-transition** filter.
There is **no PTR/NTR storage** (`EVENT_REGISTERS_STRUCT` has no transition fields) and
**no `:STAT:…:PTRansition`/`:NTRansition` command tokens** exist in the command tree
(a string search finds only `:COND?` "CONDITION" tokens). Equivalent to PTR = `0xFFFF`,
NTR = `0x0000`, hardwired. Mechanics:

- **Set** — `EventRegs_ConditionReg_SetBits` @`0x4f084`: `conditionReg |= mask`; if the
  event bit was `0`, latch it (`eventReg |= mask`); if now `(event & enable) == mask` and
  not already summarized (`word_3 == 0`), set `word_3` and **recurse into the parent node**
  (`next`, `mask`) — this is the roll-up to the STB. Called via `gEventRegs_BitTable`
  through `EventReg_ConditionReg_UpdateSet(code)` @`0x4efa8`.
- **Clear** — `EventRegs_ConditionReg_ClearBits` @`0x4f0f2`: clears only the *condition*
  bit (`conditionReg &= ~mask`); the latched event bit stays until read. Called via
  `EventReg_ConditionReg_UpdateClear(code)` @`0x4ef7c`.
- **Read-and-clear** — `EventRegs_StatusRegister` @`0x4f260`: returns `eventReg`, zeroes
  `eventReg` + `word_3`, and clears this set's summary bit in the parent. This backs every
  `:EVENt?` / `*ESR?`.
- **Enable write** — `EventRegs_EventEnableReg_SetBits` @`0x4f1f2`: stores the enable mask
  and re-evaluates `(event & enable)` → updates `word_3` and rolls the summary bit up or
  down in the parent immediately.

Related bit ops: `EventRegs_ConditionReg_SetBits`/`ClearBits`/`ToggleBits`
(`0x4f084`/`0x4f0f2`/`0x4f044`) take a node+mask directly (used by subsystems that own a
specific bit, e.g. compliance in `SOURCE_COMPLIANCE_UPDATE_STATUS`).

---

## 6. `gEventRegs_BitTable` @`0x67658`

Array of `{EVENT_REGS_STRUCT *node; word mask}` (6 bytes/entry), **indexed by the
`ERR_INDEX_ENUM` ordinal**. It is the master map from a status/error code to *which
register and which bit* it drives. `UpdateSet(code)` / `UpdateClear(code)` /
`SET_ERROR(code)` all index it. (143 entries, matching the error table in
`firmware_errors.py` @`0x679B2`.)

---

## 7. Error/event queue & EAV

Two distinct queues, both cleared by `*CLS`:

- **Status/error-code queue** — `gSTATUS_QUEUE` @`0x803848` (circular, 10 deep;
  head `0x805a9d`, tail `0x803870`). `STATUS_QUEUE_PUSH` @`0x4f406` enqueues an
  `ERR_INDEX` code, substituting `ERR_INDEX_n350_QUEUE_OVERFLOW` when full, then asserts
  **STB EAV (b2)** via `EventRegs_RS232_SRQ_ON(4)`. Read/drained by `STATUS_QUEUE_POP`
  @`0x4f49c` / `_COUNT` @`0x4f50a`; `_CLEAR` @`0x4f3ea`.
- **`:SYST:ERRor` message queue** — fed by `QUEUE_MESSAGE_PUSH` from
  `EventReg_SET_ERROR` @`0x4efd4`, the standard error-report entry point:
  1. if remote and the error class is `ERROR_EVENT_EE`, beep;
  2. set the mapped condition+event bit (rolls up to ESR→STB);
  3. push the message;
  4. clear the *condition* bit (a pulse — the latched event remains).

`EventReg_REPORT_ERROR` @`0x4ef42` is the thinner "report this code" wrapper.

---

## 8. Command surface (`:STATus` + common)

| Command | Handler / helper |
|---|---|
| `*STB?`, serial poll | `EventRegs_SerialPoll_STB_Read` `0x4f35c` (via `EXECUTE_COMMAND_QUERY` @`0x216ec`) |
| `*SRE` / `*SRE?` | `EventRegs_SRE_Write` `0x4f2b0` (@`0x17aac`) / `EventRegs_SRE_Read` `0x4f3a2` (@`0x216b0`) |
| `*ESR?` | `EventRegs_StatusRegister` `0x4f260` on `gEventStructRegister_Standard` |
| `*ESE` / `*ESE?` | `EventRegs_EventEnableReg_SetBits` `0x4f1f2` / `EventRegs_StatusEnableRegister` `0x4f2a4` |
| `:STAT:<reg>:COND?` | `EventRegs_ConditionRegister` `0x4f256` |
| `:STAT:<reg>:EVENt?` | `EventRegs_StatusRegister` `0x4f260` (read-and-clear) |
| `:STAT:<reg>:ENABle[?]` | `EventRegs_EventEnableReg_SetBits` / `EventRegs_StatusEnableRegister` |
| `:STAT:PRESet` | `EventRegs_STATUS_PRESET` `0x4ee5a` (zeros OPER/QUES/MEAS enables + queue-enable default) |
| `:STAT:QUEue[:NEXT]?` / `:CLEar` | `STATUS_QUEUE_POP` / `STATUS_QUEUE_CLEAR` |
| `*CLS` | `EventRegs_reset_CLS` `0x4ee7a` (read-clears OPER/MEAS/QUES/ESR events + both queues) |
| (boot) | `EventRegs_initialize` `0x4ee14` (PRESET + CLS + zero condition regs; PON set) |

`:STAT:<reg>` command tokens: `COMMAND_STB` `0x63616`, `COMMAND_SRE` `0x63628`,
`COMMAND_ESR` `0x636a6`, `COMMAND_ESE` `0x636b8`, `COMMAND_STATUS` `0x61108`,
`COMMAND_CONDITION` `0x60e1e`. No `:PTR`/`:NTR` tokens (§5).

Register set (`:OPER`/`:QUES`/`:MEAS`) is selected by passing the matching ROM node
(`gEventStructRegister_*`) to the shared helper above.

---

## 9. Relationship to the per-reading 24-bit measurement status word

Distinct from everything above: each **reading** carries a 24-bit *status element*
(`gMEASUREMENT_STATUS_WORD` @`0x80386c`, built by `BUILD_MEASUREMENT_STATUS_WORD`
@`0x16540`) describing that one measurement — range, compliance, overflow, filter, source
on/off, limit-test results, etc. (see `SUMMARY.md` §STATus data element / [MEASURE.md](MEASURE.md)).
That word is a **data field appended to readings** (controlled by `:FORMat:ELEMents STATus`);
it is *not* part of the IEEE-488.2 summary-register tree in this document. The two only
touch where a measurement condition (e.g. reading available/overflow) is also reported into
the **Measurement Event** register (§4) via `gEventRegs_BitTable`.

---

## 10. SRQ generation (ties to GPIB)

SRQ is asserted entirely through the STB roll-up:

- `EventRegs_RS232_SRQ_ON(mask)` @`0x4f136`: set STB event bits; write the low byte to
  `TMS9914A.x_SerialPoll`; if `(event & enable)` matches, set `word_3`, raise the SRQ
  annunciator (SCPI mode), and pulse `TMS9914A.BusStatus_AuxCmd = SET | RSV2` (request
  service). `EventRegs_RS232_SRQ_OFF` @`0x4f192` clears.
- `EventRegs_SRE_Write` and `EventRegs_SerialPoll_STB_Read` recompute MSS/RQS and
  assert/clear `RSV2` on the TMS9914A accordingly.

See [GPIB.md](GPIB.md) §7 for the TMS9914A serial-poll register and the SRQ line. (Despite
the `RS232_` prefix in the helper names, these drive the GPIB serial-poll/SRQ hardware;
the branch on `gCONFIG_COMM.commMode` handles the RS-232 MAV case.)

---

## 11. Key symbols (quick reference)

**Register banks (RAM):** STB `gEvent_RootRegisters` `0x8050f0` · ESR
`gEvent_StandardRegisters` `0x805824` · OPER `gEvent_OperationRegisters` `0x804808` ·
QUES `gEvent_QuestionableRegisters` `0x804810` · MEAS `gEvent_MeasurementRegisters`
`0x804800`.

**ROM tables:** nodes `gEventStruct_root` `0x67612` + `gEventStructRegister_*`
`0x6761c`/`0x67630`/`0x67644`/`0x6764e` · `gEventRegs_BitTable` `0x67658`.

**Core helpers:** `EventReg_ConditionReg_UpdateSet` `0x4efa8` ·
`EventReg_ConditionReg_UpdateClear` `0x4ef7c` · `EventRegs_ConditionReg_SetBits` `0x4f084`
· `EventRegs_ConditionReg_ClearBits` `0x4f0f2` · `EventRegs_StatusRegister` `0x4f260` ·
`EventRegs_EventEnableReg_SetBits` `0x4f1f2` · `EventRegs_ConditionRegister` `0x4f256` ·
`EventRegs_StatusEnableRegister` `0x4f2a4`.

**STB/SRE/SRQ:** `EventRegs_SRE_Write` `0x4f2b0` · `EventRegs_SRE_Read` `0x4f3a2` ·
`EventRegs_SerialPoll_STB_Read` `0x4f35c` · `EventRegs_RS232_SRQ_ON` `0x4f136` ·
`EventRegs_RS232_SRQ_OFF` `0x4f192`.

**Lifecycle/queue/error:** `EventRegs_initialize` `0x4ee14` · `EventRegs_reset_CLS`
`0x4ee7a` · `EventRegs_STATUS_PRESET` `0x4ee5a` · `EventReg_SET_ERROR` `0x4efd4` ·
`EventReg_REPORT_ERROR` `0x4ef42` · `STATUS_QUEUE_PUSH/POP/COUNT/CLEAR`
`0x4f406`/`0x4f49c`/`0x4f50a`/`0x4f3ea` · `gSTATUS_QUEUE` `0x803848`.

**Per-reading status (distinct):** `gMEASUREMENT_STATUS_WORD` `0x80386c` ·
`BUILD_MEASUREMENT_STATUS_WORD` `0x16540`.
