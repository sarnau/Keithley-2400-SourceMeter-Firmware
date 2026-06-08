# Keithley 2400 — GPIB Driver (TMS9914A) Reverse-Engineering Notes

How the firmware drives the IEEE-488 / GPIB interface. The controller is a **TI TMS9914A**
("9914 GPIA"). Addresses are Ghidra addresses = file offsets in `2400-FIRMWARE.bin` (flat image,
MC68332 / CPU32, big-endian). See [DATASHEETS.md](DATASHEETS.md) (TMS9914A chapter) for the
register/bit reference and [SCPI.md](SCPI.md) for what happens to received bytes afterwards.

> **Address note:** the chip is at **`0x900000`**, not the `0x090000` printed in
> [README.md](README.md) (the README dropped a digit — same as main RAM being at `0x800000`,
> not `0x080000`). All register accesses below use base `0x900000`.

---

## 1. Hardware

- **TMS9914A** GPIB controller, memory-mapped at **`0x900000`–`0x900007`** (8 byte-wide registers;
  read and write registers share offsets, selected by R/W).
- Bus transceivers: **SN75160** (8 data lines DIO1–8) + **SN75161** (8 management lines
  ATN/EOI/SRQ/REN/IFC/DAV/NRFD/NDAC).
- `INT` pin → **CPU IRQ level 3**.
- The 2400 operates as a **bus device** (talker / listener), not the active controller.

### Register map (as used by the firmware)

| Off | Addr | Read | Write | Firmware use |
|---|---|---|---|---|
| 0 | `0x900000` | Int Status 0 | Int Mask 0 | BI/BO/END/SPAS/INT0/INT1 interrupts |
| 1 | `0x900001` | Int Status 1 | Int Mask 1 | GET/DCAS/MA/IFC (`0x8D` mask) |
| 2 | `0x900002` | Address Status | — | REM/TADS/LADS/ATN sensing |
| 3 | `0x900003` | Bus Status | **Aux Command** | the workhorse — 157 of 238 refs |
| 4 | `0x900004` | — | Address | primary address (`addr & 0x1F`) |
| 5 | `0x900005` | — | Serial Poll | status byte / SRQ (`rsv`) |
| 6 | `0x900006` | Cmd Pass Through | Parallel Poll | |
| 7 | `0x900007` | Data In | Data Out | byte RX / TX |

Ghidra has a `TMS9914A` struct over this range plus `TMS9914A_AUXCMD_*`,
`TMS9914A_IntStatus0_*`, `TMS9914A_AddressStatus_*` enums. Driver functions are named
`TMS9914A_*`; the main driver cluster is `0x3576C–0x3685A`.

---

## 2. Interrupt path (IRQ level 3)

```
TMS9914A INT  ──►  CPU32 IRQ level 3  ──►  autovector 27 (VBR 0x4000 + 27*4)  =  0x35EA2
```

`0x35EA2` is a thin ISR shell that dispatches through a **swappable RAM function pointer**:

```
00035ea2: movem.l {A0},-(SP)
00035ea6: movea.l (0x00801378).l,A0     ; A0 = current GPIB ISR handler
00035eac: jsr     (A0)
00035eae: movem.l (SP)+,{A0}
00035eb2: rte
```

`0x801378` selects the handler by protocol mode (`gCONFIG_COMM.SYSTEM_MEP_STATE`):
- **SCPI mode** → `TMS9914A_SCPI_EXCEPTION_LEVEL_3` (`0x35EE6`)
- **IEEE-488.1 / MEP mode** → an alternate handler (cf. `TMS9914A_488_1_CALLBACK_CONTINUE`)

All other IRQ levels (1,2,4–7) point to a default stub at `0x4F78`.

---

## 3. Initialization — `TMS9914A_SCPI_Set_Adr(addr)` (`0x35764`)

1. Assert `swrst` (software reset).
2. Cycle/clear all aux-command latches (RTL, LON, TON, RPP, SIC, SRE, DAI, SHDW, HDFE/HDFA,
   STDL, VSTDL …) to a known state.
3. Set talker/listener Address Status; program **T1 source-settling** (`STDL` then `VSTDL`).
4. Enable interrupts: `IntMask0 = BI | BO | END | SPAS | INT0 | INT1`; `IntMask1 = 0x8D`.
5. Program the **primary GPIB address = `addr & 0x1F`** (Address register, `0x900004`).
6. Release `swrst` → controller online.

(A separate early boot-time GPIB bring-up lives around `0x1464–0x15BE`.)

---

## 4. ISR — `TMS9914A_SCPI_EXCEPTION_LEVEL_3` (`0x35EE6`)

Reads `IntStatus0` (accumulated into `gGPIB_TMS9925A_IntStatus0`) and `IntStatus1`
(`BYTE_0080023D & 0x8D`) and services each source:

### IntStatus0
| Bit | Event | Handling |
|---|---|---|
| **BI** | Byte In | read `DataIn` → push to `gGPIB_RECEIVE_BUFFER` ring; issue `RHDF`; mark end on LF/EOI |
| **BO** | Byte Out | output state machine sends next TX byte (see §6) |
| **END** | Last byte (EOI) | kick command processing (`FUN_0003B418`) |
| **SPAS** | Serial Poll Active | device transmits its status byte |
| **INT1** | REM/LOCAL change | not-REM → `SWITCH_TO_LOCAL_CONTROL` + clear REM annunc.; REM → set REM\|LISTEN; `NBAF` |
| **INT0** | Talk/Listen addressing | set/clear TALK & LISTEN annunc. from `AddressStatus.TADS` |

### IntStatus1 (`& 0x8D`)
| Bit | Event | Handling |
|---|---|---|
| `0x80` | **GET** (Group Execute Trigger) | inject `0x0404` trigger marker into RX stream + `DACR` |
| `0x08` | **DCAS** (Device Clear) | device-clear handler `TMS9914A_000363AA`, reset flags |
| `0x04` | **MA** (My Address) | reconfigure `IntMask0`, talk/listen setup, `DACR`/`NBAF` |
| `0x01` | **IFC** (Interface Clear) | reconfigure masks, mass-clear annunciators, `RHDF`/`DACR`/`NBAF` |

---

## 5. Receive ring buffer

`gGPIB_RECEIVE_BUFFER` is a **2048-entry ring** of 16-bit words:
- indices `gGPIB_RECEIVE_BUFFER_HEAD` / `_TAIL`, masked **`& 0x7FF`**
- each entry: **low byte = data**, **high byte = flag/type**
  - `0x0101` — EOI / end-of-message marker (also produced when the data byte is **LF `0x0A`**)
  - `0x0404` — GET-trigger / device-clear control marker injected inline
- on each received byte the ISR issues **`RHDF`** (release RFD holdoff) to accept the next byte;
  if `HEAD+1 == TAIL` the buffer is full → overflow flag.

**Producer** = the ISR (fills HEAD). **Consumer** = `COMM_PARSER_STATE_PROCESS_NEXT`, which drains
from TAIL via the `gGPIB_GET_BYTE` function pointer and feeds the SCPI parser ([SCPI.md](SCPI.md) §3).
RX and command execution are thus decoupled.

---

## 6. Transmit path

On each **BO** interrupt the output state machine streams one byte from `PTR_00801302`
(remaining count `WORD_008012FC`) to `DataOut` (`0x900007`). When the buffer empties it terminates
the response with **LF + EOI** via `GPIO_DATA_SEND_LF_AND_EOI_0003B358` / `GPIO_DATA_OUT_RESPONSE`.
Response strings come from the SCPI executor's result builder (`COMM_BUILD_RESULTSTR`).

---

## 7. Serial poll / SRQ

- The status byte is written to the **Serial Poll register** (`0x900005`); **SRQ** is asserted via
  the `rsv` request-service bit.
- Managed by `EventRegs_*_SRQ_ON/OFF` (`0x4F136` / `0x4F158`), wired into the SCPI status model
  (Status Byte Register, see [SUMMARY.md](SUMMARY.md) status section).
- Front-panel annunciators **REM / TALK / LISTEN / SRQ** (`gDISP_ANNUTATIONS`) mirror live bus state.

---

## 8. Flow control & aux commands

All handshake/flow control is issued through the **Aux Command register `0x900003`**:

| Aux cmd | Use |
|---|---|
| `RHDF` | release RFD holdoff (per received byte) |
| `DACR` | release DAC holdoff after command-class interrupts (GET/MA/DCAS/APT) |
| `NBAF` | cancel a pending/unsent TX byte (e.g. on ATN/addressing change) |
| `HDFE` / `HDFA` | holdoff-on-EOI / holdoff-on-all-data modes |
| `STDL` / `VSTDL` | short / very-short T1 source-settling time |
| `RTL` | return to local |
| `SIC` / `SRE` | system-controller (IFC/REN) — present but the 2400 is normally a device |

---

## 9. Key addresses

| Symbol | Address | Notes |
|---|---|---|
| TMS9914A registers | `0x900000`–`0x900007` | base (README's `0x090000` is wrong) |
| IRQ3 autovector | `0x4000 + 27*4` | → `0x35EA2` |
| ISR shell | `0x35EA2` | indirect via `0x801378` |
| GPIB ISR handler ptr | `0x801378` (RAM) | SCPI vs 488.1 handler |
| `TMS9914A_SCPI_EXCEPTION_LEVEL_3` | `0x35EE6` | main SCPI interrupt handler |
| `TMS9914A_SCPI_Set_Adr` | `0x35764` | init / set primary address |
| `TMS9914A_Return_to_local` | `0x35E86` | writes `RTL` (0x07) to AuxCmd |
| `TMS9914A_000363AA` | `0x363AA` | device-clear (DCAS) handler |
| `gGPIB_RECEIVE_BUFFER` | (RAM) | 2048-entry RX ring, idx `&0x7FF` |
| `gGPIB_RECEIVE_BUFFER_HEAD/TAIL` | (RAM) | ring indices |
| `gGPIB_GET_BYTE` | (RAM fn-ptr) | parser-side RX byte fetch |
| `PTR_00801302` / `WORD_008012FC` | (RAM) | TX buffer pointer / remaining count |
| default IRQ stub | `0x4F78` | all non-GPIB IRQ levels |

---

## 10. Relationship to the rest of the comms stack

```
                         ┌─ GPIB: TMS9914A IRQ3 ISR (0x35EE6) ─► gGPIB_RECEIVE_BUFFER (2K ring)
input bytes ─────────────┤
                         └─ RS-232: QSM SCI (MAX202/ADM202) ──► RS-232 rcv buffer
                                              │
                                              ▼
                         COMM_PARSER_STATE_PROCESS_NEXT (0x2D242)   ← gCONFIG_COMM.commMode
                                              │  (drains via gGPIB_GET_BYTE / RS232_GET_BYTE)
                                              ▼
                         SCPI parser → dispatch → handler            (see SCPI.md)
                                              │
                                              ▼
                         response → TX: GPIB BO state machine (LF+EOI) / RS-232 TX
```

Both interfaces feed the **same** SCPI parser/executor; only the byte transport differs.
RS-232 (the QSM SCI path) is the natural next thing to document.
