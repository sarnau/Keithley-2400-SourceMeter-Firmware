# Keithley 2400 SourceMeter — Component Datasheet Summary

Condensed, reverse-engineering-oriented summaries of the **component datasheets** in the
[`datasheets/`](datasheets/) directory. The focus is each chip's role in the instrument and the
register/protocol/programming details that surface when reverse-engineering the firmware in Ghidra.
See [CLAUDE.md](CLAUDE.md) for project context, [README.md](README.md) for the hardware/memory map,
and [SUMMARY.md](SUMMARY.md) for the instrument manuals.

## Chip roster & board roles

| Chip | Ref des | Role | Firmware-visible? |
|------|---------|------|-------------------|
| **MC68332** | U3 | Main CPU (CPU32 core + SIM + QSM + TPU) | Yes — registers at `$FFF000–$FFFFFF` |
| **TPU** (in MC68332) | — | Front-panel display serial link + DAC/analog interfacing | Yes — `$FFFE00`, parameter RAM |
| **TMS9914A** | U13 | GPIB/IEEE-488 controller | Yes — mapped at `0x090000` |
| **24LC16B** | U17 | 2 KB I²C EEPROM: all calibration + config | Yes — via I²C bit-bang/QSPI |
| **TC551001** ×2 | U12/U14 | 128 KB battery-backed main SRAM | Yes — data bus |
| **DS1236** | — | Power supervisor: reset, watchdog, battery switchover | Yes — watchdog must be petted |
| **ADM202 / MAX202** | U4 | RS-232 line driver/receiver | No (analog level shifter) |
| **SN75161B** (+ SN75160) | U6/U20 | GPIB bus transceivers | No (bus buffers) |
| **AQVV201A** | K2xx | PhotoMOS isolated relays (analog range/signal switching) | Indirectly (driven via control lines) |
| **UDN2549EB** | U7 | Protected quad power driver (rear Digital I/O outputs) | Indirectly |

---

# Table of Contents

1. [Motorola MC68332 (Main CPU)](#motorola-mc68332-main-cpu)
2. [Motorola TPU (Time Processor Unit)](#motorola-tpu-time-processor-unit)
3. [TI TMS9914A (GPIB/IEEE-488 Controller)](#ti-tms9914a-gpibieee-488-controller)
4. [Memory & Configuration Storage](#memory--configuration-storage) (24LC16B, TC551001, DS1236)
5. [Interface & Driver Support Chips](#interface--driver-support-chips) (ADM202, SN75161B, AQVV201A, UDN2549EB)

---

## Motorola MC68332 (Main CPU)

The MC68332 is a 32-bit modular microcontroller from Motorola's M68300 family, built around a **CPU32 core** (an instruction-compatible superset of the MC68000/68010, with many MC68020 extensions). On-chip modules — CPU32, SIM, QSM, TPU, and TPURAM — communicate over a standardized **Intermodule Bus (IMB)** with 24 address lines and 16 data lines.

### 1. Architecture / Block Diagram

| Module | Role |
|---|---|
| **CPU32** | Instruction processor; M68000-family core with BDM debug, loop mode, TBL/LPSTOP instructions |
| **SIM** (System Integration Module) | System config & protection, clock synthesizer (PLL), external bus interface, 12 chip-selects, periodic interrupt timer, watchdog, ports E/F/C |
| **QSM** (Queued Serial Module) | QSPI (synchronous SPI) + SCI (asynchronous UART/RS-232) |
| **TPU** (Time Processor Unit) | 16 autonomous timer channels with microcoded time functions, own parameter RAM |
| **TPURAM** | 2-Kbyte static RAM, usable as standby RAM or TPU microcode emulation RAM |

External bus signals of interest: `AS`, `DS`, `R/W`, `SIZ[1:0]`, `DSACK[1:0]`, `BERR`, `HALT`, `AVEC`, `RMC`, `FC[2:0]` (function codes / address space), `IRQ[7:1]`, `RESET`, `CLKOUT`. Dynamic bus sizing (8/16-bit ports via `DSACK`/`SIZ`). Big-endian (lower address = higher-order byte).

### 2. Memory Map & Module Mapping (MM bit)

All on-chip module control registers occupy a **4-Kbyte block** whose location is set by the **MM (Module Mapping) bit** in SIMCR:
- **MM = 1** → modules at **$FFF000–$FFFFFF** ← *this is what the Keithley firmware uses*
- **MM = 0** → modules at **$7FF000–$7FFFFF**

MM can be written only once after reset.

| Module | Base (MM=1) | Size |
|---|---|---|
| **SIM** | **$FFFA00** | 128 B |
| **TPURAM control** | **$FFFB00** | 64 B |
| **QSM** | **$FFFC00** | 512 B |
| **TPU** | **$FFFE00** | 512 B (ends $FFFFFF) |

The 2-Kbyte TPURAM **array** is mapped separately by TRAMBAR (programmable base), not inside this block. (Per the README, internal modules are at `0xFFF000–0xFFFFFF` and TPU RAM at `0xF00000–0xF007FF`.)

#### Exception Vector Table (CPU32)

256 vectors × 4 bytes = 1024 B. Vector address = `VBR + (vector_number × 4)`. After reset VBR=0, so the table is at `$000000` until relocated.

| Vec # | Offset | Assignment |
|---|---|---|
| 0 | $000 | Reset: Initial SSP |
| 1 | $004 | Reset: Initial PC |
| 2 | $008 | Bus Error |
| 3 | $00C | Address Error |
| 4 | $010 | Illegal Instruction |
| 5 | $014 | Zero Division |
| 6 | $018 | CHK, CHK2 |
| 7 | $01C | TRAPcc, TRAPV |
| 8 | $020 | Privilege Violation |
| 9 | $024 | Trace |
| 10 | $028 | Line 1010 Emulator (A-line) |
| 11 | $02C | Line 1111 Emulator (F-line) |
| 12 | $030 | Hardware Breakpoint |
| 14 | $038 | Format Error |
| 15 | $03C | Uninitialized Interrupt |
| 24 | $060 | Spurious Interrupt |
| 25–31 | $064–$07C | Level 1–7 Interrupt Autovectors |
| 32–47 | $080–$0BC | TRAP #0–#15 Instruction Vectors |
| 64–255 | $100–$3FC | User-defined (192 interrupt vectors) |

### 3. SIM — System Integration Module (base $FFFA00)

Key registers (MM=1 addresses):

| Addr | Reg | Function |
|---|---|---|
| $FFFA00 | **SIMCR** | Module config: EXOFF, FRZSW, FRZBM, SLVEN, SHEN, SUPV, **MM**, IARB. Reset $00CF |
| $FFFA04 | **SYNCR** | Clock synthesizer control |
| $FFFA07 | **RSR** | Reset Status: EXT,POW,SW,HLT,LOC,SYS,TST flags |
| $FFFA21 | **SYPCR** | System Protection Control: SWE,SWP,SWT,HME,BME,BMT (write-once) |
| $FFFA22 | PICR | Periodic Interrupt Control: PIRQL, PIV |
| $FFFA24 | PITR | Periodic Interrupt Timer |
| $FFFA27 | SWSR | Software watchdog Service (write $55 then $AA) |
| $FFFA41 | PORTC | Port C data (chip-select discrete outputs) |
| $FFFA44/46 | **CSPAR0/1** | Chip-select pin assignment |
| $FFFA48 | **CSBARBT** | Boot ROM chip-select base addr (reset block size 1 MB) |
| $FFFA4A | **CSORBT** | Boot ROM chip-select option |
| $FFFA4C–$FFFA74 | CSBAR0–10 | CS base address regs |
| $FFFA4E–$FFFA76 | CSOR0–10 | CS option regs |

#### System Clock / PLL (SYNCR @ $FFFA04)
Clock source set by **MODCLK pin at reset** (1 → on-chip PLL from 32.768 kHz crystal; 0 → external clock). `F_SYSTEM = F_REF × [4 × (Y+1) × 2^(2W+X)]`. The **16.78 MHz** Keithley system clock = 32768 Hz × 512 (Y=$0F, W:X=11).

#### Chip Selects (CSBOOT, CS0–CS10)
Each CS has a base-address register (CSBAR) + option register (CSOR); a match drives the CS, can generate `DSACK`/`AVEC` internally, and inserts 0–13 wait states. **This is how external FLASH, RAM, the TMS9914A, and the EEPROM get decoded.**

CSBAR block-size field (BLKSZ): 000=2K, 001=8K, 010=16K, 011=64K, 100=128K, 101=256K, 110=512K, 111=1M.

CSOR fields: MODE (async/sync-ECLK), BYTE (off/lower/upper/both — selects 8- vs 16-bit + enables CS), R/W, STRB (AS vs DS), DSACK (0–13 wait/fast/external), SPACE (CPU/user/supv/both), IPL, AVEC.

CSPAR pin-assignment (2 bits/pin): 00 discrete output, 01 alternate function, 10 chip-select (8-bit port), 11 chip-select (16-bit port).

**Boot:** out of reset only `CSBOOT` is enabled (base $000000, 1 MB, 13 wait states). **DATA0 at reset** sets boot port width (high → 16-bit, low → 8-bit) — how the firmware ROM is fetched (reset vector at $000000).

#### System Protection (SYPCR @ $FFFA21, write-once)
- **Software watchdog** (SWE/SWP/SWT): service by writing $55 then $AA to SWSR. (Distinct from the external DS1236 watchdog.)
- **Bus monitor** (BME/BMT): asserts BERR after N clocks with no DSACK/AVEC.
- **Halt monitor** (HME); **spurious-interrupt monitor**.

### 4. QSM — Queued Serial Module (base $FFFC00)

| Addr | Reg | Function |
|---|---|---|
| $FFFC00 | QSMCR | Config |
| $FFFC04 | QILR/QIVR | Interrupt level/vector |
| $FFFC08 | **SCCR0** | SCI baud: `Baud = SysClk / (32 × SCBR)` |
| $FFFC0A | **SCCR1** | SCI control: M(8/9-bit), PE/PT (parity), TIE,TCIE,RIE,ILIE,TE,RE,RWU,SBK |
| $FFFC0C | **SCSR** | SCI status: TDRE,TC,RDRF,RAF,IDLE,OR,NF,FE,PF |
| $FFFC0E | **SCDR** | SCI data (RDR read / TDR write) |
| $FFFC18–1E | SPCR0–3/SPSR | QSPI control/status |
| $FFFD00–$FFFD4F | RR/TR/CR | QSPI Receive/Transmit/Command RAM (16 entries each) |

- **SCI** = the RS-232 UART (8/9-bit NRZ async, optional parity). RXD dedicated; TXD shared with PQS7.
- **QSPI** = synchronous 3-wire SPI, 8–16-bit transfers, 16-entry queue, 4 chip-selects PCS0–3. *(A likely path for talking to the 24LC16B EEPROM or other serial peripherals — verify in the disassembly.)*

### 5. CPU32 Core (for disassembly)
- **Registers:** D0–D7, A0–A6, A7 (USP/SSP), PC; supervisor adds SSP, full SR, **VBR**, SFC/DFC.
- **SR:** T[1:0] (trace), S (supervisor), IP[2:0] (interrupt mask) + CCR (X,N,Z,V,C).
- **Instruction set** — between 68010 and 68020. Adds **LPSTOP**, **TBL/TBLS/TBLU** (table lookup+interpolate), 68020 addressing extensions/scaled indexing, **loop mode** (single-word instr + `DBcc` with displacement −4 = $FFFC), BCD ops.
- **Exceptions:** SR saved, S set, trace cleared; interrupt vector fetched via CPU-space IACK; min stack frame (SR+PC) pushed; vector → PC. IRQ[7:1] autovectored (vectors 25–31) or externally vectored.
- **Background Debug Mode (BDM):** entered when **BKPT asserted at rising edge of RESET**, or via **BGND instruction ($4AFA)**, double bus fault, or peripheral breakpoint. Serial interface on DSCLK/DSI/DSO (shared BKPT/IFETCH/IPIPE), 10-pin BDM connector. Commands: RDREG/WDREG, RSREG/WSREG, READ/WRITE, DUMP/FILL, GO, CALL, RST, NOP. Useful for live dumping/tracing the firmware.

### Key takeaways for RE
- On-chip registers at **$FFF000–$FFFFFF** (MM=1): SIM $FFFA00, QSM $FFFC00, TPU $FFFE00, TPURAM ctl $FFFB00.
- Reset vector fetched from **$000000** via CSBOOT; **DATA0 at reset** = ROM width (8/16-bit).
- External FLASH/RAM/GPIB/EEPROM decoded by **CSBAR/CSOR** pairs at $FFFA48–$FFFA76.
- 256×4-byte vector table, relocatable via VBR.
- 16.78 MHz from 32.768 kHz crystal via PLL (SYNCR @ $FFFA04).
- RS-232 = SCI (`SysClk/(32×SCBR)`, $FFFC08–$FFFC0E).
- BDM available via BKPT-at-reset.

---

## Motorola TPU (Time Processor Unit)

The TPU is an intelligent, semi-autonomous **timer coprocessor** integrated into the MC68332. It runs concurrently with the CPU32, executing microcoded "time functions" on its 16 channels to perform timing-intensive I/O, period/pulse measurement, waveform generation, and even serial communication — all with minimal CPU intervention. In the Keithley 2400 it drives the **serial link to the front-panel display** and **DAC/analog-board interfacing**.

### Architecture

| Component | Description |
|---|---|
| **Timer channels (16)** | CH0–CH15, identical/orthogonal, each tied to one MCU pin. Each has a 16-bit capture register, a 16-bit compare/match register, and a comparator + pin logic. 17 external pins (TPUCH0–15 + T2CLK). |
| **Time bases TCR1 / TCR2** | Two free-running 16-bit counters. TCR1 from system clock via prescaler; TCR2 from external **T2CLK** or system clock (T2CG bit). |
| **Microengine** | 2 KB micro-ROM (512 long words) + execution unit; runs the pre-programmed time functions. **Emulation mode** runs microcode from on-chip TPURAM instead. |
| **Scheduler** | Out of reset all channels disabled; CPU activates a channel by assigning a priority (high/middle/low); scheduler time-slices by priority then channel number. |
| **Parameter RAM** | Dual-ported work/communication area between CPU and TPU. |

Coherency: use a **long-word** access for guaranteed 32-bit coherency on adjacent parameter words.

### Host Interface Registers (block $FFFE00, 16-bit)

| Offset | Register | Purpose |
|---|---|---|
| $FFFE00 | **TPUMCR** | Config: STOP, TCR1 prescaler (PSCK, TCR1P), TCR2 prescaler, **EMU** (emulation), T2CG, SUPV, IARB |
| $FFFE08 | **TICR** | Interrupt config: CIRL (level), **CIBV** (channel interrupt base vector) |
| $FFFE0A | **CIER** | Channel Interrupt Enable (1 bit/channel) |
| $FFFE0C | **CFSR0** | Channel Function Select — 4-bit code for CH15,14,13,12 |
| $FFFE0E | **CFSR1** | Function select CH11,10,9,8 |
| $FFFE10 | **CFSR2** | Function select CH7,6,5,4 |
| $FFFE12 | **CFSR3** | Function select CH3,2,1,0 |
| $FFFE14 | **HSQR0** | Host Sequence bits (2/ch) CH15..8 |
| $FFFE16 | **HSQR1** | Host Sequence bits CH7..0 |
| $FFFE18 | **HSRR0** | Host Service Request bits (2/ch) CH15..8 |
| $FFFE1A | **HSRR1** | Host Service Request bits CH7..0 |
| $FFFE1C | **CPR0** | Channel Priority (2/ch) CH15..8 |
| $FFFE1E | **CPR1** | Channel Priority CH7..0 |
| $FFFE20 | **CISR** | Channel Interrupt Status (1/ch; byte-accessible) |

*(Offsets shown relative to the MC68332 TPU base $FFFE00; the reference manual prints them as `$###E0x`.)*

**Programming model the firmware follows** (per channel N):
1. Write a 4-bit **function code** into the channel's nibble of the appropriate **CFSRx**.
2. Write function-specific **Host Sequence** bits (HSQR0/1) — selects a mode/sub-mode.
3. Initialize the channel's **parameter RAM** (modes, periods, pin actions).
4. Write **Host Service Request** bits (HSRR0/1) — typically "Initialize" — to kick the channel. Wait for the TPU to clear HSR back to `%00` before reissuing.
5. Assign a non-zero **priority** (CPR0/1) to activate. Priority encoding: `00`=disabled, `01`=low, `10`=middle, `11`=high.

Interrupts: CIRL sets request level for all channels; per-channel mask via CIER; status via CISR; vector = CIBV nibble ∥ channel number.

### Parameter RAM Layout
200 bytes (100 × 16-bit words) at the top of the TPU module space. **Channels 0–13 have 6 parameters each; CH14/15 have 8.** Not initialized by reset. Per-channel base = `channel# × $10`; parameter P at `base + P×2`. The first word **P0** almost always holds **CHANNEL_CONTROL** (low byte) encoding pin time-base/direction (TBS), pin-action edge/level (PAC), and forced pin-state (PSC).

Examples:
- **DIO:** P0 CHANNEL_CONTROL, P1 PIN_LEVEL, P2 MATCH_RATE.
- **UART receiver:** P0 PARITY_TEMP, P1 MATCH_RATE, P2 RECEIVE_DATA_REG (PE/FE flags in high bits), P3 DATA_SIZE, P4 ACTUAL_BIT_COUNT, P5 SHIFT_REGISTER.

### Standard Time Functions (microcode ROM library)
The 4-bit CFSR code selects the function. **Two ROM mask sets exist with different code→function maps** — the disassembly will reveal the codes, which map to one of these:

**Mask Set A:** $F PPWA, $E OC, $D SM (stepper), $C PSP, $B PMA/PMM (period meas), $A ITC (input capture/transition counter), $9 PWM, $8 **DIO** (discrete I/O), $7 SPWM, $6 QDEC (quadrature).

**Mask Set G:** $F PTA, $E QOM (queued output match), $D TSM, $C FQM, $B **UART** (async serial), $A NITC, $9 COMM, $8 HALLD, $7 MCPWM, $6 FQD.

**Relevance to the 2400:**
- The **front-panel display serial link** is most plausibly **UART** (async TX/RX, parity via host-sequence bits) — or a custom clocked protocol via **DIO/OC/QOM** driving data + clock lines.
- **DAC / serial-line control** (chip-selects, clock, data, latch strobes) is the classic **DIO** (static or transition/match-rate) + **OC/QOM** (precisely timed edges) use.
- Load-bearing RE artifacts: the **CFSR nibble** (function), **HSQR** bits (mode), **HSRR** bits (init/transmit), **CPR** bits (enable), and per-channel parameter-RAM writes at `TPU_base + ch×$10`.

### Emulation Mode / TPUMASM
ROM functions can be replaced/extended by custom microcode: set **EMU** in TPUMCR → the TPU executes microcode from **TPURAM** (which then leaves the CPU map). Custom functions are assembled with **TPUMASM.EXE** into an S-record loaded into TPURAM; Motorola's TPU Function Library supplies source for all ROM + extra functions. **Worth checking the disassembly for a TPURAM load + EMU-bit-set sequence at startup** — if present, the firmware uses custom TPU microcode.

---

## TI TMS9914A (GPIB/IEEE-488 Controller)

### Role
GPIB Adapter (GPIA) implementing the IEEE-488 talker/listener/controller protocol in hardware state machines (T/TE, L/LE, controller with pass control, system controller, serial & parallel poll, DT/DC, RL, and SH/AH handshakes). Protocol controller only — must be paired with bus transceivers (**SN75160** for the 8 data lines, **SN75161/162** for the 8 management lines).

**In the Keithley 2400:** U13, memory-mapped at **0x090000–0x090007** (8 byte-wide registers). The 3 address lines RS0–RS2 select the register; **the same offset selects a different register for reads vs writes**.

### Host interface essentials
- 8-bit data bus **D0–D7 where D0 = MSB, D7 = LSB** (reversed vs typical). GPIB side: D0↔DIO8 (MSB), D7↔DIO1 (LSB).
- MPU side positive logic; GPIB side negative logic (transceivers invert).
- Pins: **CE** (chip enable, active low), **WE** (write, active low), **DBIN** (read, active high), **RS0–RS2**, **INT** (open-drain — needs pull-up), **RESET**, **CLOCK** (500 kHz–5 MHz, async), **TR** (trigger output, pulses on GET/fget), **TE**, **CONT**, **ACCRQ/ACCGR** (DMA).

### Register map (**bit order D0 = MSB … D7 = LSB**; offsets = 0x090000 + N)

**READ registers**
| Off | Register | D0…D7 |
|----|----|----|
| 0 | **Int Status 0** | INT0, INT1, BI, BO, END, SPAS, RLC, MAC |
| 1 | **Int Status 1** | GET, ERR, UNC, APT, DCAS, MA, SRQ, IFC |
| 2 | **Address Status** | REM, LLO, ATN, LPAS, TPAS, LADS, TADS, ulpa |
| 3 | **Bus Status** | ATN, DAV, NDAC, NRFD, EOI, SRQ, IFC, REN |
| 4,5 | *(not decoded — Hi-Z; designs often map an external address-switch DIP here)* | |
| 6 | **Cmd Pass Through (CPT)** | DIO8…DIO1 |
| 7 | **Data In** | DIO8…DIO1 |

**WRITE registers**
| Off | Register | D0…D7 |
|----|----|----|
| 0 | **Int Mask 0** | xx, xx, BI, BO, END, SPAS, RLC, MAC |
| 1 | **Int Mask 1** | GET, ERR, UNC, APT, DCAS, MA, SRQ, IFC |
| 3 | **Auxiliary Command** | cs, xx, xx, f4, f3, f2, f1, f0 |
| 4 | **Address** | edpa, dal, dat, A5, A4, A3, A2, A1 |
| 5 | **Serial Poll** | S8, rsv1, S6, S5, S4, S3, S2, S1 |
| 6 | **Parallel Poll** | PP8…PP1 |
| 7 | **Data Out** | DIO8…DIO1 |

**Mask convention:** 1 = unmask (enable interrupt), 0 = mask. INT asserts when (Status AND Mask) ≠ 0 unless `dai` set.

**Status 0 bits:** INT0/INT1 (summary of unmasked Status0/Status1), **BI** (byte in — cleared by reading Data In or Status 0), **BO** (byte out / ready for next TX byte), **END** (last byte had EOI — read Data In *before* re-reading Status 0 to avoid stale BI), **SPAS** (serial-poll active), **RLC** (remote/local change), **MAC** (my-address change).

**Status 1 bits** (these cause a DAC holdoff when unmasked — release with `dacr`): **GET** (group execute trigger; pulses TR pin), **ERR** (no acceptors), **UNC** (unrecognized command — inspect via CPT), **APT** (secondary address pass-through — unmasking enables secondary addressing), **DCAS** (device clear), **MA** (my talk/listen address), **SRQ** (controller only), **IFC** (interface clear, non-system-controller).

**Address register:** edpa (dual primary addressing), dal/dat (disable listener/talker), A5–A1 primary address (11111 illegal). **Not cleared by swrst or hardware reset.**

**Serial Poll:** S8/S6–S1 status byte + **rsv1** (set → pulls SRQ true; cleared on poll). **Parallel Poll:** PP8–PP1 response on DIO during a parallel poll.

### Auxiliary Command codes (write offset 3; byte = cs·xx·xx·f4f3f2f1f0)
| f4..f0 | Mnemonic | Action | byte cs=0 / cs=1 |
|----|----|----|----|
| 00000 | **swrst** | Software reset | 0x00 / 0x80 |
| 00001 | **dacr** | Release DAC holdoff (cs = secondary valid) | 0x01 / 0x81 |
| 00010 | **rhdf** | Release RFD holdoff | 0x02 |
| 00011 | **hdfa** | Holdoff on all data | 0x03 / 0x83 |
| 00100 | **hdfe** | Holdoff on EOI only | 0x04 / 0x84 |
| 00101 | **nbaf** | New byte available false | 0x05 |
| 00110 | **fget** | Force group execute trigger | 0x06 / 0x86 |
| 00111 | **rtl** | Return to local | 0x07 / 0x87 |
| 01000 | **feoi** | Send EOI with next byte | 0x08 |
| 01001 | **lon** | Listen only | 0x09 / 0x89 |
| 01010 | **ton** | Talk only | 0x0A / 0x8A |
| 01011 | **gts** | Go to standby (drop ATN) | 0x0B |
| 01100 | **tca** | Take control asynchronously | 0x0C |
| 01101 | **tcs** | Take control synchronously | 0x0D |
| 01110 | **rpp** | Request parallel poll | 0x0E / 0x8E |
| 01111 | **sic** | Send interface clear (sys ctlr only) | 0x0F / 0x8F |
| 10000 | **sre** | Send remote enable (sys ctlr) | 0x10 / 0x90 |
| 10001 | **rqc** | Request control | 0x11 |
| 10010 | **rlc** | Release control | 0x12 |
| 10011 | **dai** | Disable all interrupts | 0x13 / 0x93 |
| 10100 | **pts** | Pass through next secondary | 0x14 |
| 10101 | **stdl** | Short T1 settling time | 0x15 / 0x95 |
| 10110 | **shdw** | Shadow handshake | 0x16 / 0x96 |
| 10111 | **vstdl** | Very short T1 delay | 0x17 / 0x97 |
| 11000 | **rsv2** | Request Service bit 2 | 0x18 / 0x98 |

Writes spaced ≥5 clock cycles. Hardware RESET clears all clear/set aux commands **except swrst (set true by RESET)**. `vstdl`/`rsv2` are '9914A additions.

### Programming model
- **Init:** assert `swrst` (0x80→off3); while held, write the primary address (off4), interrupt masks (off0/1), optional serial/parallel-poll responses; clear swrst (0x00→off3).
- **Send byte:** wait for **BO**; write byte to **Data Out** (off7); for last byte issue `feoi` (0x08) first; abort unsent byte with `nbaf`.
- **Receive byte:** wait for **BI**; read **Data In** (off7) (clears BI, releases normal holdoff); check **END** for EOI; if `hdfa`/`hdfe` active, explicitly release with `rhdf`.
- **Addressing:** chip auto-recognizes its MTA/MLA → **MA** interrupt + LADS/TADS in Address Status. Secondary addressing: unmask **APT**, read secondary from CPT, release with `dacr` (cs=1 valid).
- **Interrupts:** INT (open-drain) asserts on unmasked status; ISR reads Status 0/1 to find cause; command-class interrupts (GET/MA/DCAS/UNC/APT) auto-hold the bus — release with `dacr`. Inspect unknown commands via **CPT**.
- **Controller:** `tca`/`tcs` take control, `gts` drops ATN; serial poll on SRQ; parallel poll via `rpp`; system controller uses `sic`/`sre` (non-sys-ctlr devices must never issue these).
- **DMA:** ACCRQ/ACCGR; in DMA mode DBIN sense is inverted; keep MA unmasked.

### Electrical (brief)
Single +5 V; CLOCK 500 kHz–5 MHz async; TR pulse ≈5 clocks; IFC ≥100 µs on `sic`; T1 settling 11 clk default / 6 (`stdl`) / 3 (`vstdl`); INT open-drain.

---

## Memory & Configuration Storage

### Microchip 24LC16B

**Role:** U17 — 2 KB I²C serial EEPROM storing ALL calibration constants and system/user configuration. Nonvolatile (>200 yr, >1M cycles), survives power loss and battery death. The `24LC16B.bin` dump is decoded by [parse_flash.py](parse_flash.py). **Most important of the three for RE.**

| Parameter | Value |
|---|---|
| Capacity | 16 Kbit = 2 KB = 2048 × 8 |
| Organization | **8 blocks of 256 bytes** |
| Interface | 2-wire I²C (SCL, SDA), 100/400 kHz |
| Page buffer | **16-byte page** |
| Write cycle (Twc) | **5 ms max** |
| WP | VSS = writable; VCC = whole array (000–7FF) write-protected |

**Addressing (critical for the firmware decode):** the 2 KB space is NOT addressed by a 2-byte address. The upper 3 address bits fold into the I²C control byte:
- Control byte = `1 0 1 0 B2 B1 B0 R/W` — `1010` device code; **B2 B1 B0 = block-select = A10..A8** (which 256-byte block); R/W.
- A second byte = low 8 bits (A7..A0) within the block.
- **No separate device-address pinning** (A0–A2 pins unused) → only one 24LC16B per bus. Firmware reaches all 2048 bytes by varying B2..B0 across 8 control-byte values, each followed by an 8-bit offset.

**Operations:** byte write (→5 ms cycle); **page write** up to 16 bytes — only low 4 address bits auto-increment, so a page write **wraps within its 16-byte page** if it crosses a boundary (firmware must not straddle a 16-byte boundary); current-address read; random read (dummy write sets pointer, repeated START, read); sequential read (master ACKs to keep clocking, pointer auto-increments across whole device); **ACK polling** (device NAKs during the 5 ms write — poll for ACK to detect completion). Internal erase/write disabled below ~1.5 V.

### Toshiba TC551001

**Role:** U12 + U14 — two 128K×8 CMOS SRAMs forming the **128 KB, 16-bit-wide main RAM** (one per byte lane), battery-backed via the DS1236 to retain the reading buffer.

| Parameter | Value |
|---|---|
| Organization | **131,072 × 8 (128K × 8)**, A0–A16 |
| Supply | 5 V ±10% |
| Speed grades | 55 / 70 / 85 ns |
| Standby current | 10–100 µA |
| Data-retention supply (VDH) | **2.0 V min … 5.5 V max** |

**Control:** internal CE = (/CE1 low) AND (CE2 high); either /CE1 high or CE2 low → standby/Hi-Z. The DS1236 drives /CE1 (via /CEO) to deselect/protect on power-fail. Read: /CE1 L, CE2 H, /OE L, R/W H. Write: R/W L. To retain data the part must be deselected before VDD drops; VDD may then fall to 2.0 V on the backup battery.

### Dallas DS1236

**Role:** CPU/memory supervisor ("MicroManager"): power-on reset, battery-backup switchover for the SRAM, watchdog, and early-warning power-fail interrupt. 16-pin.

**Key pins:** VCC (+5), VBAT (+3, 2.7–4.0 V), VCCO (switched SRAM supply = greater of VCC/VBAT), /CEI & /CEO (gate SRAM CE, write-protect on power-fail), RST & /RST, **/ST (watchdog strobe)**, IN & /NMI (power-fail sense / NMI), /PBRST (pushbutton reset), RC (mode), WC//SC.

**Power monitor / reset:** VCC trip **VCCTP = 4.37 V typ** (DS1236-5: 4.62 V). Below VCCTP → RST/`/RST` active + SRAM unconditionally write-protected. On power-up RST held **25 ms min / 100 ms typ / 150 ms max** after VCC recovers.

**Watchdog (firmware constraint):** forces reset if `/ST` is not driven low within the timeout. **`tTD` = 400 ms typ, 600 ms max, 100 ms min.** Kick = high-to-low transition on `/ST` (≥20 ns). **Firmware MUST pet the watchdog (toggle `/ST`) well within ~100 ms or the CPU resets** — long blocking operations must periodically kick it. (This is separate from the internal MC68332 SIM software watchdog.)

**Power-fail / NMI:** IN compared to **VTP = 2.54 V typ** via an external divider; on decay `/NMI` pulses low (≥200 µs) after 3 consecutive out-of-tolerance samples (~33 µs each) — gives the CPU a window to flush critical RAM state before reset/switchover.

**Battery switchover:** VCCO from greater of VCC/VBAT; as VCC falls below VCCTP, `/CEO` forced inactive (write-protect delayed until the current cycle completes). Battery current <100 nA. This keeps U12/U14 (the reading buffer) alive when off.

**Net firmware constraints:** (1) pet the DS1236 watchdog faster than its ~100 ms-from-reset / 400 ms-typ timeout; (2) on `/NMI` flush critical RAM; (3) RAM access valid only while VCC in tolerance (gated by `/CEO`).

---

## Interface & Driver Support Chips

### ADM202 — RS-232 Line Driver/Receiver (U4)
ADI 2-driver/2-receiver RS-232 transceiver with on-chip charge pump generating ±10 V from +5 V (TIA/EIA-232-E). Converts the MC68332 QSM SCI logic-level UART to/from RS-232 line levels for the rear serial port.

> **Naming flag:** the Keithley service manual calls U4 **"MAX202"**; this datasheet is the **pin-compatible ADM202** variant. Treat MAX202 and ADM202 as the same socket — functionally/pin-for-pin equivalent.

- Supply 5 V ±10%, Icc ~2.5 mA; 4 × 0.1 µF charge-pump caps.
- Driver swing ±5 V min / ±9 V typ (3 kΩ); receiver ±30 V input, 0.5 V hysteresis.
- 120 kbit/s; 2 drivers + 2 receivers. Driver inputs have 400 kΩ pull-ups; receiver inputs 5 kΩ pull-downs.

### SN75161B — Octal GPIB Management-Line Transceiver (U6/U20 with SN75160)
TI 8-channel bidirectional GPIB transceiver (IEEE-488-1978), with glitch-free power-up/down. The "161B" is the single-controller variant (162B = multi-controller, adds SC). With the **TMS9914A** controller and companion **SN75160** (data lines DIO1–8), it handles the 8 **management/handshake lines**: ATN, EOI, SRQ, REN, IFC, DAV, NRFD, NDAC.

- **Direction control:** **DC** sets direction of ATN/SRQ/REN/IFC; **TE** sets direction of DAV/NDAC/NRFD; ATN participates in EOI direction. High = drive toward bus (talk), Low = receive (listen).
- Supply 5 V, Icc ≤110 mA; driver sink up to 48 mA; receiver hysteresis 650 mV; prop delay ≤35 ns; high-Z when Vcc = 0.

### AQVV201A — PhotoMOS Solid-State Relay (analog board, K2xx)
Panasonic PhotoMOS 1-Form-A optically-isolated SSR (LED → photovoltaic stack → MOSFET output): galvanically-isolated, bounce-free, low-thermal-EMF switching. AQV201 = AC/DC 40 V member; "A" suffix = SMD package. Used on the analog board for **signal/range relay switching with isolation**, keeping digital control isolated from the floating analog section.

- 1 Form A (NO); load 40 V, 0.5 A continuous (A connection), 1.8 A peak (100 ms); Ron 0.6 Ω typ / 1.0 Ω max.
- Off-leakage ≤1 µA; **I/O isolation 1500 Vrms**; LED operate 2.4 mA typ (drive IF 10–30 mA); Ton ≈0.38 ms / Toff ≈0.08 ms.
- 6-pin: pins 1–2 input LED; 4,5,6 isolated output; **pin 3 internal — do not use**. "A connection" = two output MOSFETs in series (true AC/bidirectional blocking).

### UDN2549EB — Protected Quad Power Driver (U7)
Allegro quad open-collector high-current low-side driver: four AND-gated outputs each sink 600 mA, with per-channel over-current limiting (~1 A), thermal limiting (~165 °C), and integral flyback clamp diodes. TTL/5 V-CMOS inputs. "EB" = 28-lead power PLCC. Drives the **rear-panel Digital I/O / component-handler output lines** — its protection survives shorted/inductive external loads on those user-accessible pins.

- 4 channels, 600 mA sink each (all simultaneously); over-current trip ~1.0 A; output breakdown 60 V max / 40 V sustaining.
- Output sat 200 mV @100 mA … 600 mV @600 mA; Vcc 5 V, Icc ≤65 mA; clamp diode VF ≤1.7 V @1 A.
- Each output enabled by `INn AND ENABLE` (common enable). K pins = common clamp cathodes (tie to load supply for inductive loads). Fault behavior: fold output into ~1 A current-limited region, then thermal fold-back; auto-recovers when fault clears.

---

*Generated from the 13 datasheets in [`datasheets/`](datasheets/). The MC68332, TPU, TMS9914A, 24LC16B, and DS1236 sections are the primary references for firmware reverse engineering (register maps, protocols, and the watchdog/reset constraints the firmware must satisfy).*
