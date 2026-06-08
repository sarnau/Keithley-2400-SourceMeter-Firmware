# Keithley 2400 SourceMeter — Documentation Summary

This is a condensed, reverse-engineering-oriented summary of the official Keithley documentation
shipped in this directory (the PDFs whose names start with "Keithley 2400 SourceMeter"). It is meant
as a fast reference while analyzing the firmware in Ghidra — see [CLAUDE.md](CLAUDE.md) for the project
context and [README.md](README.md) for the hardware/memory map.

**Documents covered**

| File | Pages | Role |
|------|-------|------|
| `Keithley 2400 SourceMeter Datasheet.pdf` | 13 | Current (Tektronix/Keithley) rebranded datasheet, legacy models |
| `Keithley 2400 SourceMeter Datasheet 2.pdf` | 9 | Older Keithley datasheet — most complete model coverage (7 models) |
| `Keithley 2400 SourceMeter Datasheet 3.pdf` | 8 | Older brochure — strongest on applications/circuit behavior |
| `Keithley 2400 SourceMeter Specifications.pdf` | 3 | SPEC-2400 Rev. L — authoritative numbers for base 2400/2401 |
| `Keithley 2400 SourceMeter Quick Start Guide.pdf` | 46 | Front/rear panel, menus, basic operation |
| `Keithley 2400 SourceMeter Schnellstarthandbuch.pdf` | 47 | German translation of the Quick Start Guide (no extra content) |
| `Keithley 2400 SourceMeter Service Manual.pdf` | 137 | **Theory of operation, calibration, troubleshooting — most RE-relevant** |
| `Keithley 2400 SourceMeter User's Manual.pdf` | 496 | **Full SCPI command reference, status model, error list** |

**Quick orientation for firmware RE:** The most directly useful documents are the **Service Manual**
(hardware/board theory, calibration command set, EEPROM/ROM layout) and the **User's Manual**
(complete SCPI command tree → maps to the firmware command-parser tables; status/event model; full
error-code list → maps to the error table at `0x000679B2`; key-press codes → maps to front-panel
handling).

---

# Table of Contents

1. [Product Overview & Specifications](#product-overview--specifications)
2. [Quick Start Guide](#quick-start-guide)
3. [Service Manual](#service-manual) — theory of operation, calibration, troubleshooting
4. [User's Manual](#users-manual) — operation, trigger model, SCPI reference, status model, errors

---

## Product Overview & Specifications

### What the Instrument Is

The **Keithley Series 2400 SourceMeter** is a tightly-coupled **Source-Measure Unit (SMU)**: a single-channel, half-rack DC parametric tester that combines a precision low-noise DC power source with a true instrument-grade **6½-digit multimeter** in one box. Marketed as "five instruments in one" — voltage source, voltage meter, current source, current meter, and ohmmeter. Both the V and I source are programmable with **readback**; if readback hits the programmed **compliance limit**, the source is clamped (fault protection for the DUT).

- **4-quadrant operation:** sources (delivers power) in quadrants I & III; sinks (dissipates power internally) in quadrants II & IV. V, I, and R can all be measured during source or sink.
- **Sense modes:** 2-wire (local), 4-wire (remote Kelvin), and unique **6-wire guarded ohms** (adds GUARD + GUARD SENSE leads to lock out parallel current paths in resistor networks/hybrids).
- **Basic measure accuracy:** 0.012% with 6½-digit resolution.
- **Typical apps:** semiconductor/diode/LED/laser-diode I-V and LIV, varistor/TVS/MOV breakdown, I_DDQ leakage, resistor networks, solar cells, parametric & production binning.

### Product Family / Models

All share the same mainframe, firmware feature set, GPIB/RS-232/Trigger-Link, and 6½-digit DMM. They differ in **source/measure ranges and power**:

| Model | Voltage | Current | Power | Notes |
|-------|---------|---------|-------|-------|
| **2400** | ±200 V (±210 V limit) | ±1 A (±1.05 A) | 20 W (22 W) | Basic/standard |
| **2401** | ±20 V | ±1 A | 20 W | Low-voltage; **no DIO/handler interface**, convection-cooled |
| **2410** | ±1100 V | ±1 A (±21 mA above 21 V) | 20 W (22 W) | High-voltage |
| **2420** | ±63 V | ±3 A (±3.15 A) | 60 W (66 W) | High-current |
| **2425** | ±105 V | ±3 A | 100 W (110 W) | High-power |
| **2430** | ±105 V | ±3 A DC, **±10 A pulsed** | 100 W DC / **1000 W pulse** | Pulse-mode (8% max duty, ≥150 µs pulse, ≤5 ms wide) |
| **2440** | ±42 V | ±5 A (±5.25 A) | 50 W | 5 A high-current; ±40 V DC floating (vs ±250 V others) |
| **-C suffix** | — | — | — | Adds **Contact Check** (350 µs Kelvin contact verification). Not on 2401. |
| **2400-LV** | ±20 V | ±1 A | 20 W | Low-voltage 2400 variant |

### Source & Measure Ranges (representative, 2400/2401)

- **Voltage ranges:** 200 mV / 2 V / 20 V / 200 V; programming resolution 5 µV (200 mV range).
- **Current ranges:** 1 µA / 10 µA / 100 µA / 1 mA / 10 mA / 100 mA / 1 A; resolution down to 50 pA (1 µA range).
- **Resistance:** auto/manual ohms from <0.2 Ω up to >200 MΩ. Source-I+measure-V or source-V+measure-I; 6-wire guarded mode for networks.
- **Min compliance** = 0.1% of range; compliance is bipolar, set with a single value.

### Key Specs

- **Accuracy:** Source V ~0.02% rdg + offset; Measure V 0.012% rdg + offset (best ranges); Measure I 0.025–0.066%; Resistance 0.05–0.66%. 1-year, 23 °C ±5 °C.
- **Resolution:** 6½ digits (front panel); 4½ digits at max streaming rate.
- **Speed:** up to **1700 rdg/s at 4½ digits to GPIB**; ~2081 rdg/s to memory (Fast, 0.01 NPLC). Tiers = Fast (0.01 NPLC) / Medium (0.1) / Normal (1.0). Pass/fail limit test as fast as **500 µs/point** (contact check 350 µs).
- **NPLC settings:** 0.01 / 0.1 / 1.0 (line-cycle integration; firmware auto-detects 50/60 Hz at power-up).
- **Noise rejection:** CMRR 80 dB (Fast/Med) / 100 dB (Slow); NMRR 60 dB (Slow).
- **Overrange:** 105% of range, source and measure.

### Notable Features (firmware-relevant)

- **Sweeps:** Linear staircase, Logarithmic staircase, Custom (per-point list). Single-shot or continuous. Up to **1000–2500-point** sweeps.
- **Source-Memory List (built-in test sequencer):** up to **100** stored instrument configurations with **conditional branching** (pass→next, fail→bin/return). Runs without a PC. Battery-backed.
- **Source-Delay-Measure (SDM)** cycle is the fundamental measurement unit.
- **Pass/Fail comparator:** on-board, binning/sorting without a PC.
- **Math functions:** mX+b, power, voltage coefficient, % deviation, ratio, varistor alpha, offset-compensated ohms.
- **Memory buffer:** 5000 readings @ 5 digits (two 2500-point buffers), value(s) + timestamp. Li battery backup.
- **Power-up states:** 5 user-definable saved states plus factory default + `*RST`.

### Interfaces

- **GPIB IEEE-488** (SCPI-1995.0/1996.0) and **RS-232** standard on all models.
- **Keithley Trigger Link** (DIN connector) standard — hardware trigger handshake independent of GPIB.
- **Digital I/O / Component Handler interface** (all except 2401): SOT/EOT signals, 3 category bits, +5 V @ 300 mA supply; 1 trigger input + 4 TTL/Relay-Drive outputs. Output Enable / Safety Interlock = active-low input. Optional **2499-DIGIO** expander adds 16 DIO lines.

### About the Four Datasheet/Spec PDFs

Not different content — different revisions/scopes of the same Series 2400 documentation:
1. **Datasheet.pdf** — newest, Tektronix/Keithley rebrand (Rev. 02.2022); legacy models 2400/2401/2410/2420/2440 only.
2. **Datasheet 2.pdf** — older Keithley-branded, **most complete model coverage** (2400/2401/2410/2420/2425/2430/2440), Contact Check + 2430 pulse specs. (Ignore its unrelated reseller cover page.)
3. **Datasheet 3.pdf** — older brochure (2400/2410/2420/2425/2430); strongest on **application/circuit behavior** (contact-check schematic, 6-wire ohms theory, diode/network/varistor/I_DDQ setups).
4. **Specifications.pdf** — **SPEC-2400 Rev. L / May 2013**; authoritative numbers for **2400 / 2400-LV / 2400-C / 2401**.

For full model coverage use Datasheet 2; for base-model numbers use Specifications.pdf; for application behavior use Datasheet 3.

---

## Quick Start Guide

*Series 2400 SourceMeter Quick Start Guide, doc 2400S-903-01 Rev. E / Sept 2011. The "Schnellstarthandbuch.pdf" is the German translation with no additional content.*

### Front-Panel Layout
- **Display**: VFD with annunciators. Upper main line = measured reading; lower line shows source (left) and compliance (right). DISPLAY TOGGLE swaps source/measure between fields.
- **Annunciators (firmware-relevant):** REM, TALK, LSTN, SRQ, REAR (rear terminals), 4W (4-wire), AUTO (auto range), MATH, * (buffer/data store on), EDIT, ERR, REL, FILT.
- **MEAS keys:** Ω, FCTN (math), V, I. **SOURCE keys:** V, I + EDIT ◄► arrows.
- **Shifted/secondary keys:** LOCAL, REL, FILTER, LIMIT, TRIG, SWEEP, DIGITS, SPEED, STORE, RECALL, CONFIG, MENU, EXIT, ENTER.
- **Right side:** AUTO (auto-range toggle), RANGE ▲▼ (manual range — disables auto range), ON/OFF OUTPUT (red indicator), FRONT/REAR (TERMINALS) toggle.
- No physical knob — value adjustment is via EDIT/SOURCE/RANGE arrow keys + numeric keypad.

### Rear Panel
- **Terminals:** 4-WIRE SENSE HI/LO, INPUT/OUTPUT HI/LO, **V,Ω GUARD**, **GUARD SENSE** (guard + chassis ground are rear-only).
- **Interfaces:** IEEE-488/GPIB, RS-232 (DB-9), **TRIGGER LINK** (8-pin DIN), **OUTPUT ENABLE** (DB-9), AC line with fuse drawer.
- **Line:** 2.5 A 250 V slow-blow; 100–240 VAC 50/60 Hz, 190 VA max (auto-ranging mains).

### Menu System & Navigation (firmware-relevant)
- **CONFIG key** = configure prefix: CONFIG + a function key enters that function's config menu (CONFIG+SWEEP, +FILTER, +LIMIT, +FCTN, +DIGITS, +STORE, +SOURCE V/I, +MEAS Ω, …).
- **MENU key** = main system menu (SAVESETUP, source-memory save, GPIB address, …).
- Cursor positioned with ◄► arrow keys, confirmed with **ENTER**; **EXIT** backs out / cancels.
- Numeric entry: EDIT arrows move cursor & inc/dec digits; number keys enter directly; ENTER confirms.
- **Firmware quirks:** pressing **MENU resets a displayed number to its minimum**; DISPLAY EDIT mode **times out after ~6 s**; SOURCE arrows auto-enable source edit; RANGE arrows auto-disable auto range; in edit mode source/compliance update immediately on change (ENTER not required to apply).

### Basic Connections & Safety
- Three configs: **2-wire local**, **4-wire remote** (4W annunciator), **cable guard** (high-Z DUT >1 GΩ). Plus **ohms guard** for in-circuit resistance.
- **Specified accuracies require 4-wire remote sensing.** Use 4-wire when test-circuit impedance <1 kΩ.
- SCPI: `:ROUTe:TERMinals FRONt|REAR`, `:SYSTem:RSENse ON|OFF` (ON = 4-wire), `:SYSTem:GUARd CABLe|OHMS`.
- Safety: terminals are **Installation Category I only**; hazardous voltage can appear on output AND guard terminals. **Never connect/disconnect with unit on.** Ohms-guard: not usable >100 mA range; guard current must never exceed 50 mA.

### Power-Up & Defaults
- Default GPIB data string = **five elements** (V, I, R, timestamp, status), comma-separated; **+9.91e37** (NAN) marks a disabled/not-measured element.
- `*RST` → one-shot source-measure mode, source V / measure I default. Output OFF until ON/OFF OUTPUT pressed.

### Performance Settings
- **SPEED** (NPLC; 1 PLC = 16.67 ms @60 Hz / 20 ms @50 Hz): FAST 0.01 PLC→3.5 dig, MED 0.10→4.5, NORMAL 1.00→5.5, HI ACCURACY→5.5/6.5, OTHER 0.01–10 PLC. Changing SPEED changes DIGITS, but not vice-versa.
- **DIGITS** cycles 3.5/4.5/5.5/6.5. **FILTER**: moving or repeating average, count 1–100. **REL**: null offset (displayed = actual − rel).

### Simplest Remote-Control Example (source 10 V, measure I on 10 mA range)
```
*RST
:SOUR:FUNC VOLT
:SOUR:VOLT:MODE FIX
:SOUR:VOLT:RANG 20
:SOUR:VOLT:LEV 10
:SENS:FUNC "CURR"
:SENS:CURR:PROT 10e-3
:SENS:CURR:RANG 10e-3
:OUTP ON
:READ?
```

---

## Service Manual

*Keithley Model 2400 SourceMeter Service Manual (Doc 2400-902-01 Rev. G, Feb 2006; orig. 1996). Spec appendix also covers 2400-LV/-C, 2410, 2420, 2425, 2430, 2440.*

Three boards: **digital board** (2400-140), **analog board** (2400-100), **display board** (2400-110). Analog and digital sections are galvanically isolated via opto-isolators.

### Digital Board (the firmware-relevant core)

| Item | Detail |
|---|---|
| **CPU** | Motorola **MC68332** @ **16.78 MHz** (part LSI-161, U3) |
| **ROM (firmware)** | Two **256K×8** EEPROMs **U15/U16** in parallel for the 16-bit bus. U15 = `2400-803-*` (ODD/MSB), U16 = `2400-804-*` (EVEN/LSB). Only socketed ICs; field-reflashable on ROM-checksum failure. |
| **RAM** | Two **128K×8** RAMs **U12/U14** (LSI-162-70), parallel for 16-bit bus. **Battery-backed** — retains data buffer across power-down. |
| **Config EEPROM** | **U17 = I²C EEPROM 24LC16B** (LSI-153). Stores **all calibration constants and system setups**. |
| **GPIB** | **TMS9914A** "9914 GPIA" = **U13** (LSI-123). Transceivers U6 (75161), U20 (75160). |
| **RS-232 / UART** | 68332 **QSM** module; line transceiver **U4 = MAX202**. |
| **Internal serial** | 68332 **TPU** handles serial link to the front-panel display module + DAC interfacing. |
| **Trigger / Digital I/O** | Trigger out via U23; Digital I/O via U7 (4-ch power driver 2549B). |
| **Reset** | MPU RESET on U3 pin 68. |
| **Battery** | 3 V Li-Mn cell **BA-44**, holder BH-34. ~10-yr life; replace if <2.5 V. |
| **Clocks** | MPU 16.78 MHz; display 4 MHz (Y901). |

### Analog Board
- Two 16-bit DACs (**AD7849BR**, U660/U661): **V DAC** and **I DAC**, each two ranges (10 V or 1 V), fed into summing node FB.
- **Source-Voltage mode:** voltage loop dominates until I-compliance reached, then current loop overrides (and vice-versa for Source-Current). A **priority bit** selects which loop dominates.
- **Sense resistors** in HI lead do current sensing (per range). 1 A range = 0.2 V full-scale; all other I ranges = 2 V full-scale.
- Four V ranges (0.2/2/20/200 V); feedback gain changes only on 20 V & 200 V → three unique gains.
- A/D converter = multi-slope charge-balance + single-slope rundown, controlled by **gate array U610** on the analog board; MPU issues commands through opto-isolators, U610 returns data through opto-isolators.

### Active Guard ("six-wire ohms")
50 mA buffered equivalent of OUTPUT HI at the GUARD terminal for guarded/complex devices. Guard offset <300 µV, output impedance <0.1 Ω. (Calc formula: Keithley White Paper #2033.)

### Output Stage
- Class-B-biased drive transistors prevent thermal runaway. ±20 V high-current taps reduce dissipation on low ranges. Cascode Q518/Q521 with output MOSFETs Q516/Q523. Rails ±36 V and ±220 V.

### Power Supply
- **Offline flyback switcher** runs the whole instrument from 100/240 V line; digital board runs directly (incl. +12VD).
- Separate **floating switching supply** off +12VD generates analog rails +5VF, ±15VF, ±30VF, and feeds the HV/Power board for output rails ±36VO / ±220VO.
- Digital rails +5VD, +12VD. Regulators U18 = LM2940 (+5), IC1 = 7815, U8 = 79M15.

### Display Board
- **VFD** DS901, up to **49 characters** (5×7 dot matrix + underbar cursor). Needs +60 VDC + 5 VAC filament.
- **Display microcontroller U902** (ROM `7001-800-*`) drives the VFD and scans keys; 4 MHz clock from digital board.
- Display data sent serially from digital board over **TXB → U902 PD0**; key data returned over **RXB → PD1** (proprietary encoding).
- **CAL pads on the display board** — shorting them resets the cal password to factory default (`KI002400`).

### Calibration

Calibration constants live in **I²C EEPROM U17 (24LC16B)**, retained indefinitely after `:CAL:PROT:SAVE`. **Any board removal/component replacement requires recalibration.**

**Cal password:** front-panel default `002400`; **remote default `KI002400`** (note "KI" prefix).
- Unlock remote: `:CAL:PROT:CODE 'KI002400'` (send once before cal, not per-step).
- Change via CAL → CHANGE-PASSWORD, or two `:CAL:PROT:CODE` commands (max 8 chars). If first two chars become anything other than "KI", front-panel unlock is lost.
- **Lost-password recovery:** short the **CAL pads on the display board** → unlocks cal AND resets password to `KI002400`.

**Cal dates/count:** `:CAL:PROT:DATE`/`:NDUE` (year 1995–2094), `:CAL:PROT:COUNT?`. View: MENU → CAL → VIEW-DATES.

**Cal constants structure:**
- **Each SENSE range = 3 parameters:** zero, negative full scale, positive full scale.
- **Each SOURCE range = 4 parameters:** negative full scale, negative zero, positive full scale, positive zero.
- Read via `:CAL:PROT:SENS:DATA?` / `:CAL:PROT:SOUR:DATA?` (4 comma-separated ASCII floats for active range).

**Cal SCPI (`:CALibration:PROTected:`):** `:CODE`, `:COUNT?`, `:SAVE`, `:LOCK`/`:LOCK?`, `:DATE`/`:NDUE`, `:SENSe`/`:SENSe:DATA?`, `:SOURce`/`:SOURce:DATA?`. **Cal will NOT save** if not unlocked, if invalid data exists, or if steps are incomplete. With cal unlocked, sense tracks source; NPLC=1, autozero ON, filter count 10 repeat, fixed source, immediate triggers (changing these → +510).

**Calibration errors:** +500 date not set, +501 next-date not set, +502 data invalid, +503 DAC overflow, +504 DAC underflow, +505 source offset invalid, +506 source gain invalid, +507 measure offset invalid, +508 measure gain invalid. Also +510 "Not permitted with cal unlocked", +509 "…cal locked".

Appendix C provides a QBasic cal program (reference DMM HP3458A; 2400 GPIB addr 24, DMM 22) whose DATA lists enumerate exact step ordering.

### Performance Verification
18–28 °C, <70% RH, ≥1 hr warm-up. Reference: HP3458A DMM, Fluke 5450A resistance calibrator. Restore bench defaults first. **Default V-source protection is 40 V** — must raise to >200 V before testing the 200 V range. Example limits: 200 mV range 199.360–200.640 mV; 200 V range 199.936–200.064 V; 1 A range 0.99640–1.00360 A.

### Troubleshooting / Diagnostics
- **Power-on self-test:** ROM checksum + RAM test. RAM fail → lockup. **ROM checksum fail → firmware-upgrade mode auto-enabled** (field reflash).
- **Front-panel tests (MENU → TEST → DISPLAY-TESTS):** KEYS, DISPLAY-PATTERNS (5 sub-tests), CHAR-SET.
- **Key messages:** "No Comm Link" = front-panel processor lost comms with main MPU (reseat ROMs U15/U16). "Reading buffer data lost" / "DC calibration data lost" = dead/absent battery; after replacing, send `:syst:mem:init`.
- **Digital test points (Table 4-3):** U3 pin 19 = digital common, pin 7 = +5 V, pin 68 = reset, pin 66 = 16.78 MHz; A0–A19 address, D0–D15 data. U4 pin 7/8 = RS-232 RX/TX. U13 pins 34–42 = IEEE-488 data, 26–31 command lines, 24 REN, 25 IFC. D_ADDATA/D_DATA/D_CLK/D_STB on U3 pins 43/44/45/47.

### FRP / Firmware-RE Quick Reference
- **CPU:** MC68332 @ 16.78 MHz, 16-bit external bus; two parallel 8-bit ROMs (U15/U16) and two parallel 8-bit RAMs (U12/U14).
- **Firmware ROMs:** U15 = `2400-803-*` (even/odd split), U16 = `2400-804-*`; socketed, reflashable on checksum failure.
- **Display firmware:** separate µC ROM U902 = `7001-800-*`, serial TXB/RXB link with proprietary key encoding.
- **NV storage:** cal constants + setups in I²C EEPROM **U17 = 24LC16B**; data buffers/setups in battery-backed RAM.
- **In-68332 peripherals:** QSM → RS-232 (MAX202 U4); TPU → display serial + DAC interfacing. GPIB is external 9914A (U13) + 75160/75161 transceivers.

---

## User's Manual

*Keithley Series 2400 SourceMeter User's Manual, doc 2400S-900-01 Rev. K, Sept 2011. Conforms to IEEE-488.1-1987, IEEE-488.2-1992, SCPI 1996.0. Covers 2400/2400-LV/2401/2410/2420/2425/2430/2440 and `-C` variants.*

### Table of Contents

| Sec / App | Title |
|-----------|-------|
| 1 | Getting Started |
| 2 | Connections |
| 3 | Basic Source-Measure Operation |
| 4 | Ohms Measurements |
| 5 | Pulse Mode Operation (Model 2430 only) |
| 6 | Source-Measure Concepts |
| 7 | Range, Digits, Speed, and Filters |
| 8 | Relative and Math |
| 9 | Data Store |
| 10 | Sweep Operation |
| 11 | Triggering |
| 12 | Limit Testing |
| 13 | Digital I/O Port, Output Enable, & Output Configuration |
| 14 | Remote Operations |
| 15 | Status Structure |
| 16 | Common Commands |
| 17 | SCPI Signal Oriented Measurement Commands |
| 18 | SCPI Command Reference |
| A | Specifications (accuracy/SDM timing) |
| B | Status and Error Messages |
| C | Data Flow |
| D–G | IEEE-488 Bus Overview / Conformance / 488.1 Protocol / Contact Check Option |

### Getting Started — Power-Up & Defaults (firmware behavior)

- Self-tests EPROM and RAM, lights all segments/annunciators. Failure → momentary error + ERR annunciator.
- 2430 only: charges capacitor bank (~10 s, "Charging capacitor bank, please wait").
- On pass: displays model + firmware revs as `REV A01 A02` (A01 = main-board ROM, A02 = display-board ROM), then line frequency, then interface status. `*IDN?` returns model, serial, both ROM revs, analog & digital board revs.
- Line voltage (100–240 V) and frequency (50/60 Hz) auto-sensed; frequency forceable via MENU/AD-CTRL/LINE-FREQ or `SYST:LFR`.
- **7 setup slots:** 5 user (0–4, `*SAV`/`*RCL`), factory BENCH (`:SYST:PRES`), factory GPIB (`*RST`). Power-on config = BENCH / GPIB / user setup (`:SYST:POS`).
- **EDIT mode times out after 6 s;** source updates live, compliance applies on ENTER. TOGGLE swaps source/measure fields (disabled in Pulse Mode and when FCTN/REL/Limits enabled).
- Display can be disabled for speed (`:DISP:ENAB OFF` → "FRONT PANEL DISABLED"; only LOCAL/TRIG/OUTPUT remain active).
- **Menu navigation:** blinking cursor moved by EDIT ▲▼; number/range keys edit; ± toggles polarity; **MENU clears value to zero**; ENTER commits (out-of-range clamps); EXIT cancels uncommitted changes.
- **COMMUNICATION menu:** GPIB addr 0–30 (default 24); RS-232 baud 300–57600, 7/8 bits, parity none/odd/even, terminator CR/CR+LF/LF/LF+CR, flow none/XON-XOFF. **Changing interface causes a power-on reset.**

### Connections
- OUTPUT HI/LO + SENSE HI/LO on front & rear; GUARD/GUARD SENSE/EARTH rear-only. FRONT/REAR key (`:ROUT:TERM`) **turns OUTPUT OFF**. Terminals = Installation Category I only.
- 2-wire local (default) or 4-wire remote (`:SYST:RSEN`). When output off in 4-wire, sense lines internally disconnect (reconnect on output-on); unit defaults to 2-wire when output off.
- Guarding: cable guard (>1 GΩ circuits) vs ohms guard (`:SYST:GUAR OHMS/CABL`). Sense/guard changes turn OUTPUT OFF.

### Source-Measure Concepts (core firmware loop)

**Source-Delay-Measure (SDM) cycle** — the atomic operation:
1. **SOURCE** — set source output level (≤50 µs DAC config).
2. **DELAY** — settle (trigger latency ~100 µs + auto 1 ms if enabled + programmable 0–9999.999 s).
3. **MEASURE** — A/D conversion (NPLC-dependent; measure time e.g. 167 µs @ 0.01 PLC, 60 Hz; filter/offset-comp-ohms/autorange/CALC processing here).

**Compliance:** when sourcing V set I-compliance, when sourcing I set V-compliance. **Real compliance** = clamp at displayed value ("Cmpl" label flashes); **range compliance** = clamp at max for the present fixed measurement range (units label flashes; impossible with AUTO range). Lowest settable: 1 nA / 200 µV (2400/2410). `:SENS:CURR:PROT` / `:SENS:VOLT:PROT`.

**Auto zero:** every A/D conversion = zero + reference + signal measurements. `:SYST:AZER ON/OFF/ONCE`. Disabling skips ref/zero (faster, but drift). **NPLC caching** (`:SYST:AZER:CACH`): caches A/D ref/zero for up to 10 recent integration rates per function — speeds source-memory sweeps.

**Overheating protection:** over-temp trips output off; fan to high. 2420/2425/2430/2440: after 90 s still hot → "OVER-TEMP FAILURE!!!", power off.

**4-quadrant boundaries:** I/III source, II/IV sink. Sink limits derated above 60% duty cycle. **Guard:** driven, buffered = IN/OUT HI; cable guard ~10 kΩ, ohms guard <1 Ω (≤50 mA, not on 1A/3A/5A ranges).

**Data flow (Fig 6-20 / Appendix C):** SENSE (raw V/I/R/timestamp/filter) → Sample Buffer → CALC1 (math) → CALC2 (limits, NULL/REL) → Trace (data store) → CALC3 (stats). Read mapping: `:FETCh?`/`:READ?`/`:MEASure?` → raw; `:CALC1:DATA?` → math; `:CALC2:DATA?` → limit/null; `:TRAC:DATA?` → buffer; `:CALC3:DATA?` → statistics (V, I, R order). Going to local loses Sample Buffer → "Data corrupt or stale" (-230).

### Ohms / Range / Speed / Filters / Math / Data Store (brief)
- **Ohms:** auto (constant-current per range) or manual (V/I). **Source readback** (default ON) measures actual source for the Ω calc. **Offset-compensated ohms** = 2-point ΔV/ΔI, cancels thermal EMF. 6-wire = 4-wire + ohms guard.
- **Range:** full-scale = 105.5% of nominal; overflow → "OVERFLOW" (9.91E+37). **Auto range** algorithm: ≥105% → up 3 ranges; ≤10/1/0.1% → down 1/2/3 ranges. **Auto-range change mode** (`:SYST:RCM` SINGle/MULTiple) — MULTIPLE ranges up on compliance during delay phase and adds programmable **soak time**.
- **Digits** 3.5–6.5 (no effect on remote format). **Speed** = NPLC (FAST 0.01 → HI ACCURACY 10). **Filters:** repeating (default) vs moving average, count 1–100 (`:SENS:AVER`).
- **REL (NULL):** displayed = actual − rel (`:CALC2:NULL`). **Math (CALC1, FCTN):** POWER, OFFCOMPOHM, VOLTCOEF, VARALPHA, %DEV built-in; up to 5 user-defined (bus-only) with operands VOLTage/CURRent/RESistance/TIME and operators + − * / ^ log ln sin cos tan exp.
- **Data Store:** two separate 2500-reading buffers (5000 total). `:TRACe` subsystem; statistics via CALC3 (MEAN/SDEV/MAX/MIN/PKPK). Timestamp ABSolute or DELTa.

### Sweep Operation
- Four types: **linear staircase** (start/stop/step), **log staircase** (start/stop/points), **custom** (per-point list), **source memory** (recall up to 100 saved setups — different functions/math per point). Only V or I sweeps; readings auto-stored.
- `:SOUR:VOLT|CURR:MODE SWE|LIST|FIXed`; `:SOUR:SWE:SPACing LIN|LOG`, `:POINts` 2–2500, `:RANGing BEST|AUTO|FIXed`, `:CABort NEVer|EARLy|LATe`.
- **Source-memory sweep branching:** on PASS branch to a memory location (`:CALC2:CLIM:PASS:SML`), else NEXT; fail-branch via `:CALC2:CLIM:FAIL:SML` (remote only). Trigger count should equal/multiple of sweep points.

### Triggering (central to firmware)

**Two-layer trigger model (Arm + Trigger), actions Source/Delay/Measure:**
- **Idle** (ARM annunciator off): leave via OUTPUT ON (front) or `:INITiate`/`:READ?`/`:MEASure?` (remote). Return via HALT / `:ABORt`.
- **Arm layer** event sources: IMMEDIATE, BUS (GET/`*TRG`), TIMER, MANUAL (TRIG key), TLINK, NSTest/PSTest/BSTest (start-of-test SOT low/high/either). `:ARM:COUNt` 1–2500 or INFinite.
- **Trigger layer** has three event detectors (Source/Delay/Measure); trigger-in sources only IMMEDIATE or TLINk. `:TRIG:COUNt` 1–2500, `:TRIG:DELay` 0–999.9999 s.
- **Counters:** trigger count = points per sweep; arm count = sweep repeats. **arm × trigger ≤ 2500.**
- **Output triggers** per Source/Delay/Measure (`:TRIG:OUTP`) and arm-enter/exit (`:ARM:OUTP TENTer|TEXit|NONE`).
- **Trigger Link:** rear 8-pin micro-DIN, 4 TTL lines (factory: #2 out, #1 in), falling-edge input, Meter-Complete output pulse.
- **Always abort to idle:** IFC, SDC, DCL, `:ABORt`, `:SYST:PRES`, `*TRG`/GET, `*RST`, `*RCL`.

### Limit Testing
- **11 limit tests:** Limit 1 = compliance (H/W). Limit 2 = coarse, Limits 3, 5–12 = fine (S/W hi/lo). **Limit 4 = contact-check option.** All in CALC2 block.
- Modes: **GRADING** (run until a fail) vs **SORTING** (run until a pass). Binning: IMMEDIATE vs END.
- **Handler interface (DB-9 Digital I/O):** 4 output lines (pass/fail patterns), SOT input, /OE output enable, +5 V (300 mA). Line 4 doubles as EOT/BUSY strobe.
- Remote: `:CALC2:LIMx:UPPer/:LOWer/:STATe/:FAIL?`, `:CALC2:LIMx:SOUR2` (bit patterns), `:CALC2:CLIM:MODE GRAD|SORT`, `:CALC2:CLIM:BCONtrol IMM|END`, `:CALC2:CLIM:CLEar:AUTO`. **Model 2401 has no handler interface.**

### Digital I/O / Output Configuration
- **DB-9 port:** pins 1–4 = Digital Output #1–4 (#4 also EOT/BUSY), pin 5/9 = GND, pin 6 = Trigger/SOT input, pin 7 = +5 V (300 mA, self-resetting fuse), pin 8 = /Output Enable. Outputs source ≤2 mA, sink ≤500 mA. `:SOURce2:TTL` (0–15, or 0–65535 with 2499-DIGIO).
- **Output-off states** (`:OUTP:SMODe`): HIMPedance (relay opens), NORMal (V=0, I-compl 0.5% of range), ZERO ("ZER"), GUARd (I=0, V-compl 0.5%). Default NORMal (GUARd for 2410). On power-up: momentary HIMPedance then selected state.
- `:OUTPut:ENABle` + `:OUTPut:ENABle:TRIPped?` (test-fixture lid switch). 2430 Pulse Mode forces NORMal + auto-off.

### Remote Operations & Syntax
- GPIB default; RS-232 alternative (selectable only from front panel; stored NV; change → power-on reset). GPIB addr 24 default. General bus commands: REN, IFC, LLO, GTL, DCL, SDC, GET (=trigger), SPE/SPD.
- Syntax: `[ ]` optional words, `< >` parameter types; `<b>` boolean, `<NRf>` flexible numeric, `<n>` numeric/DEF/MIN/MAX, `<NDN>` non-decimal `#B/#Q/#H`. Case-insensitive. Multiple commands `;`-separated; colon after `;` resets to root. PMT = LF / EOI / LF+EOI. Invalid command → rest of message ignored.
- RS-232 defaults: 9600 8N1, XON/XOFF or none, straight-through DB-9 (TXD/RXD/GND; RTS-CTS tied). Break = ^C or ^X.

### Status Structure (Status Model)

**Status Byte Register:**

| Bit | Mnemonic | Meaning |
|-----|----------|---------|
| B0 | MSB | Measurement Summary Bit |
| B2 | EAV | Error Available (Error Queue not empty) |
| B3 | QSB | Questionable Summary Bit |
| B4 | MAV | Message Available (Output Queue not empty) |
| B5 | ESB | Event Summary Bit (standard event) |
| B6 | RQS/MSS | Request for Service / Master Summary Status |
| B7 | OSB | Operation Summary Bit |

Four register sets (Standard Event, Operation, Measurement, Questionable), each = Condition + Event + Enable. Two queues (Output → MAV, Error → EAV).

- **Standard Event (`*ESR?`, `*ESE`):** B0 OPC, B2 QYE, B3 DDE, B4 EXE, B5 CME, B6 URQ (LOCAL key), B7 PON.
- **Operation Event (`:STAT:OPER?`):** B0 Cal, B3 Swp (sweeping), B5 Trig (waiting for trigger), B6 Arm (waiting for arm), B10 Idle.
- **Measurement Event (`:STAT:MEAS?`):** B0 Limit1, B1/B2 Lo/Hi Limit2, B3/B4 Lo/Hi Limit3, B5 Limits Pass, B6 RAV (reading available), B7 ROF (overflow), B8 BAV, B9 BFL (buffer full), B10 CC (contact check), B11 Output-Enable asserted, B12 Over-Temp, B13 OVP, B14 Compliance.
- **Questionable Event (`:STAT:QUES?`):** B8 Cal (invalid cal constant at power-up), B14 Warn (SOMC parameter ignored).
- **Clearing:** `*CLS` resets all 4 event registers + Error Queue. `:STAT:PRESet` resets Operation/Measurement/Questionable enables (not Standard Event Enable, not Error Queue). `:SYST:PRESet` and `*RST` have **no effect** on status structure.
- **Error Queue:** FIFO, 10 messages, "350 Queue Overflow" when full. Negative codes = SCPI-defined, positive = Keithley-defined. `:SYST:ERR?`, `:STAT:QUE?`.
- **Register format:** `:FORMat:SREGister ASCii|HEX|OCT|BIN`.

### Common (*) Commands
`*CLS`, `*ESE`/`*ESE?`, `*ESR?`, `*IDN?` (`KEITHLEY INSTRUMENTS INC., MODEL nnnn, serial, ROMrev/date /analogrev/digitalrev`), `*OPC`/`*OPC?`, `*OPT?` (e.g. "CONTACT CHECK"), `*RCL 0–4`, `*RST`, `*SAV 0–4`, `*SRE`/`*SRE?`, `*STB?`, `*TRG` (=GET), `*TST?` (ROM checksum; 0=pass), `*WAI` (effectively no-op — all commands sequential).

### Signal-Oriented Measurement Commands
- `:CONFigure:<func>` (CURR/VOLT/RES) — defaults related controls, trigger=Immediate, counts=1, **turns output ON**.
- `:FETCh?` — latest readings from sample buffer (no trigger; NAN = +9.91e37 for unmeasured elements).
- `:READ?` = `:INITiate` + `:FETCh?`. `:MEASure?` = `:CONFigure` + `:READ?`.

### SCPI Command Reference — Subsystem Map

- **CALCulate[1]** — math: `:MATH:NAME/:EXPRession/:CATalog?/:DELete`, `:STATe`, `:DATA?`, `:UNITs`. Built-ins POWER/OFFCOMPOHM/VOLTCOEF/VARALPHA/%DEV. Vectored math (`VOLT[3]`). Math errors +801…+821.
- **CALCulate2** — limit tests + NULL/REL: `:LIMit1` (compliance), `:LIMit2/3/5–12` (`:UPPer`/`:LOWer`/`:SOURce2`/`:STATe`/`:FAIL?`), `:LIMit4` (contact check), `:CLIMits` (`:PASS/:FAIL:SMLocation`, `:BCONtrol IMM|END`, `:MODE GRAD|SORT`), `:CLEar:AUTO`, `:NULL`, `:FEED`, `:DATA?`.
- **CALCulate3** — buffer stats: `:FORMat MEAN|SDEV|MAX|MIN|PKPK`, `:DATA?`.
- **DISPlay** — `:ENABle`, `:CNDisplay`, `:WINDow[1|2]:TEXT:DATA` (20/32 chars), `:DIGits 4–7`.
- **FORMat** — `:DATA ASCii|REAL,32|SREal`, `:BORDer NORMal|SWAPped`, `:ELEMents` (VOLTage/CURRent/RESistance/TIME/STATus), `:SREGister`, `:SOURce2`.
- **OUTPut** — `[:STATe]`, `:ENABle[:STATe]`/`:TRIPped?`, `:SMODe HIMPedance|NORMal|ZERO|GUARd`.
- **ROUTe** — `:TERMinals FRONt|REAR`.
- **SENSe[1]** — `:FUNCtion:CONCurrent`, `:FUNCtion[:ON]/:OFF` ("VOLTage"/"CURRent"/"RESistance"); per-function `:RANGe[:AUTO]`, `:NPLCycles` (0.01–10), `:PROTection` (compliance); `:RESistance:MODE MAN|AUTO`, `:OCOMpensated`; `:AVERage:TCONtrol REP|MOV`, `:COUNt 1–100`.
- **SOURce[1]** — `:CLEar:AUTO`, `:FUNCtion:SHAPe DC|PULSe`, `:FUNCtion[:MODE] VOLTage|CURRent|MEMory`, `:DELay`/`:DELay:AUTO`; I/V source `:MODE FIXed|SWEep|LIST`, `:RANGe[:AUTO]`, `[:LEVel][:IMMediate]`/`:TRIGgered`; V-source `:PROTection` (OVP), `:SOAK`; `:SWEep:SPACing/:POINts/:DIRection/:RANGing/:CABort`; `:LIST`; `:MEMory:SAVE/:RECall/:POINts/:STARt` (1–100); `:PULSe:WIDTh/:DELay` (2430).
  - **SOURce2** (digital out/handler): `:BSIZe 3|4`, `:TTL`, `:TTL4:MODE EOTest|BUSY`, `:CLEar:AUTO:DELay` (EOT strobe width). Invalid on 2401.
- **STATus** — see Status Structure above. Not affected by `*RST`/`:SYST:PRESet`.
- **SYSTem** — `:PRESet`, `:POSetup`, `:VERSion?` ("1996.0"), `:ERRor?`/`:CLEar`, `:CCHeck`/`:CCHeck:RESistance` (2/15/50 Ω), `:RSENse`, `:KEY <n>` (simulate key), `:GUARd OHMS|CABLe`, `:BEEPer`, `:AZERo ON|OFF|ONCE`/`:CACHing`, `:LFRequency 50|60`/`:AUTO`, `:TIME?`/`:RESet`, `:MEMory:INITialize`, `:LOCal`/`:RWLock`, `:RCMode SINGle|MULTiple`, `:MEP`.
- **TRACe** — `:DATA?`, `:CLEar`, `:FREE?`, `:POINts 1–2500`, `:FEED SENSe|CALC1|CALC2`, `:FEED:CONTrol NEXT|NEVer`, `:TSTamp:FORMat ABS|DELT`.
- **TRIGger / ARM** — `:INITiate`, `:ABORt`; ARM `:COUNt`/`:TIMer`/`:SOURce`/`:TCONfigure`/`:OUTPut`; TRIG `:CLEar`/`:COUNt`/`:DELay`/`:SOURce IMMediate|TLINk`/`:INPut`/`:OUTPut`.

### STATus data element (24-bit measurement status word) — load-bearing for parsing readings
B0 OFLO, B1 Filter, B2 Front/Rear (1=front), B3 Compliance (real), B4 OVP, B5 Math, B6 Null, B7 Limits, B8/B9 limit results, B10 Auto-ohms, B11 V-Meas, B12 I-Meas, B13 Ω-Meas, B14 V-Sour, B15 I-Sour, B16 Range Compliance, B17 Offset Compensation, B18 Contact-check fail, B19–B21 limit results, B22 Remote Sense (4-wire), B23 Pulse Mode.

### Key-Press Codes (`:SYSTem:KEY <n>`, maps to front-panel handling)
1 RANGE↑, 2 SOURCE↓, 3 ◄, 4 MENU, 5 FCTN, 6 FILTER, 7 SPEED, 8 EDIT, 9 AUTO, 10 ►, 11 EXIT, 12 SOURCE-V, 13 LIMITS, 14 STORE, 15 MEAS-V, 16 TOGGLE, 17 RANGE↓, 18 ENTER, 19 SOURCE-I, 20 TRIG, 21 RECALL, 22 MEAS-I, 23 LOCAL, 24 ON/OFF, 26 SOURCE↑, 27 SWEEP, 28 CONFIG, 29 Ω, 30 REL, 31 DIGITS, 32 FRONT/REAR.

### Error / Status Messages (Appendix B)

Codes: negative = SCPI-defined, positive = Keithley-defined. (This list directly corresponds to the firmware error table parsed by `firmware_errors.py` at `0x000679B2`.)

**SCPI errors (negative, → Standard Event register):** -100..-178 command/parse errors (bit 5); -200..-285 execution/trigger/arm errors (bit 4, incl. -210..-215 trigger/arm deadlock/ignored, -221 settings conflict, -222 data out of range, -230 data corrupt/stale); -300..-363 device/comm errors (bit 3); -410..-440 query errors (bit 2). +000 "No error".

**Measurement events (positive):** +100 Limit1 failed, +101/102 Lo/Hi Limit2, +103/104 Lo/Hi Limit3, +105 limits passed, +106 reading available, +107 reading overflow, +108 buffer available, +109 buffer full, +110 Limit4 (contact check), +111 OUTPUT-enable asserted, +112 temperature limit, +113 voltage limit, +114 source in compliance.

**Standard event:** +200 Operation complete.
**Operation events:** +300 calibrating, +303 sweeping, +305 waiting in trigger layer, +306 waiting in arm layer, +310 entering idle.
**Questionable events:** +408 questionable calibration, +414 command warning.

**Calibration errors:** +500..+510 (see Service Manual — Calibration).

**Lost-data errors (bit 3):** +601 reading buffer lost, +602 GPIB address lost, +603 power-on state lost, +604 DC cal data lost, +605 cal dates lost, +606 GPIB language lost.

**Communication errors:** +700 invalid system comm, +701 ASCII only with RS-232.

**Command-execution errors:** +800 illegal with storage active, +801 insufficient vector data, +802 OUTPUT blocked by output enable, +803 not permitted with OUTPUT off, +804..+808 expression list errors, +809 OUTPUT blocked by over-temp, +811..+821 math-expression parse errors, +822 too small for sense range, +823 invalid with source readback on, +824 cannot exceed compliance range, +825 invalid with auto-ohms on, +826 attempt to exceed power limit, +827 invalid with ohms guard on, +828 invalid on 1 A range, +829 invalid on 1 kV range, +830 invalid with INF ARM:COUNT, **+831 invalid in Pulse Mode**, +900 internal system error.

**Three most common SCPI errors:** -113 "Undefined header" (missing space before parameter / wrong short/long form), -410 "Query INTERRUPTED" (new command sent before reading prior response), -420 "Query UNTERMINATED" (addressed to talk with no pending query).

### Appendix A — Timing (SDM cycle)
SDM = Trigger Latency → Trigger Delay (0–999.9999 s) → Source Config (≤50 µs) → Source Delay (auto-delay adds 100 µs) → A/D conversion. **A/D conversion time = NPLC × (1/line freq) + 185 µs.** Firmware overhead per case: auto-zero on/1 function 1.8 ms (V)/2.15 ms (I) with 3× A/D; auto-zero off/1 function 300 µs (V)/640 µs (I) with 1× A/D.

---

*Generated from the eight "Keithley 2400 SourceMeter" PDFs in this directory. The Service Manual and User's Manual sections are the primary references for firmware reverse engineering; see [CLAUDE.md](CLAUDE.md) for how this maps to the binary.*
