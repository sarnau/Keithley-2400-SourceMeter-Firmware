# Keithley 2400 — Annotated SCPI Command Reference

A description of **every SCPI command** the firmware implements, keyed by the internal **cmdId**
(the dispatch id from the parser tables — see [SCPI.md](SCPI.md)). Access: **R** = query-only,
**RW** = settable + queryable. The authoritative command tree is [SCPI_COMMANDS.txt](SCPI_COMMANDS.txt);
cmdId → handler addresses and settability are in [SCPI_DISPATCH.txt](SCPI_DISPATCH.txt).

Descriptions combine the standard Keithley 24xx SCPI semantics with firmware verification of the
handlers. The **`:DIAGnostic:KEIThley`** factory/service subtree (cmdIds `0x84`, `0x146`,
`0x150–0x18D`) is documented separately in **[DIAGNOSTIC.md](DIAGNOSTIC.md)** and not repeated here.

> Rows labelled `? (internal …)` are cmdIds with no public SCPI mnemonic — hidden internal
> setters/handlers confirmed by decompiling their handler (e.g. single-byte RAM config writes).

---

## Common (`*`) commands & top-level

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x0001 | RW | `:OUTP:ON` | Internal output-on action (energizes the source output relay; equivalent to `:OUTPut ON`). |
| 0x0002 | RW | `*CLS` | Clear Status: clears all event registers (Standard/Operation/Measurement/Questionable), the error queue, and the related Status-Byte summary bits. |
| 0x0003 | RW | `*ESE` | Set/query the Standard Event Status **Enable** mask (0–255) that gates the ESB summary bit. |
| 0x0004 | R | `*ESR?` | Read & clear the Standard Event Status Register (OPC/QYE/DDE/EXE/CME/PON…). |
| 0x0005 | R | `*IDN?` | Identification: `KEITHLEY INSTRUMENTS, MODEL 24xx, <serial>, <firmware revs>`. |
| 0x0006 | RW | `*OPC` | Operation Complete: set form sets OPC when pending ops finish; `*OPC?` returns "1" when complete (sync). |
| 0x0007 | R | `*OPT?` | Option identification (installed options, e.g. contact-check). |
| 0x0008 | RW | `*RCL` | Recall a saved setup (0–4) from non-volatile memory (shared restore routine). |
| 0x0009 | RW | `*RST` | Reset to `*RST` defaults (source/measure/trigger model to power-on state). |
| 0x000a | RW | `:SYST:PRES` | Restore `:SYSTem:PRESet` (bench) defaults via the shared restore routine. |
| 0x000b | RW | `*SAV` | Save the present complete setup to a non-volatile location (0–4). |
| 0x000c | RW | `*SRE` | Set/query the Service Request Enable mask selecting which Status-Byte bits assert SRQ/MSS. |
| 0x000d | R | `*STB?` | Read the Status Byte (with MSS) without clearing. |
| 0x000e | RW | `*TRG` | Bus trigger: advances the trigger model like a GET when armed/waiting. |
| 0x000f | R | `*TST?` | Self-test; returns 0 = pass. |
| 0x0010 | RW | `*WAI` | Wait-to-continue (sequential-completion sync; no-op since commands are sequential). |
| 0x0011 | RW | *(internal)* | Unnamed cmdId; handler inspects trigger/operation state flags and sets a pending-op bit (internal trigger/arm action). |
| 0x0012 | R | `:DATA?` | Return the latest reading element(s) (`[:SENSe]:DATA:LATest?`-style fetch). |

## `[:SENSe[1]]` — measurement function & config

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x0013 | RW | `:FUNC:CONC` | Concurrent measurement on/off — ON allows simultaneous V, I, R in one reading. |
| 0x0014 | RW | `:FUNC:OFF` | Disable named function(s) ("VOLT"/"CURR"/"RES") from the active set; query lists off functions. |
| 0x0015 | RW | `:FUNC:OFF:ALL` | Disable all measurement functions. |
| 0x0016 | R | `:FUNC:OFF:COUN?` | Count of disabled functions. |
| 0x0017 | RW | `:FUNC[:ON]` | Enable a measurement function; query lists enabled functions. |
| 0x0018 | RW | `:FUNC:ALL` | Enable all functions (V, I, R) concurrently. |
| 0x0019 | R | `:FUNC:COUN?` | Count of enabled functions. |
| 0x001a | R | `:FUNC:STAT?` | State (on/off) of a named function. |
| 0x001b | RW | `:AVER:TCON` | Averaging filter control: MOVing vs REPeat. |
| 0x001c | RW | `:AVER:COUN` | Averaging filter count (1–100 readings). |
| 0x001d | RW | `:AVER` | Enable/disable the digital averaging filter. |
| 0x001e | RW | `:NPLC` | A/D integration time in power-line cycles (~0.01–10 PLC) for the active function. |
| 0x001f | RW | `:CURR:PROT:RSYN` | Current compliance range-synchronize (couple measure range to compliance). |
| 0x0020 | RW | `:VOLT:RANG` | Fixed voltage **measure** range (0.2–200 V). |
| 0x0021 | RW | `:VOLT:RANG:AUTO` | Voltage measure autorange on/off. |
| 0x0022 | RW | `:VOLT:RANG:AUTO:ULIM` | Voltage autorange upper-limit range. |
| 0x0023 | RW | `:VOLT:RANG:AUTO:LLIM` | Voltage autorange lower-limit range. |
| 0x0024 | RW | `:VOLT:PROT` | Voltage compliance (protection) limit while sourcing current. |
| 0x0025 | R | `:VOLT:PROT:TRIP?` | Voltage in-compliance (tripped) flag. |
| 0x0026 | RW | `:RES:RANG` | Fixed resistance measure range (2 Ω–200 MΩ). |
| 0x0027 | RW | `:RES:RANG:AUTO` | Resistance autorange on/off. |
| 0x0028 | RW | `:RES:RANG:AUTO:ULIM` | Resistance autorange upper-limit range. |
| 0x0029 | RW | `:RES:RANG:AUTO:LLIM` | Resistance autorange lower-limit range. |
| 0x002a | RW | `:RES:MODE` | Ohms mode: MANual (V/I from user source) or AUTO (instrument-controlled). |
| 0x002b | RW | `:RES:OCOM` | Offset-compensated ohms on/off (cancels thermal EMF via two-level measurement). |
| 0x002c | RW | `:CURR:RANG` | Fixed current **measure** range (amps). |
| 0x002d | RW | `:CURR:RANG:AUTO` | Current measure autorange on/off. |
| 0x002e | RW | `:CURR:RANG:AUTO:ULIM` | Current autorange upper-limit range. |
| 0x002f | RW | `:CURR:RANG:AUTO:LLIM` | Current autorange lower-limit range. |
| 0x0030 | RW | `:CURR:RANG:HOLD` | Current range hold (lock present range against autorange). |
| 0x0031 | RW | `:CURR:RANG:HOLD:DEL` | Settling delay applied when current range-hold is active. |
| 0x0032 | RW | `:CURR:PROT` | Current compliance (protection) limit while sourcing voltage. |
| 0x0033 | R | `:CURR:PROT:TRIP?` | Current in-compliance (tripped) flag. |

## Signal-oriented measurement (`:MEASure`/`:CONFigure`/`:READ`/`:FETCh`)

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x0034 | R | `:MEAS:VOLT?` | One-shot: configure voltage measure, trigger one cycle, return the reading. |
| 0x0035 | R | `:MEAS:CURR?` | One-shot current measurement. |
| 0x0036 | R | `:MEAS:RES?` | One-shot resistance measurement. |
| 0x0037 | R | `:MEAS?` | One-shot measurement on the active function(s). |
| 0x0038 | RW | `:CONF:VOLT` | Configure for voltage measure (default setup) without triggering. |
| 0x0039 | RW | `:CONF:CURR` | Configure for current measure without triggering. |
| 0x003a | RW | `:CONF:RES` | Configure for resistance measure without triggering. |
| 0x003b | R | `:CONF?` | Return the present measurement configuration. |
| 0x003c | R | `:READ?` | `:ABORt`+`:INITiate`+`:FETCh?` — trigger and return new reading(s). |
| 0x003d | R | `:FETC?` | Return the latest reading(s) from the sample buffer without re-triggering. |

## `:SOURce[1]` / `:SOUR2` / `:OUTPut` — source & output

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x003e | RW | `:SOUR2:TTL` | Digital-I/O (Source 2) output bit pattern driven on the rear DIO lines. |
| 0x003f | R | `:SOUR2:TTL:ACT?` | Actual asserted TTL level/polarity on the DIO lines. |
| 0x0040 | RW | `:ARM:SOUR:TLIN` | Trigger-link input line used as arm-layer event (when `ARM:SOUR TLINk`). |
| 0x0041 | RW | `:SOUR2:CLE:AUTO:DEL` | Auto-clear delay (hold time) for the digital output (EOT strobe width). |
| 0x0042 | RW | `:SOUR2:CLE` | Immediately clear the digital output to its inactive state. |
| 0x0043 | RW | `:SOUR2:TTL4:MODE` | DIO line 4 mode: general TTL output vs EOT/BUSY handshake. |
| 0x0044 | RW | `:SOUR2:TTL4:BST` | Busy/strobe polarity/state for DIO line 4 in handshake mode. |
| 0x0045 | RW | `:SOUR2:BSIZ` | Digital-output port width (bit size, 3/4/16). |
| 0x0046 | RW | `:SOUR:CURR` | Immediate current-source amplitude (amps). |
| 0x0047 | RW | `:SOUR:CURR:TRIG` | Triggered current-source level (applied on trigger). |
| 0x0048 | RW | `:SOUR:CURR:TRIG:SFAC` | Scale factor applied to the triggered current level. |
| 0x0049 | RW | `:SOUR:CURR:TRIG:SFAC:STAT` | Enable/disable triggered current source-factor scaling. |
| 0x004a | RW | `:SOUR:CURR:MODE` | Current source mode: FIXed / SWEep / LIST. |
| 0x004b | RW | `:SOUR:CURR:RANG` | Fixed current **source** range. |
| 0x004c | RW | `:SOUR:CURR:RANG:AUTO` | Current source autorange on/off. |
| 0x004d | RW | `:SOUR:CURR:STAR` | Current sweep start level. |
| 0x004e | RW | `:SOUR:CURR:STOP` | Current sweep stop level. |
| 0x004f | RW | `:SOUR:CURR:STEP` | Current sweep per-point step size. |
| 0x0050 | RW | `:SOUR:CURR:SPAN` | Current sweep span (with CENTer). |
| 0x0051 | RW | `:SOUR:CURR:CENT` | Current sweep center (with SPAN). |
| 0x0052 | RW | `:SOUR:VOLT` | Immediate voltage-source amplitude (volts). |
| 0x0053 | RW | `:SOUR:VOLT:TRIG` | Triggered voltage-source level. |
| 0x0054 | RW | `:SOUR:VOLT:TRIG:SFAC` | Scale factor for the triggered voltage level. |
| 0x0055 | RW | `:SOUR:VOLT:TRIG:SFAC:STAT` | Enable/disable triggered voltage source-factor scaling. |
| 0x0056 | RW | `:SOUR:VOLT:MODE` | Voltage source mode: FIXed / LIST / SWEep. |
| 0x0057 | RW | `:SOUR:VOLT:PROT` | Over-voltage protection clamp (discrete steps or NONE). |
| 0x0058 | R | `:SOUR:VOLT:PROT:TRIP?` | OVP tripped flag. |
| 0x0059 | RW | `:SOUR:VOLT:RANG` | Fixed voltage **source** range. |
| 0x005a | RW | `:SOUR:VOLT:RANG:AUTO` | Voltage source autorange on/off. |
| 0x005b | RW | `:SOUR:VOLT:STAR` | Voltage sweep start level. |
| 0x005c | RW | `:SOUR:VOLT:STOP` | Voltage sweep stop level. |
| 0x005d | RW | `:SOUR:VOLT:STEP` | Voltage sweep step size. |
| 0x005e | RW | `:SOUR:VOLT:SPAN` | Voltage sweep span. |
| 0x005f | RW | `:SOUR:VOLT:CENT` | Voltage sweep center. |
| 0x0060 | RW | `:SOUR:LIST:CURR` | Custom current list (≤2500 points) played when `CURR:MODE LIST`. |
| 0x0061 | RW | `:SOUR:LIST:CURR:APP` | Append value(s) to the current list. |
| 0x0062 | R | `:SOUR:LIST:CURR:POIN?` | Number of points in the current list. |
| 0x0063 | RW | `:SOUR:LIST:CURR:STAR` | Start index into the current list. |
| 0x0064 | RW | `:SOUR:LIST:DIR` | List traversal direction UP/DOWN. |
| 0x0065 | RW | `:SOUR:LIST:VOLT` | Custom voltage list (≤2500 points). |
| 0x0066 | RW | `:SOUR:LIST:VOLT:APP` | Append value(s) to the voltage list. |
| 0x0067 | R | `:SOUR:LIST:VOLT:POIN?` | Number of points in the voltage list. |
| 0x0068 | RW | `:SOUR:LIST:VOLT:STAR` | Start index into the voltage list. |
| 0x0069 | RW | `:SOUR:SWE:DIR` | Staircase sweep direction UP/DOWN. |
| 0x006a | RW | `:SOUR:SWE:SPAC` | Sweep spacing LINear/LOGarithmic. |
| 0x006b | RW | `:SOUR:SWE:POIN` | Number of staircase sweep points (1–2500). |
| 0x006c | RW | `:SOUR:SWE:RANG` | Sweep source ranging: BEST/AUTO/FIXed. |
| 0x006d | RW | `:SOUR:SWE:CAB` | Sweep compliance-abort: NEVer/EARLy/LATE. |
| 0x006e | RW | `:SOUR:PULS:WIDT` | Source pulse width (2430 pulse mode), seconds. |
| 0x006f | RW | `:SOUR:PULS:DEL` | Source pulse delay before measurement, seconds. |
| 0x0070 | RW | `:SOUR:MEM:SAVE` | Save present setup into a source-memory location (1–100). |
| 0x0071 | RW | `:SOUR:MEM:REC` | Recall a source-memory setup. |
| 0x0072 | RW | `:SOUR:MEM:POIN` | Number of memory locations stepped in a source-memory sweep. |
| 0x0073 | RW | `:SOUR:MEM:STAR` | Start location for a source-memory sweep. |
| 0x0074 | RW | `:SOUR:DEL` | Manual source delay (settle time before measure), 0–9999.999 s. |
| 0x0075 | RW | `:SOUR:DEL:AUTO` | Auto source-delay on/off (instrument computes settle time). |
| 0x0076 | RW | `:SOUR:SOAK` | Soak time at the first sweep point. |
| 0x0077 | RW | `:SOUR:FUNC` | Active source function: VOLTage or CURRent. |
| 0x0078 | RW | `:SOUR:FUNC:SHAP` | Source shape: DC or PULSe (2430). |
| 0x0079 | RW | `:SOUR:CLE:AUTO` | Auto output-off (auto-clear) on/off. |
| 0x007a | RW | `:SOUR:CLE:AUTO:MODE` | Auto-clear timing: ALWays / TCOunt. |
| 0x007b | RW | `:SOUR:CLE` | Immediately turn the source output off. |
| 0x007c | RW | `:OUTP` | Output relay ON/OFF (off-state set by `:OUTP:SMODe`). |
| 0x007d | RW | `:OUTP:SMOD` | Output-off mode: NORMal/HIMPedance/ZERO/GUARd. |
| 0x007e | RW | `:OUTP:ENAB` | Rear-panel output-enable interlock on/off (safety for high V). |
| 0x007f | R | `:OUTP:INT:TRIP?` | Interlock tripped/open status. |

## `:SYSTem` & internal config

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x0080 | R | `:SYST:TIME?` | Elapsed timestamp (s) of the reading-timestamp timer. |
| 0x0081 | RW | `:SYST:TIME:RES` | Reset the timestamp timer to zero. |
| 0x0082 | RW | `:SYST:TIME:RES:AUTO` | Auto-reset timestamp at each INITiate. |
| 0x0083 | RW | *(internal SYST config)* | Hidden boolean config → RAM byte `0x8085A4`. |
| 0x0085 | RW | *(internal SYST config)* | Hidden config, int 0–8 → RAM byte `0x8085A6`. |
| 0x0086 | RW | *(internal SYST config)* | Hidden boolean → RAM byte `0x8085A9`. |
| 0x0087 | RW | *(internal SYST config)* | Hidden boolean → RAM byte `0x8085AA`. |
| 0x0088 | RW | *(internal SYST config)* | Hidden config, int 0–2 → RAM byte `0x8085A8`. |
| 0x0089 | RW | *(internal SYST config)* | Hidden boolean → RAM byte `0x8085A7`. |
| 0x008a | R | `:SYST:VERS?` | SCPI version (e.g. 1996.0). |
| 0x008b | R | `:SYST:ERR?` | Read & pop the oldest error-queue entry (`<code>,"<msg>"`). |
| 0x008c | R | `:SYST:ERR:ALL?` | Read & pop all error-queue entries. |
| 0x008d | R | `:SYST:ERR:COUN?` | Number of messages in the error queue. |
| 0x008e | R | `:SYST:ERR:CODE?` | Read & pop oldest error code only (no message). |
| 0x008f | R | `:SYST:ERR:CODE:ALL?` | Read & pop all error codes only. |
| 0x0090 | RW | `:SYST:KEY` | Simulate a front-panel key (set); query the last key code. |
| 0x0091 | RW | `:SYST:FRSW` | Front/rear terminal switch state (`:ROUTe:TERMinals`-equivalent). |
| 0x0092 | RW | `:SYST:AZER` | Autozero on/off (periodic ref/zero drift correction). |
| 0x0093 | RW | `:SYST:AZER:CACH` | Autozero NPLC cache on/off. |
| 0x0094 | RW | `:SYST:AZER:CACH:RES` | Reset (clear) the autozero cache. |
| 0x0095 | RW | `:SYST:AZER:CACH:REFR` | Refresh (re-acquire) the autozero cache. |
| 0x0096 | R | `:SYST:AZER:CACH:NPLC?` | List of NPLC values currently cached. |
| 0x0097 | RW | `:SYST:POS` | Power-on setup (RST/PRESet/SAV0–4). |
| 0x0098 | RW | `:SYST:LFR` | Power-line frequency reference 50/60 Hz. |
| 0x0099 | RW | `:SYST:LFR:AUTO` | Auto line-frequency detection on/off. |
| 0x009a | RW | `:SYST:REM` | Enter remote (bus control), front panel locked except LOCAL. |
| 0x009b | RW | `:SYST:LOC` | Return to local (front-panel) operation. |
| 0x009c | RW | `:SYST:RWL` | Remote with lockout (also disables LOCAL key). |
| 0x009d | RW | `:SYST:RSEN` | 2-wire (OFF) vs 4-wire remote sense (ON). |
| 0x009e | RW | `:SYST:GUAR` | Guard mode CABLe vs OHMS. |
| 0x009f | RW | `:SYST:BEEP:STAT` | Beeper enable/disable. |
| 0x00a0 | RW | `:SYST:BEEP` | Sound the beeper at `<freq>,<time>`. |
| 0x00a1 | RW | `:SYST:MEM` | System setup-storage / memory-init control. |
| 0x00a2 | RW | `:SYST:RCT` *(internal)* | Reading/contact-check timeout-count config byte (`0x8047D1`). |
| 0x00a3 | RW | `:SYST:RCM` *(internal)* | Reading/contact-check mode byte (`0x8047D2`). |
| 0x00a4 | RW | `:SYST:FCON` *(internal)* | Config flag byte (`0x8047D3`), gated by a hardware-option flag. |
| 0x00a5 | RW | `:SYST:CCH` | Contact-check enable (requires 4-wire). |
| 0x00a6 | RW | `:SYST:CCH:RES` | Contact-check resistance threshold (2/15/50 Ω). |
| 0x00a7 | RW | `:SYST:MEP` | Message-exchange-protocol (488.1) state. |
| 0x00a8 | RW | `:SYST:MEP:HOLD` | MEP hold-off behavior. |

## `:STATus`

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x00a9 | RW | `:STAT:PRES` | Preset all STATus enable registers to default. |
| 0x00aa | R | `:STAT:QUE?` | Read & pop oldest error/event-queue entry. |
| 0x00ab | RW | `:STAT:QUE:ENAB` | Error codes admitted into the queue. |
| 0x00ac | RW | `:STAT:QUE:DIS` | Error codes excluded from the queue. |
| 0x00ad | RW | `:SYST:CLE` | Clear the error/event queue (alias of `:STAT:QUE:CLEar`). |
| 0x00ae | RW | `:STAT:QUE:CLE` | Clear all messages from the error/event queue. |
| 0x00af | R | `:STAT:OPER:COND?` | Operation Status condition register (real-time). |
| 0x00b0 | R | `:STAT:OPER?` | Read & clear Operation Status event register. |
| 0x00b1 | RW | `:STAT:OPER:ENAB` | Operation Status enable mask. |
| 0x00b2 | R | `:STAT:QUES:COND?` | Questionable Status condition register. |
| 0x00b3 | R | `:STAT:QUES?` | Read & clear Questionable Status event register. |
| 0x00b4 | RW | `:STAT:QUES:ENAB` | Questionable Status enable mask. |
| 0x00b5 | R | `:STAT:MEAS:COND?` | Measurement-Event condition register (limit/buffer/reading bits). |
| 0x00b6 | R | `:STAT:MEAS?` | Read & clear Measurement-Event register. |
| 0x00b7 | RW | `:STAT:MEAS:ENAB` | Measurement-Event enable mask. |

## `:DISPlay`

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x00b8 | RW | `:DISP:CND` | Return the display to normal (non-text) measurement mode. |
| 0x00b9 | RW | `:DISP:TEXT:STAT` | Enable user text on the top line (window 1). |
| 0x00ba | RW | `:DISP:TEXT` | Define the ASCII message on window 1. |
| 0x00bb | R | `:DISP:DATA?` | Raw character data currently on window 1. |
| 0x00bc | R | `:DISP:ATTR?` | Window-1 character attribute (blink/highlight) bytes. |
| 0x00bd | RW | `:DISP:WIND2:TEXT:STAT` | Enable user text on the bottom line (window 2). |
| 0x00be | RW | `:DISP:WIND2:TEXT` | Define the ASCII message on window 2. |
| 0x00bf | R | `:DISP:WIND2:DATA?` | Raw character data on window 2. |
| 0x00c0 | R | `:DISP:WIND2:ATTR?` | Window-2 attribute bytes. |
| 0x00c1 | RW | `:DISP:ENAB` | Enable/disable the front-panel display (off = faster operation). |
| 0x00c2 | RW | `:DISP:DIG` | Display resolution, 4–7 digits (4½–6½). |

## `:ABORt` / `:INITiate` / `:ARM` / `:TRIGger` — trigger model

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x00c3 | RW | `:ABORt` | Abort and return the trigger/arm model to idle. |
| 0x00c4 | RW | *(internal)* | Hidden cmdId; handler manipulates internal device-state flags. |
| 0x00c5 | RW | *(internal)* | Hidden cmdId; set tests/sets system status flags, query returns internal state. |
| 0x00c6 | RW | `:INITiate` | Initiate one trigger/measure cycle (idle → arm/trigger layers). |
| 0x00c7 | RW | `:ARM:SOUR` | Arm-layer event source: IMMediate/TLINk/TIMer/MANual/BUS/NSTest/PSTest/BSTest. |
| 0x00c8 | RW | `:ARM:COUN` | Arm count (1–2500 or INF). |
| 0x00c9 | RW | `:ARM:TIMer` | Arm-layer timer interval (when `ARM:SOUR TIMer`). |
| 0x00ca | RW | `:ARM:DIR` | Arm event-detector bypass: SOURce (use) / ACCeptor (bypass first). |
| 0x00cb | RW | `:ARM:ILIN` | Trigger-link input line for the arm layer. |
| 0x00cc | RW | `:ARM:OLIN` | Trigger-link output line for the arm layer. |
| 0x00cd | RW | `:ARM:OUTP` | Arm-layer output trigger: TENTer/TEXit/NONE. |
| 0x00ce | RW | `:TRIG:CLE` | Clear pending input triggers (reset trigger-layer detector). |
| 0x00cf | RW | `:TRIG:SOUR` | Trigger-layer source: IMMediate / TLINk. |
| 0x00d0 | RW | `:TRIG:COUN` | Trigger count / points per sweep (1–2500 or INF). |
| 0x00d1 | RW | `:TRIG:DEL` | Trigger delay (0–999.9999 s) before the SDM cycle. |
| 0x00d2 | RW | `:TRIG:DEL:AUTO` | Auto trigger-delay on/off. |
| 0x00d3 | RW | `:TRIG:DIR` | Trigger event-detector bypass: SOURce / ACCeptor. |
| 0x00d4 | RW | `:TRIG:ILIN` | Trigger-link input line for the trigger layer. |
| 0x00d5 | RW | `:TRIG:OLIN` | Trigger-link output line for the trigger layer. |
| 0x00d6 | RW | `:TRIG:OUTP` | Trigger-layer output trigger events: SOURce/DELay/SENSe/NONE. |
| 0x00d7 | RW | `:TRIG:INP` | Trigger-layer events that require an input trigger: SOURce/DELay/SENSe/NONE. |
| 0x00d8 | RW | `:TRIG:SEQ2:SOUR` | Source for trigger SEQuence2 (secondary SDM timing). |
| 0x00d9 | RW | `:TRIG:SEQ2:TOUT` | Timeout/interval for trigger SEQuence2. |

## `:TRACe` / `:DATA` — reading buffer

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x00da | R | `:TRAC:DATA?` | Read back all stored buffer readings (per `:FORMat:ELEMents`). |
| 0x00db | RW | `:TRAC:FEED` | Buffer source: SENSe[1] / CALCulate[1] / CALCulate2. |
| 0x00dc | RW | `:TRAC:FEED:CONT` | Buffer fill control: NEVer / NEXT. |
| 0x00dd | R | `:TRAC:FREE?` | Bytes available / bytes in use. |
| 0x00de | RW | `:TRAC:POIN` | Buffer size (1–2500 readings). |
| 0x00df | R | `:TRAC:POIN:ACT?` | Number of readings actually stored. |
| 0x00e0 | RW | `:TRAC:CLE` | Clear the buffer. |
| 0x00e1 | RW | `:TRAC:TST:FORM` | Buffer timestamp format ABSolute/DELTa. |

## `:FORMat`

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x00e2 | RW | `:FORM[:DATA]` | Response data format: ASCii / REAL,32 / SREal. |
| 0x00e3 | RW | `:FORM:BORD` | Binary byte order NORMal/SWAPped. |
| 0x00e4 | RW | `:FORM:ELEM[:SENS]` | Reading elements: VOLTage/CURRent/RESistance/TIME/STATus. |
| 0x00e5 | RW | `:FORM:ELEM:CALC` | CALC reading elements: CALCulate/TIME/STATus. |
| 0x00e6 | RW | `:FORM:SREG` | Status-register read/write numeric format ASCii/HEX/OCT/BIN. |
| 0x00e7 | RW | `:FORM:SOUR2` | Numeric format for Digital-I/O (SOURce2) bit-pattern values. |

## `:CALCulate1` — math

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x00e8 | R | `:CALC1:DATA?` | Array of CALC1 math results over the buffer. |
| 0x00e9 | R | `:CALC1:DATA:LAT?` | Latest single CALC1 math result. |
| 0x00ea | RW | `:CALC1:STAT` | Enable/disable the CALC1 math operation. |
| 0x00eb | RW | `:CALC1:MATH[:EXPR]` | Select/define the active math expression (POWER/OFFCOMPOHM/VOLTCOEF/VARALPHA/%DEV or user). |
| 0x00ec | R | `:CALC1:MATH:CAT?` | Catalog of available/defined math expression names. |
| 0x00ed | RW | `:CALC1:MATH:DEL[:SEL]` | Delete the selected user math expression. |
| 0x00ee | RW | `:CALC1:MATH:DEL:ALL` | Delete all user math expressions. |
| 0x00ef | RW | `:CALC1:MATH:NAME` | Select the math expression by name. |
| 0x00f0 | RW | `:CALC1:MATH:EXPR:BIND` *(BINDex)* | Bind/define the formula/operands of the selected math name. |
| 0x00f1 | RW | `:CALC1:MATH:UNIT` | Units string reported with the math result. |

## `:CALCulate2` — limit testing & NULL(REL)

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x00f2 | R | `:CALC2:DATA?` | Array of CALC2 (limit/null) results over the buffer. |
| 0x00f3 | R | `:CALC2:DATA:LAT?` | Latest single CALC2 result. |
| 0x00f4 | RW | `:CALC2:FEED` | CALC2 data source: CALCulate1 / VOLTage / CURRent / RESistance. |
| 0x00f5 | RW | `:CALC2:LIM1:COMP:FAIL` | Limit 1 (compliance) fail condition IN/OUT. |
| 0x00f6 | RW | `:CALC2:LIM1:COMP:SOUR2` | Digital-I/O bin pattern on Limit-1 (compliance) fail. |
| 0x00f7 | RW | `:CALC2:LIM4:SOUR2` | Digital-I/O bin pattern on Limit-4 (contact-check) fail. |
| 0x00f8 | R | `:CALC2:LIM1:FAIL?` | Limit-1 (compliance) pass/fail result. |
| 0x00f9 | R | `:CALC2:LIM4:FAIL?` | Limit-4 (contact-check) result. |
| 0x00fa | R | `:CALC2:LIM2:FAIL?` | Limit-2 (HI/LO software limit) result. |
| 0x00fb | R | `:CALC2:LIM3:FAIL?` | Limit-3 result. |
| 0x00fc–0x00ff | R | `:CALC2:LIM5/6/7/8:FAIL?` | Limit 5–8 pass/fail results (binning/sorting). |
| 0x0100 | R | `:ARM:SOUR:NST?` | Arm-source NSTest line-status readback (shares the limit-fail query dispatch). |
| 0x0101–0x0103 | R | `:CALC2:LIM10/11/12:FAIL?` | Limit 10–12 results. |
| 0x0104 | RW | `:CALC2:LIM1:STAT` | Enable/disable Limit 1 (compliance test). |
| 0x0105 | RW | `:CALC2:LIM4:STAT` | Enable/disable Limit 4 (contact check). |
| 0x0106–0x010f | RW | `:CALC2:LIM2/3/5/6/7/8/9/10/11/12:STAT` | Enable/disable software HI/LO limit tests 2,3,5–12 (binning/sorting). |
| 0x0110–0x0119 | RW | `:CALC2:LIM2/3/5..12:UPP` | Upper-limit threshold for each limit test (reading above → fail). |
| 0x011a–0x0122 | RW | `:CALC2:LIM2/3/5..11:UPP:SOUR2` | Digital-I/O bin pattern asserted when that test's **upper** limit fails. |
| 0x0123 | RW | `:CALC2:CLIM:FAIL:SOUR2` | Composite-limit fail bin pattern (no passing bin matched). |
| 0x0124–0x012d | RW | `:CALC2:LIM2/3/5..12:LOW` | Lower-limit threshold for each limit test (reading below → fail). |
| 0x012e–0x0137 | RW | `:CALC2:LIM2/3/5..12:LOW:SOUR2` | Digital-I/O bin pattern asserted when that test's **lower** limit fails. |
| 0x0138 | RW | `:CALC2:CLIM:CLE` | Clear composite-limit results & latched binning state. |
| 0x0139 | RW | `:CALC2:CLIM:CLE:AUTO` | Auto-clear composite results at the start of each test sequence. |
| 0x013a | R | `:CALC2:CLIM:PASS?` | Composite "all enabled limits passed" status. |
| 0x013b | RW | `:CALC2:CLIM:PASS:SOUR2` | Digital-I/O pattern on the all-pass condition. |
| 0x013c | RW | `:CALC2:CLIM:PASS:SML` | Pass bin / branch-to-source-memory location on pass. |
| 0x013d | RW | `:CALC2:CLIM:FAIL:SML` | Fail bin / branch-to-source-memory location on fail. |
| 0x013e | RW | `:CALC2:CLIM:BCON` | Binning-control update timing IMMediate/END. |
| 0x013f | RW | `:CALC2:CLIM:MODE` | Composite mode GRADing vs SORTing. |
| 0x0140 | RW | `:CALC2:NULL:OFFS` | NULL (REL) offset subtracted from each reading. |
| 0x0141 | RW | `:CALC2:NULL:STAT` | Enable/disable NULL (REL). |
| 0x0142 | RW | `:CALC2:NULL:ACQ` | Acquire present reading as the NULL offset. |

## `:CALCulate3` — buffer statistics

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x0143 | RW | `:CALC3:FORM` | Statistic over the buffer: MEAN/SDEViation/MAXimum/MINimum/PKPK. |
| 0x0144 | R | `:CALC3:DATA?` | Computed statistic result. |

## `:CALibration:PROTected`

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x0145 | RW | `:CAL:PROT:LOCK` | Lock the protected calibration subsystem; query = unlocked? |
| 0x0147 | RW | `:CAL:PROT:CODE` | Calibration unlock password/code. |
| 0x0148 | RW | `:CAL:PROT:SAVE` | Save new cal constants to EEPROM and end/lock the cal session. |
| 0x0149 | RW | `:CAL:PROT:DATE` | Calibration date (y,m,d). |
| 0x014a | RW | `:CAL:PROT:NDUE` | Calibration next-due date. |
| 0x014b | RW | `:CAL:PROT:SENS` | Perform a SENSe (measure) cal step. |
| 0x014c | RW | `:CAL:PROT:SENS:DATA` | SENSe cal reference value for the current step; query = stored data. |
| 0x014d | RW | `:CAL:PROT:SOUR` | Perform a SOURce (output) cal step. |
| 0x014e | RW | `:CAL:PROT:SOUR:DATA` | SOURce cal reference value (externally measured actual output). |
| 0x014f | R | `:CAL:PROT:COUN?` | Calibration count (times calibrated/saved). |

## `:DIAGnostic:KEIThley` — factory/service subtree

Cmdids `0x84`, `0x146`, `0x150–0x18D`. **See [DIAGNOSTIC.md](DIAGNOSTIC.md)** for the full
description of raw analog-HW access (`:BITS`/`:SET`/`:CNT`), calibration seeding, board
provisioning, and dangerous system control (`:BOOT`, `:MELTDOWN`, `:OTDIS`, …).

## High-cmdId trigger-model enum aliases

| cmdId | Acc | Command | Description |
|---|---|---|---|
| 0x0200 | R | `:ARM:SOUR:BST?` | Bus-status (BSTest) arm-source readback for the ARM layer. |
| 0x0400 | — | `:TRIG:SEQ2:SOUR:CCH` | Internal/unnamed; TRIGger SEQuence2 SOURce = compliance-change (CCHange) event. |

---

*Generated by analyzing each command's dispatch handler (parallel agents) combined with standard
Keithley 24xx SCPI semantics. Subsystem paths are authoritative per [SCPI_COMMANDS.txt](SCPI_COMMANDS.txt);
handler addresses per [SCPI_DISPATCH.txt](SCPI_DISPATCH.txt). Descriptions for standard commands
follow the documented 2400 behavior; `(internal)` rows were confirmed by decompiling the handler.*
