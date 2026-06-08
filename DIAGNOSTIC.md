# Keithley 2400 — Undocumented `:DIAGnostic:KEIThley` Commands

The `:DIAGnostic:KEIThley` subtree is the **factory/service command set** — present in the firmware
but **absent from the User's Manual SCPI reference**. It gives raw access to the analog hardware,
calibration, board identity, and system control. This is reverse-engineered from the firmware
(see [SCPI.md](SCPI.md) for the parser/dispatch and [MEASURE.md](MEASURE.md) for the analog path);
cmdIds and handler addresses are from [SCPI_DISPATCH.txt](SCPI_DISPATCH.txt) / [SCPI_COMMANDS.txt](SCPI_COMMANDS.txt).

> **Gating:** much of this subtree is intended to be reachable only after the diagnostic mode is
> enabled — `:DIAG:KEIT:SECRET ON` (cmdId 0x17F) sets `gDIAGNOSTIC_KEITHLEY_SECRET`, the same flag
> set by holding key combo **`0x86`** at power-on (see `main`, [SCPI.md](SCPI.md)). **These commands
> drive hardware directly with no range/safety checks — they can mis-set DACs, disable thermal
> protection, corrupt calibration, or reboot the unit.**

Confidence: **H** = handler logic confirmed; **M** = inferred from callees/structure; **?** = best guess.

---

## Raw analog-hardware access — `:BITS` / `:SET` / `:CNT`

These map 1:1 onto the analog-board serial protocol `frame = (value << 3) | targetCode`
(targetCodes: 0=INT,1=AFB,2=MUX,3=SYS,4=VDAC,5=IDAC,6=RNG,7=CCS — see [MEASURE.md](MEASURE.md)).
Each writes via the `ANALOG_SET_*` primitive after validating the value (`PARAM_GET_VALUE`,
DACs 0–65535, others 0–255).

| Cmd | cmdId | Conf | Action |
|---|---|---|---|
| `:BITS:AFB <n>` | 0x158 | H | write Analog FeedBack/routing bits (`ANALOG_SET_AFB`) |
| `:BITS:RNG <n>` | 0x159 | H | write range bits (`ANALOG_SET_RNG`) |
| `:BITS:VDAC <n>` | 0x15A | H | write the 16-bit **voltage DAC** code directly (`ANALOG_SET_VDAC`) |
| `:BITS:IDAC <n>` | 0x15B | H | write the 16-bit **current DAC** code directly (`ANALOG_SET_IDAC`) |
| `:BITS:SYS <n>` | 0x15C | H | write SYS/guard control bits (`ANALOG_SET_SYS`) |
| `:BITS:MUX <n>` | 0x15D | H | write the measurement **MUX** select (`ANALOG_SET_MUX`) |
| `:BITS:INT <n>` | 0x15E | H | write A/D integration control (`ANALOG_SET_INT`) |
| `:BITS:DATA?` | 0x15F | H | **read** the raw A/D data register (query-only) |
| `:BITS:SIG1/SIG2/REF/ZERO <n>` | 0x160–0x163 | H | force-select an A/D phase line |
| `:SET:SIG1/SIG2/REF/ZERO <n>` | 0x164–0x167 | H | set the A/D phase-select signals (`gDIAGNOSTIC_KEITHLEY_SET_*`) |
| `:CNT:SIG1?` | 0x168 | H | **read** SIG1 multi-slope phase count (`0x8018B0`) |
| `:CNT:SIG2?` | 0x169 | H | read SIG2 count (`0x8018B4`) |
| `:CNT:REF?` | 0x16A | H | read REFERENCE count (`0x8018B8`) |
| `:CNT:ZERO?` | 0x16B | H | read ZERO count (`0x8018BC`) |
| `:SPHAS <n>` | 0x16D | H | A/D single-phase mode select → `gDIAGNOSTIC_KEITHLEY_SPHAS` |
| `:INT` | 0x173 | M | trigger an integration/measure step |
| `:ENAB <b>` | 0x16C | M | enable analog/measurement path (range setup + `ANALOG_SET_MUX`) |

The `:CNT:*` counts feed the reading formula `(SIG2−ZERO)/(REF−ZERO)·gain+offset`
([MEASURE.md](MEASURE.md) §3) — so this subtree lets a calibration jig read raw converter output.

---

## Calibration

| Cmd | cmdId | Conf | Action |
|---|---|---|---|
| `:VREF <n>` | 0x18C | H | scale the default calibration constants by a voltage-reference % (`CALIBRATION_APPLY_VREF_SCALING`, float math) and write to the I²C EEPROM |
| `:INITCAL` | 0x18D | M | initialize/seed calibration (VREF scaling + reset, then command-done) |
| `:CCR` | 0x171 | M | contact-check calibration/result (checksum + response) |

(The user-facing `:CALibration:PROTected:*` set is documented separately in the Service Manual /
[SUMMARY.md](SUMMARY.md).)

---

## Board identity & configuration (factory provisioning → I²C EEPROM)

| Cmd | cmdId | Conf | Action |
|---|---|---|---|
| `:IBBR KI2400…KI2425` | 0x151 | H | **set the model / board ID** (`deviceModelId`): `SET_MODEL_AND_LOAD_DEFAULTS` + `FACTORY_RESET_RAM_STATE` — reprovisions the unit as that model and reloads its factory defaults |
| `:ISN <str>` | 0x150 | H | set the **Instrument Serial Number** (`PARAM_GET_STRING` → config block) |
| `:AHWREV <str>` | 0x17C | M | set **Analog** board hardware-revision string |
| `:DHWREV <str>` | 0x17D | M | set **Digital** board hardware-revision string |
| `:CCREV <str>` | 0x17E | M | set **Contact-Check** board hardware-revision string |
| `:LVOL <b>` | 0x180 | M | set the **Low-Voltage** variant flag (e.g. 2400-LV) |
| `:GPIB <n>` | 0x84 | M | set the GPIB primary address (ranged param + checksum to EEPROM) |
| `:DBUR <b>` | 0x154 | H | enable the **burn-in test** (same flag as the power-on `0x84`-key toggle in `main`) |
| `:NOPULSE <b>` | 0x185 | M | disable 2430 **pulse mode** |
| `:CCHK <b>` | 0x157 | M | enable **contact check** |
| `:SETUP1…SETUP5 <str>` | 0x187–0x18B | M | factory setup/config strings (shared handler `0x20DE0`: string-param → checksum → EEPROM) |

Most of these recompute a block checksum (`CALC_WORD_CHECKSUM`) and persist via `I2C_WRITE_DATA`,
matching the EEPROM layout decoded by [parse_flash.py](parse_flash.py).

---

## System control (dangerous)

| Cmd | cmdId | Conf | Action |
|---|---|---|---|
| `:BOOT` | 0x153 | H | **reboot the instrument** (`CPU_REBOOT`: abort to idle, force output off, pulse the PORTC reset line, `reset()`) |
| `:PROG` | 0x156 | M | enter **firmware-programming** mode (output-off, halts normal operation) |
| `:MELTDOWN` | 0x184 | H | **force the over-temperature fault path** for test: clears source, sets the over-temp status event, forces MUX, runs `COMM_UPDATE_FANSPEED` |
| `:OTDIS <b>` | 0x183 | M | **disable over-temperature protection** |
| `:FAN <n>` | 0x155 | M | set **fan speed** directly |
| `:KEYLOCK NONE\|FEDERAL\|JUAREZ` | 0x186 | M | front-panel **lockout level** (enum param; disables key IRQ) |
| `:SECRET <b>` | 0x17F | H | set `gDIAGNOSTIC_KEITHLEY_SECRET` (unlock the diagnostic command set) |
| `:UNLOCK` | 0x146 | ? | unlock diagnostic/calibration access |

---

## Display / keyboard / trigger-link diagnostics

| Cmd | cmdId | Conf | Action |
|---|---|---|---|
| `:DISP <str>` | 0x16E | H | write a raw text string straight to the **VFD** (`DISPBOARD_SEND_BYTES`) |
| `:DCMD <n>` | 0x16F | M | send a raw **command byte to the display board** (`DISPBOARD_SEND_BYTES`) |
| `:KEY?` | 0x170 | M | read the current/last front-panel **key code** |
| `:ILIN1?…ILIN4?` | 0x174–0x177 | M | read **Trigger-Link input** lines 1–4 |
| `:OLIN1…OLIN4 <b>` | 0x178–0x17B | M | drive **Trigger-Link output** lines 1–4 |
| `:STES` | 0x172 | ? | start/run a self-test step |
| `:FTYP?` | 0x181 | ? | query firmware type |
| `:EES?` | 0x182 | ? | query EEPROM status / error |

---

## Helper functions referenced (named this session)

`PARAM_GET_VALUE`/`PARAM_GET_VALUE_BOOL` (`0x29158`)/`PARAM_GET_STRING` (`0x2AFBC`) — argument
decode; `CALC_WORD_CHECKSUM` (`0x50C26`); `DISPBOARD_SEND_BYTES` (`0x3CD2E`); `CPU_REBOOT`
(`0x2B044`); `SET_MODEL_AND_LOAD_DEFAULTS` (`0x2C696`); `FACTORY_RESET_RAM_STATE` (`0x2C50E`);
`CALIBRATION_APPLY_VREF_SCALING` (`0x2CC3E`); `ANALOG_SET_{VDAC,IDAC,MUX,SYS,AFB,RNG,INT}`
(`0x10B6A`–`0x10CA6`); A/D phase counts `SIG1/SIG2/REF/ZERO` at `0x8018B0/B4/B8/BC`.

> **Caveat:** rows marked **M/?** are inferred from handler call-structure and globals, not from
> on-screen confirmation. The `:BITS`/`:SET`/`:CNT`/`:VREF`/`:IBBR`/`:BOOT`/`:MELTDOWN` rows (H) are
> confirmed from the decompiled handlers; `:STES`/`:FTYP`/`:EES` have small/opaque handlers and the
> exact behavior is a best guess.
