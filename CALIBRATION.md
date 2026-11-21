# Keithley 2400 — Calibration Subsystem (firmware C34)

How the firmware stores, computes, validates and applies the DC calibration constants, and how the
`:CALibration:PROTected:*` commands, the front-panel CAL menu and the hidden `:DIAG:KEIT:*`
cal helpers work. This is reverse-engineered from `2400-FIRMWARE.bin` in Ghidra. Addresses are
Ghidra addresses (= file offsets for ROM). The names used here are the ones now in the Ghidra DB.
Several older names were wrong and have been renamed; see [§10](#10-renames-made-in-ghidra).

Related: [SCPI.md](SCPI.md) (parser and dispatch), [MEASURE.md](MEASURE.md) (A/D path that consumes
the sense constants), [DIAGNOSTIC.md](DIAGNOSTIC.md), [parse_flash.py](parse_flash.py) (EEPROM
decoder), [SUMMARY.md](SUMMARY.md) §Calibration (what the Service Manual says).

Confidence: **H** = read directly from the code, **M** = inferred from structure or data, **?** = guess.

---

## 1. Data model

### 1.1 EEPROM blocks (24LC16B, I²C address `0xA0`)

Each block has a ROM descriptor `{RAM ptr, i2c addr, EEPROM offset, size w/o checksum, total size}`.
`I2C_READ_DATA` / `I2C_WRITE_DATA` take a pointer to one of these descriptors.

| Descriptor | RAM | EEPROM | Size | Contents |
|---|---|---|---|---|
| `FLASH_DATA_CALIBRATION_DATA` `0x5C638` | `gCALIBRATION_DATA` `0x80566C` | `0x000` | 0x160 + 2 | 22 rows × 4 floats |
| `FLASH_DATA_CALIBRATION_INFO` `0x5C64C` | `gCALIBRATION_INFO` `0x808504` | `0x162` | 0x1C + 2 | password, dates, count |
| `FLASH_DATA_CURRENT_CONFIG` `0x5C69C` | `gCURRENT_CONFIG` `0x805554` | `0x1A6` | 0x8A + 2 | holds the `VREF` byte (`0x8055A7`) |

The checksum is `CALC_WORD_CHECKSUM` (`0x50C26`). It is the 16-bit one's complement of the byte
sum, so `sum(bytes) + chk + 1 ≡ 0 (mod 0x10000)`, which matches `verifyChecksum` in parse_flash.py. **H**

### 1.2 `gCALIBRATION_DATA` — 22 rows of 4 IEEE floats (big-endian)

A row is selected by the **active source range**: `SOURCE1_VOLTAGE_RANGE` (`0x804729`) or
`SOURCE1_CURRENT_RANG` (`0x804767`). The choice between V and I uses the byte at `0x80470D`,
`gCONFIG_0x19E.bSOURCE1_FUNCTION_MODE` — the **active SOURce function** set by `:SOUR:FUNC`
(cmdId 0x77): **0 = VOLTage, 1 = CURRent, 4 = MEMory**. It gates the V-vs-I path throughout the
firmware (cal, measure, trigger, display). It was previously mis-named `PROTECTION_TRIPPED`. **H**

| Rows | Offset | Block | Range index (2400) |
|---|---|---|---|
| 0–3 | `0x000` | **SENSE V** | 0.2 V, 2 V, 20 V, 200 V |
| 4–10 | `0x040` | **SENSE I** | 1 µA … 1 A (decades) |
| 11–14 | `0x0B0` | **SOURCE V** | 0.2 V … 200 V |
| 15–21 | `0x0F0` | **SOURCE I** | 1 µA … 1 A |

Other models use the same layout with different range values (see §1.4).

**SENSE row** (reading = `raw × gain + offset`):

| idx | meaning | how it is computed (§3) |
|---|---|---|
| [0] | gain A, fitted through the **+FS** and **zero** points | `(PFS_REF − ZERO_REF) / (PFS_RAW − ZERO_RAW)` |
| [1] | gain B, fitted through the **−FS** point | `(NFS_REF − offset) / NFS_RAW` |
| [2] | offset (shared by both polarities) | `PFS_REF − gainA × PFS_RAW` |
| [3] | unused (always 0) | — |

Both gains are **negative** in real data (e.g. −1.2545 on the 2 V range), so the A/D front end
inverts. [MEASURE.md](MEASURE.md) §3 says the reading routine uses `0x8018E8` (= row[1]) when
`SIG2 − ZERO > 0` and `0x8018E4` (= row[0]) otherwise. Combined with the negative gains, this means
a *positive* input gives a *negative* raw count difference. In other words, MEASURE.md's
"positive/negative gain" labels describe the raw-count sign, not the input polarity. **M**

**SOURCE row** (16-bit DAC code = `gain × setpoint + offset`; polarity is handled by a separate
switch and the DAC code is always the magnitude):

| idx | meaning |
|---|---|
| [0] | gain+ (DAC codes per volt or amp, > 0) |
| [1] | gain− (< 0, so `gain− × negative setpoint` is positive) |
| [2] | offset+ (DAC code at 0 for + polarity, must be ≥ 0) |
| [3] | offset− (DAC code at 0 for − polarity, must be ≥ 0) |

Consumers: `CAL_COMPUTE_VDAC_CODE` `0xABC0` / `CAL_COMPUTE_IDAC_CODE` `0xAAB0` (and the
`_RANGEMAX` / `_FULLSCALE` variants at `0xAD64…0xAF5E`) compute
`PASCAL_FLOAT_2_LONG(row[pol] × level + row[pol+2])`, where `pol` is the polarity flag (0/1). **H**

### 1.3 `gCALIBRATION_INFO` (`0x808504`, EEPROM `0x162`)

| off | type | field |
|---|---|---|
| 0x00 | char[10] | `calibrationPassword` (NUL-terminated, default `KI00`+model name, e.g. `KI002400`) |
| 0x0A / 0x0B | u8 / u8 | last-cal day / month |
| 0x0C | u32 | last-cal year |
| 0x10 / 0x11 | u8 / u8 | next-due day / month |
| 0x12 | u32 | next-due year (unaligned) |
| 0x16 | u32 | `calibrationCount` |
| 0x1A | 2 bytes | pad |
| 0x1C | u16 | checksum |

### 1.4 Factory default tables (ROM)

`gDEFAULT_CALIBRATION_DATA` at `0x5B9E6` holds one 0x162-byte image per `deviceModelId`
(`gHARDWARE_CONFIG.deviceModelId`, `0x80510E`). Default sense gains are `−6.2 × range / 5` for V
(0.2 V and 2 V both −1.24) and `−6.2 × I-range` for I, with offset 0. Default source rows are
`±59577 / range` codes per unit (≈ 0.909 × 65535 at full scale), with offset 500. **H** (decoded
values)

| model id | table | V-source gain on top range | implied top V range |
|---|---|---|---|
| 0 (2400) | `0x5B9E6` | 297.886 | 200 V |
| 1 (2410) | `0x5BB48` | 54.161 | 1100 V class |
| 2 (2420) | `0x5BCAA` | 992.95 | 60 V |
| 3 (2400 old analog) | `0x5BE0C` | 297.886 | 200 V |
| 4 (2430) | `0x5BF6E` | 595.77 | 100 V |
| 5 (2426?) | `0x5C0D0` | 992.95 | 60 V |
| 6 (2440) | `0x5C232` | 1489.43 | 40 V |
| 7 (2425?) | `0x5C394` | **no valid table**: this address holds the 2430 rows below plus other data | — |

The 2430 special case: when `deviceModelId == 4` and `analogBoardRevision ≥ 'D'` (0x44), the
**sense-I** default rows for current ranges 5 and 6 come from `gDEFAULT_CAL_2430_REVD_ISENSE_R5`
`0x5C394` (gain −1.24) and `…_R6` `0x5C3A4` (gain −12.0962) instead. These rows are only used as
references when validating sense gains (§3). **H**

> Model 7 indexes into data that isn't a cal table. A unit with model id 7 and a corrupt cal block
> would load garbage defaults. Either model 7 isn't supported in C34, or the table is missing. **?**

### 1.5 RAM working state

| Address | Name | Role |
|---|---|---|
| `0x8035E3` | `gCALIBRATION_UNLOCKED` | 1 = unlocked (was mis-named `…PROTECTED_LOCK`). Not persistent. |
| `0x807ED4` | `gCAL_SENSE_POINT_MASK` | bit0 = +FS, bit1 = −FS, bit4 = zero; fit runs when `& 0x13 == 0x13` |
| `0x807EBC…0x807ED0` | `gCAL_SENSE_{PFS,NFS,ZERO}_{REF,RAW}` | user reference value / raw reading pairs |
| `0x801724` | `gCAL_SOURCE_POINT_MASK` | bit0 +FS, bit1 −FS, bit2 +zero, bit3 −zero; fit runs when `& 0xF == 0xF` |
| `0x801704…0x801720` | `gCAL_SOURCE_{PFS,NFS,PZERO,NZERO}_{VALUE,DAC}` | measured value / DAC code pairs |
| `0x80486C` | `gVDAC_RANGE_FS_TABLE` | per V range `{float +FS, u16 code+, float −FS, u16 code−}` (12 B) |
| `0x804818` | `gIDAC_RANGE_FS_TABLE` | same, 7 I ranges |
| `0x8018E4/E8/EC` | (A/D) | active-range sense gain[0], gain[1] and offset, loaded by `ANALOG_LOAD_*_CAL` |
| `0x808726` | `gFP_CAL_STEP_ACTIVE` | front-panel cal step in progress (drives display) |

---

## 2. SCPI command reference (as implemented)

All `:CAL:PROT` set handlers are inline blocks inside `EXECUTE_COMMAND_MAIN` (SET table B). Query
handlers are inline in `EXECUTE_COMMAND_QUERY`. Errors are `ERR_INDEX_*` values in `D3`.

| Command | cmdId | Handler | Behaviour | Conf |
|---|---|---|---|---|
| `:CAL:PROT:CODE '<pw>'` | 0x147 | `0x1F296` | See §2.1 | H |
| `:CAL:PROT:CODE?` | 0x147 | `0x26546` | **Returns the stored password in clear text** when unlocked; 509 when locked | H |
| `:CAL:PROT:LOCK` | 0x145 | `0x1F6CA` | `gCALIBRATION_UNLOCKED = 0`, `gFP_CAL_STEP_ACTIVE = 0`. No save, no rollback. | H |
| `:CAL:PROT:LOCK?` | 0x145 | `0x26514` | 1 if locked, 0 if unlocked | H |
| `:CAL:PROT:DATE y,m,d` | 0x149 | `0x1F5B2` | Unlocked only (509). `VALIDATE_DATE` (year 1994…9999, real month/day, leap years), else −222. RAM only. | H |
| `:CAL:PROT:NDUE y,m,d` | 0x14A | `0x1F632` | Same, next-due date | H |
| `:CAL:PROT:DATE?` / `NDUE?` | | `0x2658E` / `0x265D2` | Always allowed | H |
| `:CAL:PROT:SENS <ref>` | 0x14B | `0x1F6DE` | Sense cal point, §3.1 | H |
| `:CAL:PROT:SOUR <meas>` | 0x14D | `0x1FB6A` | Source cal point, §3.2 | H |
| `:CAL:PROT:SENS:DATA a,b,c,d` | 0x14C | `0x1F9A6` | Unlocked only; exactly 4 values else **502**. Writes the active-range sense row as `[0]=a, [1]=c, [2]=b, [3]=d` | H |
| `:CAL:PROT:SOUR:DATA a,b,c,d` | 0x14E | `0x1FA88` | Same for the source row | H |
| `:CAL:PROT:SENS:DATA?` / `SOUR:DATA?` | | `0x26672` / `0x26616` | Returns the 4 floats of the active-range row (response type 0x1F) | H |
| `:CAL:PROT:SAVE` | 0x148 | `0x1F6B2` | Unlocked only; `CALIBRATION_WRITE_AND_INCREMENT` (§4) | H |
| `:CAL:PROT:COUNt?` | 0x14F | `0x266CE` | `calibrationCount` | H |

> **`:DATA` argument order — round-trip is safe (traced).** The set handlers store the four SCPI
> arguments `a,b,c,d` into the row as `[0]=a, [1]=c, [2]=b, [3]=d` (slots 1↔2 swapped). The `DATA?`
> query (`0x26672`/`0x26616`) stages a type-`0x1F` descriptor pointing at that row, and the shared
> formatter `RESPONSE_ADD_4_floats` (`0x3AB82`, via `RESPONSE_ADD_VALUE`) emits the slots in order
> **`[0],[2],[1],[3]`** through `"%+013.6E,…"` ×4 — i.e. it applies the **same** 1↔2 swap on read.
> The two swaps cancel, so `DATA?` returns `a,b,c,d` in the exact order `DATA` received them, and
> feeding `DATA?` output straight back into `DATA` reproduces the identical row. **No gain/offset
> corruption.** Holds for both `SENS:DATA` and `SOUR:DATA` (identical slot order, same formatter). **H**

### 2.1 `:CAL:PROT:CODE` (`0x1F296`)

1. Pulse mode enabled → **831**.
2. Read the string argument (max 9 bytes) into a stack buffer.
3. **Already unlocked → change password.** It is rejected with −224 if longer than 9, not starting
   with `KI`, or containing anything other than `0-9`/`A-Z`. Otherwise it is copied into
   `gCALIBRATION_INFO`, re-checksummed and **written to EEPROM immediately**: no `:SAVE` is needed
   and the cal count doesn't change. This is how "send CODE twice" changes the password.
4. **Locked → unlock.** `PASCAL_STRCMP(buf, stored)`; a mismatch gives −224. On a match:
   - `gCALIBRATION_UNLOCKED = 1`, `gBUILDIN_TEST_AVAILABLE = 1`
   - arm count 1 / source IMM (8); trigger count 1 / source IMM
   - sense function forced to the source function, sense autorange off (V and I)
   - filter: repeat (`TCONTROL = 1`), count 10, on
   - source V and I mode FIXED, source autorange off
   - NPLC 1 (stored 1000), integration time recomputed from line frequency
   - autozero / ref-zero refresh, sweep points rebuilt
   - display "CALIBRATION UNLOCKED"; both point masks cleared.

These are the settings the Service Manual lists as frozen during cal.

### 2.2 Settings that are locked while cal is unlocked (error 510)

These handlers test `gCALIBRATION_UNLOCKED` and return **510** "Not permitted with cal un-locked":

`:FUNC`, `:FUNC:CONC`, `:FUNC:OFF`, `:FUNC:OFF:ALL`, `:FUNC:ALL`, `:…:NPLC`, `:SOUR:FUNC`,
`:SOUR:FUNC:SHAP`, `:SOUR:VOLT:MODE`, `:SOUR:VOLT:RANG:AUTO`, `:SOUR:CURR:MODE`,
`:SOUR:CURR:RANG:AUTO`, `:SYST:AZER`, `:ARM:SOUR`, `:ARM:COUN`, `:TRIG:SOUR`, `:TRIG:COUN`.

The front-panel keys MEAS V/I/Ω, FUNCTION, FILTER, TRIG, SWEEP, AUTO, SPEED and the A/D-controls
menu are refused the same way (`FUNCTION_KEYCODE__*`, `MENU_GET_NEXT_MENU_WITH_CAL_LOCK`).

**`*RST`, `*RCL` and `:SYST:PRES` re-lock calibration** (`0x179EC`). **H**

> The filter commands (`:SENS:AVER:*`) aren't in the 510 list. Changing them while unlocked
> isn't blocked, but `:CAL:PROT:SENS`/`SOUR` will then fail with −221 (§3). **M**

---

## 3. Point acquisition and coefficient fitting

Both point handlers share the same gate and classifier. Here `FS` is the nominal full scale of the
active source range (`gFLOAT_ARRAY_VOLT` / `gFLOAT_ARRAY_CURR`), `x` is the command argument and
`src` is the programmed source level.

- Not unlocked → **509**.
- `:SENS` only: the cal state from §2.1 must still hold (sense func = source func, arm/trig count
  ≤ 1, arm source IMM, …), else **−221**.
- Source autorange on → **−221**.
- `|x| > 1.5·FS` → **−222**.
- Classification:

| condition | point |
|---|---|
| `x ≥ 0.75·FS` **and** `src ≥ 0.75·FS` | +FS |
| `x ≤ −0.75·FS` **and** `src ≤ −0.75·FS` | −FS |
| `|x| ≤ 0.5·FS` **and** `|src| ≤ 0.5·FS` | zero (source cal: + or − zero, taken from the polarity flag) |
| anything else | **−222** |

The +FS/−FS window is ≥ 75 % of range, so with Keithley's usual cal points (±FS and 0) the order of
points doesn't matter. Each point **overwrites** its slot, so repeating a point just replaces it.

### 3.1 `:CAL:PROT:SENS <reference>` → `CAL_COMPUTE_SENSE_COEFFICIENTS` (`0x50062`)

1. Set operation-condition bit 300 "Device calibrating", `TRIGGER_ABORT_TO_IDLE`, start one
   measurement (`FUN_0001288a`), and busy-wait until bit 31 of `*(PTR_00814784+0x1A)` clears.
2. Store `REF = x` and `RAW = *A5`. `A5` is `0x801920` for V and `0x80191C` for I: the uncalibrated
   A/D result for the sensed function.
3. Set the point bit. When the mask is `0x13`, fit:

```
gainA  = (PFS_REF − ZERO_REF) / (PFS_RAW − ZERO_RAW)      → row[0]
offset =  PFS_REF − gainA · PFS_RAW                       → row[2]
gainB  = (NFS_REF − offset) / NFS_RAW                     → row[1]
```

4. Validate against the model default row (`gDEFAULT_CALIBRATION_DATA[model]`, or the 2430 rev-D
   rows):
   - `|offset| > 0.5·FS` → **507** "Measurement offset data invalid"
   - `|gainA|` or `|gainB|` outside **0.5×…1.5× |default gain|** → **508** "Measurement gain data
     invalid" (the exact compare direction is inferred) **M**
5. Error → restore the previous row. OK → `ANALOG_LOAD_VOLTAGE_CAL` / `ANALOG_LOAD_CURRENT_CAL`
   reload `0x8018E4/E8/EC`, so the new constants take effect immediately.
6. Clear the mask and the status bit.

### 3.2 `:CAL:PROT:SOUR <measured>` → `CAL_COMPUTE_SOURCE_DAC_COEFFICIENTS` (`0x50328`)

Here `x` is what the **external DMM** measured. The handler pairs it with the DAC code currently
driving the output, read from `0x805230` (V-source path) or `0x80522E` (I-source path). These are
labelled `gDIAGNOSTIC_KEITHLEY_BITS_VDAC/IDAC`; the V/I labels may be swapped relative to the polarity
fields, so check before trusting them. **M** The code is converted to float.

| point | bit | stored in |
|---|---|---|
| +FS | 0x1 | `PFS_VALUE`, `PFS_DAC` |
| −FS | 0x2 | `NFS_VALUE`, `NFS_DAC` |
| zero, + polarity | 0x4 | `PZERO_VALUE`, `PZERO_DAC` |
| zero, − polarity | 0x8 | `NZERO_VALUE`, `NZERO_DAC` |

When the mask is `0xF`:

```
gain+   = (PFS_DAC − PZERO_DAC) / (PFS_VALUE − PZERO_VALUE)   → row[0]
offset+ =  PFS_DAC − gain+ · PFS_VALUE                         → row[2]
gain−   = (NFS_DAC − NZERO_DAC) / (NFS_VALUE − NZERO_VALUE)   → row[1]
offset− =  NFS_DAC − gain− · NFS_VALUE                         → row[3]
```

Validation:
- `offset+ < 0` or `offset− < 0` → **505** "Source offset data invalid"
- `gain+ · (+FS) + offset+ > 65535` or `gain− · (−FS) + offset− > 65535` → **506** "Source gain data
  invalid"

Error → restore the row. OK → `CAL_BUILD_DAC_RANGE_FS_CODES`. Mask cleared.

So the instrument never needs to know the true output. It programs a nominal setpoint through the
existing constants, the operator measures what actually comes out, and the firmware fits a straight
line from measured output to DAC code for each polarity.

### 3.3 `CAL_BUILD_DAC_RANGE_FS_CODES` (`0x14264`, was `CALIBRATION_DATA_VALIDATE`)

For every source range (4 V + 7 I) and each polarity `p ∈ {0: +, 1: −}`:
`fs = range × (1 − 2p)`, `code = round(row[p]·fs + row[p+2])`. The result is stored in
`gVDAC/gIDAC_RANGE_FS_TABLE`. `code < 0` → 0 and error **504** "DAC calibration underflow";
`code > 65535` → 0xFFFF and error **503** "…overflow". The `_RANGEMAX` DAC helpers read the table
for the compliance/limit DAC. It also runs at boot from `CALIBRATION_DATA_LOAD`. **H**

---

## 4. Persistence

**`CALIBRATION_WRITE_AND_INCREMENT`** (`0x171C4`, called by `:SAVE`):
`calibrationCount++` → checksum both blocks → `I2C_WRITE_DATA(CAL_DATA)`, `I2C_WRITE_DATA(CAL_INFO)`
→ clear questionable bit **408** → refresh annunciators. **H**

The firmware does **not** check for missing dates or incomplete steps here (errors 500/501 aren't
raised on this path), even though the manual says SAVE refuses. The only gate is "unlocked". The
fit routines already reject bad data, so invalid constants never reach the RAM row. **M**

**`CALIBRATION_DATA_LOAD`** (`0x17076`, at boot):
1. Read the cal-data block. On a checksum mismatch, copy the model's defaults from
   `gDEFAULT_CALIBRATION_DATA` and raise **604** "DC calibration data lost".
2. `CAL_BUILD_DAC_RANGE_FS_CODES`.
3. Read the cal-info block.
   - Checksum OK: fix up 2-digit years (`< 94 → +2000`, `< 100 → +1900`).
   - Checksum bad: password `KI00`+model name, last cal 16.3.1995, next 16.3.1996, count 0, and
     raise **605** "Calibration dates lost".
4. If either block failed → set questionable bit **408**.
5. Clear both point masks.

The EEPROM is **not** rewritten here, so the defaults stay in RAM until a SAVE.

---

## 5. Hidden factory helpers (`:DIAG:KEIThley:*`)

| Command | cmdId | Handler | Behaviour | Conf |
|---|---|---|---|---|
| `:UNLOCK` | 0x146 | `0x1F264` | Builds a fake `:CAL:PROT:CODE` command whose string argument is a **pointer to the stored password**, then falls through into the CODE handler. **Unlocks cal without knowing the password.** No password check. | H |
| `:CCR` | 0x171 | `0x1FF6E` | **Cal Count Reset**: `calibrationCount = 0`, rewrite the cal-info block | H |
| `:VREF <v>` | 0x18C | `0x20E40` | `v` ∈ 6.0…7.0 (default 6.2). Stores `round((v−6)·100)` in `gCURRENT_CONFIG.DIAGNOSTIC_KEITHLEY_VREF` and writes CURRENT_CONFIG to EEPROM. Doesn't touch cal data. | H |
| `:INITCAL` | 0x18D | `0x20EE2` | `CALIBRATION_APPLY_VREF_SCALING` (`0x2CC3E`): reload **all** rows from the model defaults, scale only the **sense gains** (rows 0–10, [0] and [1]) by `(6 + VREF/100) / 6.2`, recompute the checksum, write cal data to EEPROM, reload the A/D constants. The cal count and dates are untouched. | H |

So `:VREF` + `:INITCAL` is a factory "rough cal": it measures the on-board ~6.2 V reference and
pre-scales the default A/D gains before the real calibration. Note that `:INITCAL` **wipes the user
calibration** in EEPROM.

---

## 6. Front panel

| Function | Address | Behaviour |
|---|---|---|
| CAL pads (display board) → keycode `0x5A` | `FUNCTION_KEYCODE_0x5a_CAL_PADS_UNLOCK` `0x3F1E6` | Refused in pulse mode or if already unlocked. Otherwise: password = `KI00`+model name, **written to EEPROM**, then queues `:CAL:PROT:CODE` with it → unlocked. This matches the manual's "short CAL pads to reset password". **H** |
| MENU → CAL → UNLOCK | `MENU_ACTION_PASSWORD` `0x48590` | Builds `"KI" + entered digits`, space-pads to 8, `strcmp` with the stored password. Match → queues `:CAL:PROT:CODE`; else "INVALID PASSWORD" + beep. So the front panel can only unlock passwords that start with `KI`. |
| CHANGE-PASSWORD | `MENU_ACTION_CAL_CHANGE_PASSWORD` `0x48634` | Queues `:CAL:PROT:CODE "KI"+digits` while unlocked → new password saved immediately |
| LOCK | `MENU_ACTION_CALIBRATION` `0x484D0` | Queues `COMMAND_ID_CALIBRATION_PROTECTED_LOCK` |
| EXECUTE step setup | `MENU_SETUP_CAL_EXECUTE_STEP` `0x48686` | Sets `gFP_CAL_STEP_ACTIVE`, queues `:OUTP OFF`, proposes a cal value of `range / 1.05` (the nominal full-scale — the range tables hold 105 % values, see below). On a 2410 1 kV range it uses a fixed **975 V**. **H** |
| Menu gating | `MENU_GET_NEXT_MENU_WITH_CAL_LOCK` `0x3F780` | "CAL ALREADY UNLOCKED", "ENTER PASSWORD TO UNLOCK", "Invalid selection with cal enabled" (A/D controls) |

### 6.1 Front-panel EXECUTE sequence (traced)

EXECUTE drives a **4-point manual-calibration walk** through a dedicated menu sub-tree (nodes at
`0x65528…`, label strings **"X-CAL" / "Press ENTER to Output"** and **"DMM RDG:"**). Each cal point
is a **two-step pair**:

1. **"X-CAL — Press ENTER to Output"** — `MENU_SETUP_CAL_EXECUTE_STEP` (`0x48686`): sets
   `gFP_CAL_STEP_ACTIVE`, queues `:OUTP OFF`, and proposes the editable source value
   `gFLOAT_ARRAY_VOLT[Vrange] / 1.05` (resp. `gFLOAT_ARRAY_CURR[Irange] / 1.05`) — i.e. the nominal
   range full-scale (975 V on the 2410 1 kV range). **ENTER →**
   `MENU_ACTION_CAL_EXECUTE_ENTER` (`0x48712`): queues `SOUR:VOLT|CURR:LEV = value` then `:OUTP ON`,
   so the SMU outputs that point.
2. **"DMM RDG:"** — `MENU_SETUP_CAL_READING_DISPLAY` (`0x48758`) formats the reading field; the user
   keys in the value measured on an external DMM. **ENTER →**
   `MENU_ACTION_CAL_SUBMIT_DMM_READING` (`0x48AE4`): queues `:CAL:PROT:SOUR <rdg>` (cmdId `0x14D`)
   **and**, on every node except the last, `:CAL:PROT:SENS <rdg>` (cmdId `0x14B`). So a single
   reading calibrates **source and sense together**, through the very same coefficient-fit path as
   remote calibration (§3.1 / §3.2).

**`gFLOAT_ARRAY_VOLT` (`0x80580C`) / `gFLOAT_ARRAY_CURR` (`0x8051F4`)** are the **source V/I per-range
full-scale tables** — not cal-specific buffers. `RANGE_TABLES_INIT` (`0x4F85A`) builds them at
start-up from a per-model ROM table (`0x5A278`) as `nominal × 1.05` (V) / `× 1.055` (I), which is why
the EXECUTE step divides by 1.05 to recover the nominal full-scale. They are read throughout the
source/range path (`RANGE_FIND_VOLTAGE`, `ANALOG_LOAD_VOLTAGE_CAL`, `SOURCE_VOLTAGE_RESOLUTION`,
`CAL_BUILD_DAC_RANGE_FS_CODES`, …). Menu strings for the sequence live around `0x6E6CC…0x701DC`.

---

## 7. Security observations

The password is a speed bump, not a lock. Any of the following unlocks calibration remotely:

- `:DIAG:KEIT:UNLOCK` (no password needed)
- `:CAL:PROT:CODE?` after an unlock leaks the password
- `:DIAG:KEIT:CCR` hides how many times the unit was recalibrated

---

## 8. Typical remote cal flow (what the firmware expects)

```
:CAL:PROT:CODE 'KI002400'        # unlock (forces NPLC1, filter 10, IMM triggers, fixed source)
# per function and range:
:SOUR:FUNC VOLT ; :SOUR:VOLT:RANG 2 ; :SOUR:VOLT 2 ; :OUTP ON
:CAL:PROT:SOUR <DMM reading>     # +FS source point
:CAL:PROT:SENS <DMM reading>     # +FS sense point (instrument takes its own reading)
:SOUR:VOLT 0
:CAL:PROT:SOUR <DMM> ; :CAL:PROT:SENS <DMM>   # zero (+ polarity)
:SOUR:VOLT -2
:CAL:PROT:SOUR <DMM> ; :CAL:PROT:SENS <DMM>   # −FS → sense fit runs here
:SOUR:VOLT -0                    # zero with − polarity → source fit completes
:CAL:PROT:SOUR <DMM>
...
:CAL:PROT:DATE 2026,11,20 ; :CAL:PROT:NDUE 2027,11,20
:CAL:PROT:SAVE                   # count++, write EEPROM
:CAL:PROT:LOCK
```

The source fit needs both a +zero and a −zero point; which one a zero becomes depends on the polarity
flag (`0x80472B` for V, `0x804769` for I). **M** [../cal2400.py](../cal2400.py) (xDevs) follows this
pattern.

---

## 9. Error codes produced by the cal code

| Err | Index | Raised by |
|---|---|---|
| −221 settings conflict | 0x17 | SENS/SOUR with cal state broken or source autorange on |
| −222 data out of range | 0x16 | SENS/SOUR point outside the windows; bad DATE/NDUE |
| −224 illegal parameter | 0x14 | wrong password / bad new password |
| 300 device calibrating | 0x53 | status bit while a point is measured |
| 408 questionable calibration | 0x58 | set at boot on lost data, cleared by SAVE |
| 502 cal data invalid | 0x5C | `SENS:DATA`/`SOUR:DATA` without exactly 4 values |
| 503 / 504 DAC overflow / underflow | 0x5D/0x5E | `CAL_BUILD_DAC_RANGE_FS_CODES` |
| 505 / 506 source offset / gain invalid | 0x5F/0x60 | source fit |
| 507 / 508 measurement offset / gain invalid | 0x61/0x62 | sense fit |
| 509 not permitted with cal locked | 0x63 | all cal setters except CODE/LOCK; `CODE?` |
| 510 not permitted with cal unlocked | 0x64 | §2.2 |
| 604 / 605 DC cal data / dates lost | 0x68/0x69 | `CALIBRATION_DATA_LOAD` |
| 831 invalid in pulse mode | 0x8D | CODE, CAL pads |

500/501 (dates not set) exist in the error table, but I found no use of them on the cal path.

---

## 10. Renames made in Ghidra

| Address | Old name | New name | Why |
|---|---|---|---|
| `0x50062` | `CAL_COMPUTE_SOURCE_COEFFICIENTS` | `CAL_COMPUTE_SENSE_COEFFICIENTS` | writes sense rows, returns 507/508 |
| `0x50328` | `CAL_COMPUTE_MEASURE_COEFFICIENTS` | `CAL_COMPUTE_SOURCE_DAC_COEFFICIENTS` | writes source rows, returns 505/506 |
| `0x14264` | `CALIBRATION_DATA_VALIDATE` | `CAL_BUILD_DAC_RANGE_FS_CODES` | builds the DAC FS code tables |
| `0x57184` | `PASCAL_STRLEN` | `PASCAL_STRCMP` | two args, returns 0 on equal |
| `0x3F1E6` | `FUNCTION_KEYCODE_0x5a_unknown` | `FUNCTION_KEYCODE_0x5a_CAL_PADS_UNLOCK` | §6 |
| `0x48634` | `MENU_ACTION_00048634` | `MENU_ACTION_CAL_CHANGE_PASSWORD` | |
| `0x48686` | `MENU_SETUP_00048686` | `MENU_SETUP_CAL_EXECUTE_STEP` | |
| `0x8035E3` | `gCALIBRATION_PROTECTED_LOCK` | `gCALIBRATION_UNLOCKED` | polarity was inverted |
| `0x80470D` | `CONFIG_0x19E_CHECKSUM.PROTECTION_TRIPPED` | `…bSOURCE1_FUNCTION_MODE` | struct field = active SOURce function (0 V / 1 I / 4 MEM), not a protection flag |
| various | `SHORT_/FLOAT_/DAT_…` | `gCAL_*`, `gVDAC/gIDAC_RANGE_FS_TABLE`, `gFP_CAL_STEP_ACTIVE`, `gDEFAULT_CAL_2430_REVD_ISENSE_R5/R6` | §1.5 |

Pre-comments were added at every inline cal handler (`0x1F264…0x1FB6A`, `0x1FF6E`, `0x20E40`,
`0x20EE2`, `0x179EC`), and plate comments on the fit and build functions.

### Open items

**Resolved**

- ~~Check whether the V/I labels of `0x805230`/`0x80522E` vs. polarity fields `0x80472B`/`0x804769`
  are swapped.~~ **Not swapped.** `0x805230` is the **voltage** DAC code and `0x80522E` the
  **current** DAC code: each is written only by its own `ANALOG_BUILD_*SRCV*/*VDAC*` resp.
  `*SRCI*/*IDAC*` frame builders and read back only by `ANALOG_COMPUTE_VDAC_*` / `CAL_COMPUTE_VDAC_*`
  resp. the `IDAC` equivalents; and `CAL_COMPUTE_VDAC_CODE` operates on the voltage cal rows
  (`gCALIBRATION_DATA.field5_0xb0`, the `0xB0` V block) while `CAL_COMPUTE_IDAC_CODE` uses the current
  rows (`field6_0xf0`, `0xF0` I). The appearance of a swap comes from the two **polarity bytes**
  `0x80472B`/`0x804769`, which are **not** a V-polarity/I-polarity pair — each is bound to one of two
  ±-column selector indices in `gCONFIG_0x19E` (now named `bCAL_COLUMN_SEL_A` `+0xEB` /
  `bCAL_COLUMN_SEL_B` `+0x129`) that pick the gain±/offset± half of a 4-float cal row, and the runtime
  (`ANALOG_COMPUTE_*`) and cal (`CAL_COMPUTE_*`) paths pair them differently. They are deliberately
  **not** labelled `gVDAC_POLARITY` / `gIDAC_POLARITY` (nor V/I); they read as two source/compliance
  sign selectors. (Which byte is source-sign vs compliance-sign is the one detail still unconfirmed.)

- ~~`:DATA?` ↔ `:DATA` argument order round-trip (§2).~~ **Round-trip is safe.** SET stores
  `a,b,c,d` as row `[0]=a,[1]=c,[2]=b,[3]=d`; `DATA?` emits `[0],[2],[1],[3]` via
  `RESPONSE_ADD_4_floats` (`0x3AB82`) — the read-swap inverts the write-swap, so `DATA?` returns
  `a,b,c,d` and re-feeding it into `DATA` reproduces the identical row (both SENS and SOUR). See §2.

- ~~Trace the front-panel EXECUTE sequence and the contents of `gFLOAT_ARRAY_VOLT/CURR`.~~
  **Done — see §6.1.** EXECUTE is a 4-point manual walk: each point drives the output to the nominal
  range full-scale (`gFLOAT_ARRAY_VOLT/CURR[range] / 1.05`), then a "DMM RDG:" entry submits the
  reading as `:CAL:PROT:SOUR` (+ `:SENS` on all but the last node), reusing the §3 fit path.
  `gFLOAT_ARRAY_VOLT`/`CURR` are the source range full-scale tables (`nominal × 1.05 / × 1.055`,
  built by `RANGE_TABLES_INIT`), not cal-specific buffers.

_All open items resolved._
