# Keithley 2400 — Software Floating-Point Library (`PASCAL_*`)

The MC68332 / CPU32 has **no FPU**, so all floating-point math (measurement readings, calibration,
math functions, sweeps) goes through a software float/double library. The routine naming and ABI
indicate the firmware was built with a **Pascal compiler** and links its runtime — hence the
`PASCAL_*` names. Addresses are Ghidra addresses = file offsets in `2400-FIRMWARE.bin` (big-endian).

This library is used **2087 times** across 27 public entry points. It is the backbone of the A/D
reading computation ([MEASURE.md](MEASURE.md) §3) and the calibration / math subsystems.

## Layout

- **Public entry points** live at `0x56C00–0x57200` — thin **Pascal-ABI stubs** that pull operands
  off the stack into registers and tail-call a worker.
- **Workers** (the real exponent/mantissa math) live at `0x52000–0x55000`.
- Formats: IEEE-style **float** = 32-bit (1 long); **double** = 64-bit (2 longs, passed/returned as
  a `d0:d1` pair). Args are passed Pascal-style on the stack; results come back on the stack or in
  `d0` / `d0:d1`.

Identification method: arithmetic ops were pinned by **worker adjacency** — SUB shares the ADD
worker via a sign-flip entry a few bytes earlier (float `0x52A00`→`0x52A04`; double
`0x5302E`→`0x53034`); MUL XORs operand signs; DIV swaps operands. Conversions were pinned by stub
signature (operand/return widths) and caller context.

## Arithmetic

| Addr | Name | Worker | Calls | Notes |
|---|---|---|---|---|
| `0x56F30` | `PASCAL_FLOAT_ADD` | `0x52A04` | 85 | |
| `0x56F8C` | `PASCAL_FLOAT_SUB` | `0x52A00` | 68 | sign-flip → falls into ADD worker |
| `0x56F74` | `PASCAL_FLOAT_MULT` | `0x56D56` | 122 | core = `PASCAL_FLOAT_MUL_CORE` |
| `0x56F5C` | `PASCAL_FLOAT_DIV` | `0x53170` | 94 | |
| `0x56F48` | `PASCAL_FLOAT_CMP` | `0x54CA8` | 168 | strips sign bits, compares magnitudes; returns int |
| `0x56E04` | `PASCAL_DOUBLE_ADD` | `0x53034` | 120 | |
| `0x56E7C` | `PASCAL_DOUBLE_SUB` | `0x5302E` | 67 | sign-flip → falls into ADD worker |
| `0x56E5C` | `PASCAL_DOUBLE_MUL` | `0x5326C` | 214 | XOR operand signs |
| `0x56E3C` | `PASCAL_DOUBLE_DIV` | `0x535EE` | 72 | swaps operands; was mis-named `..._2_DOUBLE_*` |
| `0x56E24` | `PASCAL_COMPARE_DOUBLES` | — | 137 | returns ordering (int) |

## Conversions

| Addr | Name | Direction | Calls | Conf. |
|---|---|---|---|---|
| `0x5703E` | `PASCAL_LONG_TO_FLOAT` | i32 → float | 56 | ✓ |
| `0x5704E` | `PASCAL_REG_ULONG_TO_DOUBLE` | u32 → double | 79 | ✓ |
| `0x5702E` | `PASCAL_LONG_2_DOUBLE` | i32 → double | 64 | likely |
| `0x56FA4` | `PASCAL_FLOAT_2_DOUBLE` | float → double | 271 | ✓ (most-called routine) |
| `0x56E9C` | `PASCAL_DOUBLE_2_FLOAT` | double → float | 94 | likely |
| `0x56EC8` | `PASCAL_DOUBLE_2_LONG` | double → i32 (truncate / Pascal `Trunc`) | 23 | ✓ |
| `0x56FC8` | `PASCAL_FLOAT_2_LONG` | float → i32 (truncate / Pascal `Trunc`) | 64 | ✓ (used by the DAC handler to make the integer code) |
| `0x57096` | `PASCAL_REG_LONG_2_FLOAT` | i32 → float (register ABI) | 70 | ✓ (Ghidra-confirmed normalize loop) |

### Rounding conversions (Pascal `Round` — round-to-nearest, vs the truncating `*_2_LONG` above)

| Addr | Name | Direction | Worker | Calls | Conf. |
|---|---|---|---|---|---|
| `0x56EB4` | `PASCAL_DOUBLE_ROUND` | double → i32 (round) | `0x533B6` | 37 | ✓ (adds ±0.5: `0xBFE00000`/`0x3FE00000`) |
| `0x56FB8` | `PASCAL_FLOAT_ROUND` | float → i32 (round) | `0x54E34` = `REG_FLOAT_2_LONG` | 23 | likely (routes through rounding core `0x54E5C`) |

## Helpers

| Addr | Name | Role |
|---|---|---|
| `0x56D56` | `PASCAL_FLOAT_MUL_CORE` | mantissa-multiply core for `FLOAT_MULT` |
| `0x558B4` | `DOUBLE_ABS` | absolute value (double) |
| `0x529F8` | (negate-if-negative helper) | small `bpl;neg.l d0;rts` abs/neg helper |
| `0x5710C` | `PASCAL_FLOAT_2_STRING` | format a float to text (calls the number formatter `0x57B1C`) |

## Not floating point (adjacent Pascal runtime, swept up by the address-range scan)

These sit in the same `0x57xxx` band but are string / memory routines:

| Addr | Name | Role |
|---|---|---|
| `0x57184` | `PASCAL_STRLEN` | string length (uses the `0x80808080` zero-byte test) |
| `0x5715C` | `PASCAL_STRCHR` | scan string for a byte |
| `0x57144` | `PASCAL_STRCAT` | append (find NUL, copy) |
| `0x571E4` | (bounded string copy — unnamed) | strncpy/strncat-style |
| `0x56CD8` | (sized block move — unnamed) | memcpy/memmove-style |

## Workers (real implementations in `0x52000–0x55000`)

The `0x56Exx`/`0x57xxx` entries above call these; a few already carry Ghidra names:
`0x52A04` float-add, `0x52A00` float-sub entry, `0x53034` double-add, `0x5302E` double-sub entry,
`0x5326C` double-mul, `0x535EE` double-div, `0x53170` float-div, `0x54CA8` float-cmp,
`0x54E34` = `REG_FLOAT_2_LONG`, `0x54E5C` = shared round-to-int core (calls round helper `0x54E8C`),
`0x54E1E` = long→float worker. Left as `FUN_*` (not separately documented) — they are internal and
only reached through the named API above.

## Notes for reverse engineering

- The `PASCAL_` prefix + stack ABI means **all numeric code in this firmware is Pascal-compiled**;
  expect Pascal string descriptors and runtime helpers (STRLEN/STRCHR/etc.) elsewhere.
- When reading any measurement / calibration / math routine, calls into `0x56Exx`–`0x57xxx`
  are float ops — substitute the names above to read the arithmetic.
- The worker region `0x52000–0x55000` is the actual soft-float implementation; the `0x56Exx`
  entries are the callable API.
