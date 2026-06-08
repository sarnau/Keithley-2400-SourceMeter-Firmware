# Keithley 2400 — SCPI Command Engine (Reverse-Engineering Notes)

How the firmware receives, parses, dispatches, and executes SCPI / IEEE-488.2 commands.
All addresses are Ghidra addresses, which equal file offsets in `2400-FIRMWARE.bin` (the image
is a flat binary loaded at 0). CPU is an MC68332 (CPU32, big-endian). See [README.md](README.md),
[DATASHEETS.md](DATASHEETS.md), and [SUMMARY.md](SUMMARY.md) for hardware/context.

Companion artifacts in this repo:
- [SCPI_COMMANDS.txt](SCPI_COMMANDS.txt) — full command tree (names, cmdIds, parameter enums), produced by [dump_scpi.py](dump_scpi.py)
- [SCPI_DISPATCH.txt](SCPI_DISPATCH.txt) — every cmdId → SET/QUERY handler address + R/RW settability, produced by [dump_dispatch.py](dump_dispatch.py)

---

## 1. Command lifecycle (end to end)

```
GPIB (TMS9914A @0x090000) / RS-232 (QSM SCI)
        │   byte at a time
        ▼
COMM_PARSER_STATE_PROCESS_NEXT (0x2D242)      receive state machine (gRECEIVE_STATE)
        │   each char classified, then:
        ▼
gPARSER_FUNC_TABLE[gPARSER_FUNC_INDEX]()       per-char parser state machine (table @0x5CD12)
        │   • match command name token against the SCPI tables
        │   • parse argument(s) per the command's paramType
        ▼
gPARSER_VALUE  (@0x802800)                      parsed record {cmdId, isQuery, params...}
        │   serialized into a 2-entry queue
        ▼
COMMAND_TABLE[2]                                command queue (gCOMMAND_DATA_PTR cached @0x804628)
        │
        ▼
EXECUTE_COMMAND_TILL_DONE (0x168FE)            main-loop executor pump (FUNCPTR_EXECUTE_COMMAND @0x8086D8)
        │   EXECUTE_NEXT_COMMAND routes by query flag:
        ├── set   → settability gate (0x72C2C) → EXECUTE_COMMAND_MAIN  (0x17694)
        ├── query → EXECUTE_COMMAND_QUERY (0x20F1A)
        └── special (cmdId 0x01) → EXECUTE_COMMAND_C (0x16CA0)
        │   cmdId → 16-bit-offset jump table → inline handler block
        ▼
handler executes (range-validates, acts on hardware, builds response)
```

---

## 2. Command tables (the SCPI grammar, as data)

Two root tables, each an array of pointers to `Command` structs:

| Root table | Address | Entries | Contents |
|---|---|---|---|
| `COMMANDS_ROOT_SCPI` | `0x635DA` | 65 | the `:SUBSYSTEM` tree (18 top-level subsystems) |
| `COMMANDS_ROOT_COMMON` | `0x63714` | 14 | the IEEE-488.2 common (`*`) commands |

**Table header** (`>LB`): 4-byte offset to the entry array, 1-byte entry count.
**Entry**: 4-byte big-endian pointer to a `Command`.

**`Command` struct — 18 bytes (`>LBBHBxLL`):**

| Off | Type | Field | Meaning |
|---|---|---|---|
| 0x00 | u32 | nameOffset | → command name string |
| 0x04 | u8 | nameLen | short-form length (for SCPI long/short casing) |
| 0x05 | u8 | cmdType / commandFlags | 0=node, 1=branch, 2=executable, 4=… |
| 0x06 | u16 | **cmdId** | dispatch id (0x01–0x18D) |
| 0x08 | u8 | paramType | argument type (see §5) |
| 0x09 | — | pad | |
| 0x0A | u32 | →paramTable | nested table of parameter enum keywords |
| 0x0E | u32 | →subTable | nested table of sub-commands |

Commands nest recursively to form the tree. For enum-parameter commands, the param sub-table
holds `Command` entries whose **cmdId is the enum value** (e.g. `0x00CD:OUTPut … 4:TENTer,2:TEXit,1:TRIGger,0:NONE`).

Ghidra has a `COMMAND_ID_ENUM` mapping cmdId→name. Full dump: [SCPI_COMMANDS.txt](SCPI_COMMANDS.txt).

### Top-level subsystems
`:ARM` · `:TRIGger` · `:SOURce1` · `:SOURCE2` · `:SENSe1` · `:CURRent` · `:VOLTage` · `:RESistance` ·
`:CALCulate1` · `:CALCULATE2` · `:CALCULATE3` · `:CALibration` · `:DISPlay` · `:ROUTe` · `:STATus` ·
`:SYSTem` · `:TRACe` · `:DIAGnostic`

### Common commands (`0x63714`)
`*CLS *ESE *ESR *IDN *OPC *OPT *RCL *RST *SAV *SRE *STB *TRG *TST *WAI` (cmdIds 0x02–0x10).

### Hidden `:DIAGnostic:KEIThley` subtree (not in the manuals)
Factory/service commands, gated by the boot-time `gDIAGNOSTIC_KEITHLEY_SECRET` flag (hold key
combo `0x86` at power-on). Includes `:IBBR` (set model id `KI2400…KI2425`), `:BITS`/`:SET`
(raw `VDAC`/`IDAC`/`MUX`/`RNG`/`AFB`/`SIG1/2`/`REF`/`ZERO` access), `:MELTDOWN`, `:OTDIS`,
`:NOPULSE`, `:KEYLOCK JUAREZ|FEDERAL`, `:SECRET`, `:LVOL`, `:INITCAL`, board-rev queries.

---

## 3. Receive & parser state machines

**Receive** — `COMM_PARSER_STATE_PROCESS_NEXT` (`0x2D242`), driven by `gRECEIVE_STATE`:
- pulls a byte from GPIB (`gGPIB_GET_BYTE`, TMS9914A) or RS-232 (`RS232_GET_BYTE_FROM_RCVBUF`)
- classifies the char (`TMS9914A_PARSER_SETUP_STATE` → `gPARSER_STRUCT.state`, e.g. ALPHA, DIGIT, `+`/`-`, `.`, `;`, LF, `?`, `#`, `"`/`'`, `(`…)
- GPIB `0xAAAA` magic → injects the implicit `:READ?` (`COMMAND_ID_READ`)
- runs the current parser state: `gPARSER_FUNC_TABLE[gPARSER_FUNC_INDEX]()`

**Parser state table** — `gPARSER_FUNC_TABLE @0x5CD12`, ~20+ function pointers indexed by
`gPARSER_FUNC_INDEX`. Notable states:

| State | Handler | Role |
|---|---|---|
| 9 | `PARSER_FUNCTION_9_NEXT_CHAR` (0x2E954) | match a command-name token; `?`→query, space→param state |
| 8 | `PARSER_FUNCTION_8` (0x2E61E) | **parameter dispatch** (number / keyword / string / list / block) |
| 10 | `PARSER_FUNCTION_10` (0x2EB0C) | restricted param dispatch variant (rejects keywords) |
| 13–16 | — | number accumulation: 13 leading-0/base, 14 signed, 15 integer, 16 fraction |
| 24 | — | quoted-string accumulation |
| 31 | — | enum-keyword accumulation |
| 49 | — | `(` channel/number list / expression |
| 76 | — | `#` IEEE-488.2 block data |
| 126 | `PARSER_FUNCTION_126_DONE` | terminal/error finalize |

**Token matcher** — `PARSER_FUNCTION_COMMAND_FIND(list)` (`0x2F226`): exact-compares the accumulated token
(`gCOMMAND_NAME` / `gCOMMAND_NAME_LEN`) against each entry of `list` and sets `gCOMMAND_PTR`.
The search list is `gPARSER_COMMAND_NEXT`, which is reset to `COMMANDS_ROOT_SCPI` by
`PARSER_FUNCTION_COMMAND_RESET_TO_SCPI_COMMANDS` (`0x2F1F2`) and advanced to a command's
sub-table / param-table as the tree is descended.

---

## 4. Parsed-command record `gPARSER_VALUE` (@0x802800)

Written by `PARSER_FUNCTION_SET_CMD_IS_QUERY/_NOT_QUERY` and the param states:

| Addr | Field |
|---|---|
| 0x802801 | isQueryCommandFlag (byte) |
| 0x802802 | **cmdId** (word) |
| 0x802804 | currentParamIndex (word) |
| 0x80280C + i·0x22 | paramValue[i] (per-arg value record, 0x22-byte stride) |
| — | paramType[i] (per-arg type) |

On a terminator the parser sets `parsingCompleteFlag` and the record is serialized into the
2-entry `COMMAND_TABLE` queue (`PARSER_FUNCTION_00035364` is the (de)serializer).

---

## 5. Parameter parsing & `paramType`

After a command name + space, `PARSER_FUNCTION_8` finalizes the match and branches on the
**first argument character × `gCOMMAND_PTR->paramType`**:

| First char | Required paramType | Path |
|---|---|---|
| digit / `+` `-` / `.` | numeric (INT, BOOL, NUMLIST, 0x12–0x17) | `PARSER_FUNCTION_NUMBERS_INIT`; numeric width selector `WORD_00800212` set from paramType → number states 13/14/15/16 |
| ALPHA | enum keyword | accumulate (`UPPER_BUF`) → state 31 → match param sub-table; **enum entry cmdId = value** |
| `"` / `'` | STR | string buffer → state 24 (display text, math expression, **cal password**) |
| `(` | numlist / expression | state 49 |
| `#` | 0x17 | state 76 (block data) |
| `;` / LF, paramType NONE/0x0E | (no argument) | execute immediately |

`paramType` is an enum-ish field (values incl. INT, BOOL, STR, NUMLIST=0x10, 0x12, 0x13, 0x14,
0x16, 0x17, 0x0E, NONE). The numeric **type-size selector** `WORD_00800212` is derived from it
(INT/BOOL/NUMLIST/0x17→1, 0x12→2, 0x13/0x14→2, 0x16→0x62…), telling the number states whether to
store byte/short/long/float. `dump_scpi.py` renders the low bits as `<intvalue>`/`<str>`/`<b>`/
`<strlist>`/`<numlist>` for readability.

---

## 6. Command queue & executor pump

The main loop (`main` @0x4492) calls `EXECUTE_COMMAND_TILL_DONE` (`0x168FE`), which pumps the RAM
function pointer `FUNCPTR_EXECUTE_COMMAND` (`@0x8086D8`) until it returns 0.

`EXECUTE_NEXT_COMMAND` (`0x16D6A`) pops `COMMAND_TABLE[idx]` (→ `gCOMMAND_DATA_PTR`, ptr cached at
`0x804628`) and, when `parsingCompleteFlag` is set, selects the executor:

| Condition | Next state |
|---|---|
| not a query | `EXECUTE_COMMAND_MAIN` (0x17694) — set/write |
| query | `EXECUTE_COMMAND_QUERY` (0x20F1A) — read |
| `LONG_00803860 != 0` | `EXECUTE_COMMAND_C` (0x16CA0) — special; handles device-clear cmdId 0x01 |

`gCOMMAND_DATA_PTR->cmdId` is at struct offset +2.

---

## 7. Dispatch — cmdId jump tables

Both executors switch on cmdId via 68k PC-relative **16-bit-offset jump tables**:
```
move.w  0x2(a0),d0           ; d0 = cmdId   (a0 = gCOMMAND_DATA_PTR)
sub     #K,d0                ; index = cmdId - K
cmpi.l  #LIM,d0 ; bhi DEFAULT ; range check
move.w  BASE(pc,d0.l),d1     ; 16-bit offset
jmp     BASE(pc,d1.w)        ; handler = BASE + int16(table[index])
```
Handlers are **inline code blocks, not separate functions**, and are frequently **shared** across
related commands (e.g. `0x1EE68` implements the SET side of 11 range/NPLC commands across
CURR/VOLT/RES; `0x1798E` serves `*RST`/`*RCL`/`:SYST:PRES`).

| Path | Table base | Index | cmdId range | "no handler" default |
|---|---|---|---|---|
| SET A | `0x176E4` | cmdId − 0x001 | 0x001–0x07E | `0x20EEA` |
| SET B | `0x1C310` | cmdId − 0x081 | 0x081–0x14E | `0x20EEA` |
| SET C | `0x1FE18` | cmdId − 0x150 | 0x150–0x18D | `0x20EEA` |
| QUERY | `0x21156` | cmdId − 0x003 | 0x003–0x18C | `0x270CE` |

`:READ` (cmdId 0x3C) is special-cased inline at `0x20F72` ahead of the query table (hot path).

Totals: 399 cmdIds — **345 with a SET handler, 327 with a QUERY handler**. Full map (with names):
[SCPI_DISPATCH.txt](SCPI_DISPATCH.txt).

---

## 8. Settability gate — `0x72C2C`

A 1-byte-per-cmdId table indexed directly by cmdId, read once at the top of
`EXECUTE_COMMAND_MAIN`:
```
tst.b  0x72C2C(d0.l)   ; d0 = cmdId
beq.l  0x20EEA         ; attr == 0  → reject the write (error)
```

| Value | Count | Meaning |
|---|---|---|
| 0 | 72 | **query-only** — a write/set form is rejected before the SET table is consulted |
| 1 | 327 | **settable** (`set+qry`) |
| 2 | 1 | special / internal pseudo-command (`0x18F`, unnamed) |
| 0xFF | — | end-of-table marker (`0x191`) |

The 72 `attr==0` entries are all read-only nodes (`*IDN?`/`*ESR?`/`*STB?`/`*TST?`/`*OPT?`,
`:READ`/`:FETCh`/`:DATA`/`:MEASure:*`/`:CONFigure`, `:SYSTem:ERRor*`/`:VERSion`/`:TIME`, every
`:STATus:*` condition/event read, `:CALCulate*:DATA`, `:…:TRIPped`, `:CALCulate2:LIM*:FAIL`,
`:CALibration:PROTected:COUNt`, `:DIAGnostic:KEIThley` readbacks). This is the `W` column in
[SCPI_DISPATCH.txt](SCPI_DISPATCH.txt) (R = query-only, RW = settable, S = special).

---

## 9. Validation & errors (two layers)

1. **Parse-time (syntax/type)** — sets `gPARSER_ERROR` (an `ERR_INDEX_*` enum):
   `-100` command, `-101` invalid character, `-102` syntax, `-104` data type, `-109` missing
   parameter, `-110` command header, `-112` mnemonic too long, `-113` undefined header.
2. **Execution-time (semantic/range)** — inside the per-command handler:
   `-221` settings conflict, `-222` data out of range, plus Keithley `+8xx` execution errors
   (`+826` exceed power limit, `+828` invalid on 1 A range, `+831` invalid in pulse mode, …) and
   the `+5xx` calibration errors. The error table is at `0x679B2` (143 entries; see
   `firmware_errors.py`). Errors are queued and surfaced via `:SYSTem:ERRor?` / the EAV status bit.

---

## 10. Key addresses

| Symbol | Address | Notes |
|---|---|---|
| `COMMANDS_ROOT_SCPI` | `0x635DA` | subsystem command table header |
| `COMMANDS_ROOT_COMMON` | `0x63714` | `*` command table header |
| `gPARSER_FUNC_TABLE` | `0x5CD12` | parser state → handler fn-ptr array |
| `COMM_PARSER_STATE_PROCESS_NEXT` | `0x2D242` | receive state machine |
| `PARSER_FUNCTION_9_NEXT_CHAR` | `0x2E954` | command-name matcher state |
| `PARSER_FUNCTION_8` | `0x2E61E` | parameter dispatch state |
| `PARSER_FUNCTION_COMMAND_FIND` | `0x2F226` | token matcher |
| `PARSER_FUNCTION_COMMAND_RESET_TO_SCPI_COMMANDS` | `0x2F1F2` | `gPARSER_COMMAND_NEXT = root` |
| `gPARSER_VALUE` | `0x802800` | parsed-command scratch record |
| `gPARSER_COMMAND_NEXT` | (RAM) | current search table pointer |
| `gCOMMAND_PTR` | (RAM) | last matched `Command` |
| `EXECUTE_COMMAND_TILL_DONE` | `0x168FE` | executor pump |
| `FUNCPTR_EXECUTE_COMMAND` | `0x8086D8` | current executor state (RAM fn-ptr) |
| `EXECUTE_NEXT_COMMAND` | `0x16D6A` | queue pop + query/set routing |
| `EXECUTE_COMMAND_MAIN` | `0x17694` | SET dispatcher |
| `EXECUTE_COMMAND_QUERY` | `0x20F1A` | QUERY dispatcher (largest fn, 6634 instr) |
| `EXECUTE_COMMAND_C` | `0x16CA0` | special (device clear) |
| `gCOMMAND_DATA_PTR` cache | `0x804628` | active queue entry |
| settability table | `0x72C2C` | per-cmdId write gate |
| SET default (no handler) | `0x20EEA` | |
| QUERY default (no handler) | `0x270CE` | |
| error table | `0x679B2` | 143 `{errNo, event, →string}` entries |

---

## 11. Tooling

| Script | Purpose |
|---|---|
| [dump_scpi.py](dump_scpi.py) | walk the command tables → full command tree ([SCPI_COMMANDS.txt](SCPI_COMMANDS.txt)) |
| [dump_dispatch.py](dump_dispatch.py) | decode the jump tables + settability gate → cmdId→handler map ([SCPI_DISPATCH.txt](SCPI_DISPATCH.txt)) |
| [Keithley2400.py](Keithley2400.py) | Ghidra/Jython version of the table walk (annotates the program) |

Both `dump_*.py` read the flat binary directly (file offset == address); no Ghidra needed.
