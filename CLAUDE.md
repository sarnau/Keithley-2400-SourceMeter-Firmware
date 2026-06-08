# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **reverse-engineering project** for the firmware of a Keithley 2400 SourceMeter (SMU), version C34. There is no application source to build — the "code" is a Motorola 68k binary analyzed in Ghidra, plus a set of Python helper scripts that extract structure from the firmware and the instrument's EEPROM. Analysis findings live inside the Ghidra database (renamed functions, comments, data types, enums), not in source files.

## Target hardware (context for all analysis)

- **CPU:** Motorola MC68332 (CPU32 core, a 68020-class 68k variant) with on-chip TPU (Time Processor Unit). Big-endian.
- **GPIB:** TI TMS9914A controller at `0x090000`.
- **Config storage:** Microchip 24LC16B 2KB I2C EEPROM (dumped as `24LC16B.bin`). Holds calibration + all user config; survives power loss.
- **Firmware flash:** two AT49F002T chips — U15 = ODD/MSB (`2400-803*.x`), U16 = EVEN/LSB (`2400-804*.x`). The combined image is `2400c34.x`.

### Memory map (see `README.md` for detail)
- `0x000000-0x07FFFF` 512KB flash: booter `0x0000-0x0FFF`; RAM-copied code `0x1000-0x3FFF`; vector table + main firmware from `0x4000`.
- `0x080000-0x083FFF` 256KB RAM · `0x090000` TMS9914A · `0xF00000-0xF007FF` TPU RAM · `0xFFF000-0xFFFFFF` MC68332 I/O registers.

## Two kinds of Python scripts — do not confuse them

**Standalone Python 3** (run from the shell, operate on `.bin`/`.x` files on disk):

| Script | Purpose | Run |
|---|---|---|
| `read_firmware.py` | Parse Motorola S-records and rebuild the flat image. Top of `if True:` branch reads the combined `2400c34.x`; the `else` branch interleaves the split MSB/LSB chip images. **Produces `2400-FIRMWARE.bin`** (the file loaded in Ghidra). | `python3 read_firmware.py` |
| `parse_flash.py` | Decode `24LC16B.bin`: calibration floats, cal info/password/dates, serial number, comm config, hardware/model config. Every block ends in a word checksum (`verifyChecksum`). The layout map is the comment block near the top. | `python3 parse_flash.py` |
| `firmware_errors.py` | Read the error-message table at `0x000679B2` (143 × 8-byte entries) and **emit a Ghidra Jython snippet** that defines an `ERR_INDEX_ENUM`. Output is meant to be pasted/run inside Ghidra. | `python3 firmware_errors.py` |
| `firmware_update.py` | Upload firmware over RS-232 (19200 baud) as S-records. Noted as unreliable by the author — kept for reference. | (needs serial HW) |

**Ghidra Jython** (run *inside* Ghidra via the Script Manager / MCP, use `currentProgram`, `memory`, `jarray`, `USER_DEFINED`):

| Script | Purpose |
|---|---|
| `Keithley2400.py` | Walk the SCPI command-parser tables and print the full command tree. Also has helpers `setPrimaryLabelOnAddr` / `setEOLCommentOnAddr` for annotating the program. |

Tell them apart by the header: Jython scripts start with `#@author / #@category / #@menupath` comment tags.

## SCPI command parser structure (the central firmware data structure)

`Keithley2400.py` decodes the command dispatch tables — start there to understand command handling. Two root tables at `0x000635DA` and `0x00063714`.

- **Table** = header `>LB` (offset to entry array, entry count) followed by `count` 4-byte offsets, each pointing to a Command.
- **Command** = 18 bytes `>LBBHBxLL`: name-string offset, name length, `cmdType`, `cmdId`, `paramType` bitfield, then two offsets to nested tables (sub-commands and parameter list). Commands nest recursively to form the SCPI tree.
- `paramType` bits: `1`=int, `2`=string, `4`=bool, `8`=string-list, `0x10`=num-list.

## Working in Ghidra (primary workflow)

Use the **`mcp__ghidra__*` tools** against the live program `2400-FIRMWARE.bin`:
- Orient/inspect: `check_connection`, `decompile_function`, `disassemble_function`, `get_function_metrics`, `get_current_selection`.
- Record findings durably: `rename_function_by_address`, `rename_variables`, `set_function_prototype` — these persist in the Ghidra DB (the `Keithley2400CFirmware.rep/` repository), which is what gets committed.
- Run/manage Jython: `save_ghidra_script` / `update_ghidra_script` / `run` via the script tools.
- The knowledge-DB tools (`query_knowledge_context`, `store_function_knowledge`) report "not available" for this project — don't rely on them.

The Ghidra project is `Keithley2400CFirmware.gpr` + `Keithley2400CFirmware.rep/`. Treat `*.lock` / `tmp*.ps` files as transient Ghidra artifacts (ignore in commits).

## Reference material

`datasheets/` (MC68332, TPU, TMS9914A, 24LC16B, DS1236, board drivers), the Keithley Service/User manuals (repo root PDFs), and `img/` board photos + block diagrams are the authoritative sources for pin-level and behavioral questions — consult them before guessing at peripheral semantics.
