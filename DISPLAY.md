# Keithley 2400 — Front-Panel Display & Keyboard Link

How the main CPU (MC68332) talks to the **front-panel display board**, which has its own
microcontroller (**U902**, ROM `7001-800-*`) driving the VFD and scanning the key matrix. The two
boards are joined by a **byte-serial link emulated on the MC68332 TPU** (no hardware UART). Addresses
are Ghidra addresses = file offsets in `2400-FIRMWARE.bin` (big-endian). See [DATASHEETS.md](DATASHEETS.md)
(MC68332 TPU; display board) and the front-panel key map in [SUMMARY.md](SUMMARY.md).

---

## 1. Physical link — TPU PWM-as-UART

Two TPU channels run the **PWM time function (CFSR code 9)** as a byte shifter — one byte per channel
interrupt, the data byte living in the channel's parameter RAM. Set up by
`CPU_TPU_CH0_DISPLAY_INITIALIZE` / `CPU_TPU_CH1_KEYBOARD_INITIALIZE` (param `[n][1]=437` timing,
`[n][3]=8` bits/byte). TPU interrupts at level → **CIBV base `0x50`**:

| Channel | Vector | ISR | Direction | Data register |
|---|---|---|---|---|
| **CH0** | 80 (`0x4140`) → `0x3CE6C` | `EXCEPTION_USER_80_DISPLAY_BOARD` | **RX** (display board → CPU) | `TPU_Parameter_RAM[0][2]` |
| **CH1** | 81 (`0x4144`) → `0x3CE9C` | `EXCEPTION_USER_81_SEND_BYTE_TO_DISPLAY` | **TX** (CPU → display board) | `TPU_Parameter_RAM[1][2]` |

(The init function names say "CH0=display / CH1=keyboard", but by data flow **CH0 is the inbound link
from the display board** — carrying key codes and query replies — and **CH1 is the outbound link**.)

TPU control registers used: `CIER` (`0xFFFE0A`, channel IRQ enable), `CISR` (status/ack), `CFSR3`
(function select), `CPR1` (priority), `HSQR1`/`HSRR1` (host sequence / service request).

Also relevant: **TPU CH12 = the beeper** (`CPU_TPU_CH12_BEEPER`), pulsed on each key press.

---

## 2. Transmit (CPU → display)

`DISPBOARD_SEND_BYTES(buf, len)` (`0x3CD2E`):
- returns 1 (busy) if `gDISPBOARD_SEND_BUSY_FLAG` set or the display output is disabled; rejects `len > 0x80`.
- copies `buf` into the send buffer, sets `gDISPBOARD_SEND_BUFFER_PTR` (`0x8050A8`),
  `gDISPBOARD_SEND_BUFFER_COUNT` (`0x8050D8`), `gDISPBOARD_SEND_BUSY_FLAG` (`0x80873C`), and
  **enables the CH1 TPU interrupt** (`CIER |= 2`).

`EXCEPTION_USER_81_SEND_BYTE_TO_DISPLAY` (CH1 ISR) then fires once per byte:
```c
if (count == 0) { CIER &= ~2; busy = 0; }            // done → disable IRQ
else { TPU_Parameter_RAM[1][2] = *ptr++; count--; }  // load next byte into the PWM channel
```

Callers of `DISPBOARD_SEND_BYTES` (≈45 sites) are the display-build routines (`DISPLAY_FORMAT_READING`,
`DISPLAY_BUILD_SOURCE_COMPLIANCE_LINE`, `DISPLAY_BUILD_STATUS_ANNUNCIATORS`, the menu renderers, …)
and the diagnostic `:DIAG:KEIT:DISP`/`:DCMD` commands.

---

## 3. Receive (display → CPU): keys & replies

`EXCEPTION_USER_80_DISPLAY_BOARD` (CH0 ISR) reads the byte from `TPU_Parameter_RAM[0][2]` and calls
`DISPBOARD_RECEIVE(byte)` (`0x3CC3A`), which stores it into **two** structures:
- an **8-byte ring** `gDISPBOARD_RECEIVE_BUF_RING` (head wraps at 8) — the live key/byte stream;
- a **0x80-byte line buffer** `gDISPBOARD_RECEIVE_BUFFER` (write pos 0…0x80) — used to capture a
  whole reply line (e.g. the identify response). Returns 0 (→ sets a query error) if the line buffer overflows.

`DISPBOARD_CLEAR_RECEIVE_BUFFER` resets both.

---

## 4. Power-on identify / handshake

`DISPBOARD_INITIALIZE` (returns the boot keycode):
1. send byte **`0x0F`** (display reset / identify command);
2. wait ~50 ticks (`IRQ_COUNTDOWN_DISPBOARD`);
3. read the reply line: if it starts with **`"200"`** (a valid 24xx display board), copy bytes
   **10–14** into `gDisplayBoardRevision` (the display-board firmware rev) and take byte **15** as the
   **key held at power-on** (returned to `main`, which uses it for the hidden boot key-combos `0xC0`,
   `0x86`, `0x84` — see [SCPI.md](SCPI.md)/`main`). If invalid, the revision defaults to `"XXX.XX"`.

So the display-board identity, firmware revision, and the power-on key combo all come back over this
same serial link during init.

display→CPU = key-event bytes and query replies. The CPU→display command set is reversed below.

---

## 4b. CPU→display command protocol (opcodes)

The CPU→display byte stream mixes **command opcodes** (the `DISP_STR_CODE_*` enum) with **character
data** (ASCII `0x20`–`0x7F`, written at the cursor and auto-advancing). A full screen refresh is
built in `DISP_FILL_SEND_DATA_BUF` (`0x4D4F8`) into `gDISPLAY_SEND_DATA_BUF` (`0x805158`) and pushed
via `DISPBOARD_SEND_BYTES`:

| Opcode | `DISP_STR_CODE_*` | Args | Meaning |
|---|---|---|---|
| `0x04` | `SUBTEXT` | `00` | Start a full text write (packet header is `04 00`). |
| `0x0B` | `BLINK_ENABLE_DISABLE` | 1 state byte | Set the blink attribute for following chars: `0`=off, `1`/`2`=blink modes. |
| `0x06` | `ANNUN_A_2_BYTES` | `<lo> <hi>` | Annunciator segment bitmask (16-bit). |
| `0xAA` | `ANNUN_B_2_BYTES` | `<~lo> <~hi>` | The **complement** of the annunciator mask — lets U902 verify link integrity (`A == ~B`). |
| `0x0F` | (identify/reset) | — | Power-on identify (see §4). |
| `0x20`–`0x7F` | — | — | Character written at the cursor (auto-advance). |

**Full-refresh packet layout** (`DISP_FILL_SEND_DATA_BUF`):
```
04 00                              ; SUBTEXT header
[0B s] <20 top-line chars>         ; window-1 line, BLINK commands interspersed where the attr changes
[0B 00]                            ; blink-off if the last char blinked
[0B s] <32 bottom-line chars>      ; window-2 line
0B 00                              ; blink-off terminator
06 <lo> <hi>                       ; ANNUN_A: annunciator bitmask
AA <~lo> <~hi>                     ; ANNUN_B: complement
```
Total length = (chars + blink commands) + 8. A standalone annunciator-only update
(`DISP_APPEND_ANNUTATIONS_TO_OUTPUT` @`0x4D812`) is exactly those last **6 bytes**
(`06 lo hi AA ~lo ~hi`), sent when only the annunciators changed.

Character substitutions applied while filling the buffer: `'.'`(`0x2E`)→`','`(`0x2C`) when the
display is in comma-decimal mode; `' '`(`0x20`) under a blink attribute →`'_'`(`0x5F`) to render the
edit cursor. The annunciator bitmask (`gDISP_ANNUTATIONS`) carries REM/TALK/LSTN/SRQ/REAR/4W/AUTO/
MATH/FILT/REL/EDIT/ERR/etc. The exact VFD glyph/segment mapping lives in U902's own firmware (not in this image).

---

## 5. Key-handling pipeline

```
display board key → CH0 RX ISR → DISPBOARD_RECEIVE → ring buffer
        │
        ▼
DISPBOARD_KEY → DISPBOARD_READ_KEY (pop a KEYCODE from the ring)
        │
        ▼
KEY_GET_NEXT_KEYCODE_BY_MODE (0x3CFE0)   arbitrates by gKeyboardMode:
   mode 1 → KEY_DISPATCH_KEYCODE_HANDLER ;  mode 3/4 → pending edit keycode ;  mode 5 → special
        │
        ▼
KEY_DISPATCH_KEYCODE_HANDLER (0x3D340)
   • autorepeat via KEY_GET_AUTOREPEAT_KEYCODE (0x3D54A) + 800-tick delay (BOOL_00808738)
   • beep on press (CPU_TPU_CH12_BEEPER)
   • LOCAL mode: binary-search KEYCODE_ARRAY_0003D3CE, dispatch via jump table WORD_ARRAY_0003D3BA
     → per-key handler (FUNCTION_KEYCODE_0x..)
   • REMOTE mode (BOOL_00805800): only LOCAL, OUTPUT ON/OFF, and TRIG keys act — OUTPUT aborts to
     idle and reconfigures the active interface; TRIG triggers a measurement (manual's safety rule).
```

Front-panel keys can also be injected remotely via `:SYSTem:KEY` (cmdId 0x90) and `:DIAG:KEIT:KEY`
(0x170).

### Key codes

The display board sends a **raw 1-byte key code** per key over the serial link (`DISPBOARD_READ_KEY`
passes it through untranslated; `KEY_DISPATCH` works on it directly). The `:SYSTem:KEY` handler
(`0x1C986`) maps the documented index `n` (1–32) to the raw code by **`raw = 0x40 + n`**
(`move.b idx; addi.b #0x40`), and rejects index 25 (`0x59`, unused).

| Raw | n | Key | Raw | n | Key |
|----|----|----|----|----|----|
| 0x41 | 1 | RANGE ▲ | 0x51 | 17 | RANGE ▼ |
| 0x42 | 2 | SOURCE ◄/▼ | 0x52 | 18 | ENTER |
| 0x43 | 3 | EDIT ◄ | 0x53 | 19 | SOURCE I |
| 0x44 | 4 | MENU | 0x54 | 20 | TRIG |
| 0x45 | 5 | FCTN | 0x55 | 21 | RECALL |
| 0x46 | 6 | FILTER | 0x56 | 22 | MEAS I |
| 0x47 | 7 | SPEED | 0x57 | 23 | LOCAL |
| 0x48 | 8 | EDIT | 0x58 | 24 | ON/OFF OUTPUT |
| 0x49 | 9 | AUTO | 0x59 | 25 | *(unused)* |
| 0x4A | 10 | EDIT ► | 0x5A | 26 | SOURCE ►/▲ |
| 0x4B | 11 | EXIT | 0x5B | 27 | SWEEP |
| 0x4C | 12 | SOURCE V | 0x5C | 28 | CONFIG |
| 0x4D | 13 | LIMIT | 0x5D | 29 | MEAS Ω |
| 0x4E | 14 | STORE | 0x5E | 30 | REL |
| 0x4F | 15 | MEAS V | 0x5F | 31 | DIGITS |
| 0x50 | 16 | TOGGLE | 0x60 | 32 | FRONT/REAR |

**Special pre-dispatch keys** (the 9-entry binary-search array `KEYCODE_ARRAY_0003D3CE` =
`41 42 43 4A 50 51 54 55 5A`): the four arrows, TOGGLE, RANGE▼, TRIG, RECALL, SOURCE▲ — the
navigation/edit/trigger keys handled ahead of the normal path.

In **remote** mode only LOCAL (`0x57`), ON/OFF (`0x58`) and TRIG (`0x54`) act.

### Boot key codes (held at power-on)

The display board signals "held at power-on" by adding **`0x40`** to the key's normal raw code, and
reports it in **byte 15 of the `0x0F` identify reply** (§4). Only `main()` recognizes them (three
`cmpi.l` @`0x4578`/`0x4580`/`0x4588`); any other held key is ignored. Exactly three are acted on:

| Boot code | = normal +0x40 | Held key | Effect in `main()` |
|---|---|---|---|
| `0x84` | `0x44`+`0x40` | **MENU** | Toggle **burn-in test** enable, recompute the hardware-config checksum, write it to the I²C EEPROM, then call `FUNCTION_KEYCODE_0x66`. |
| `0x86` | `0x46`+`0x40` | **FILTER** | Enable **secret diagnostic mode** (`gDIAGNOSTIC_KEITHLEY_SECRET`, unlocks the `:DIAGnostic:KEIThley` subtree) + `gBUILDIN_TEST_AVAILABLE`. |
| `0xC0` | — (`0xC0-0x40=0x80`, out of `0x41–0x60`) | not a single key → **factory/multi-key combo** | **VFD display test**: sends the fixed string `"+200.000V   Isrc:+10.000mA  Cmpl:+200.000V"` and spins in an infinite loop (power-cycle to exit). |

`0x84`/`0x86` decode cleanly to MENU/FILTER via the `+0x40` rule; `0xC0` can't be a single key, so it
is a dedicated factory test chord (the exact key combination is in U902's firmware, not this image).
These boot codes are distinct from runtime key codes and from the synthetic band `0x61–0x6A`.

---

## 6. Display output build (main loop)

The main loop (`main` @0x4492) calls `DISPLAY_UPDATE` each pass. The two-line ~49-char VFD content is
composed into `gDISP_LINES_DATA` by the `DISPLAY_FORMAT_*` / `DISPLAY_BUILD_*` routines (reading value
+ units + annunciators on the top line; source/compliance on the bottom), then pushed with
`DISPBOARD_SEND_BYTES`. `:DISPlay:TEXT`/`:WINDow2:TEXT` override the lines with user text.

---

## 7. Key addresses

| Symbol | Address | Notes |
|---|---|---|
| `CPU_TPU_CH0_DISPLAY_INITIALIZE` | (named) | sets CH0 = RX, PWM fn 9 |
| `CPU_TPU_CH1_KEYBOARD_INITIALIZE` | (named) | sets CH1 = TX, PWM fn 9 |
| CH0 RX ISR `EXCEPTION_USER_80_DISPLAY_BOARD` | `0x3CE6C` | vec 80 |
| CH1 TX ISR `EXCEPTION_USER_81_SEND_BYTE_TO_DISPLAY` | `0x3CE9C` | vec 81 |
| `DISPBOARD_SEND_BYTES` | `0x3CD2E` | TX buffer + CIER\|2 |
| `DISPBOARD_RECEIVE` | `0x3CC3A` | RX → ring + line buffer |
| `DISPBOARD_KEY` / `DISPBOARD_READ_KEY` | (named) | pop keycode from ring |
| `DISPBOARD_INITIALIZE` | (named) | `0x0F` identify, parse rev + boot key |
| `KEY_GET_NEXT_KEYCODE_BY_MODE` | `0x3CFE0` | keyboard-mode arbiter |
| `KEY_DISPATCH_KEYCODE_HANDLER` | `0x3D340` | main key dispatch (jump table `0x3D3BA`) |
| `KEY_GET_AUTOREPEAT_KEYCODE` | `0x3D54A` | held-key repeat |
| `CPU_TPU_CH12_BEEPER` | (named) | key-press beep |
| `CIER` / `CISR` / `CFSR3` | `0xFFFE0A` / … | TPU channel control |
| TPU parameter RAM (data byte) | `[0][2]` RX, `[1][2]` TX | per-channel |
| `gDISPBOARD_SEND_BUFFER_PTR/_COUNT/_BUSY_FLAG` | `0x8050A8`/`0x8050D8`/`0x80873C` | TX state |
| `gDISPBOARD_RECEIVE_BUF_RING` (8) / `gDISPBOARD_RECEIVE_BUFFER` (0x80) | (RAM) | RX |
| `gDisplayBoardRevision`, `gKeyboardMode` | (RAM) | identity / key mode |

---

*The display/keyboard channel is a TPU-PWM byte-serial link: CH1 shifts CPU→display bytes, CH0
receives display→CPU key codes and replies. It's separate from the GPIB/RS-232 remote interfaces
([GPIB.md](GPIB.md)) — those feed the SCPI parser, while this drives the local UI.*
