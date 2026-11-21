# Keithley 2400 — Boot / Reset Sequence Reverse-Engineering Notes

How the firmware comes up from power-on reset to the main scheduler loop. Addresses are Ghidra
addresses = file offsets in `2400-FIRMWARE.bin` (flat MC68332 / CPU32 image, big-endian). See
[DATASHEETS.md](DATASHEETS.md) (§3 MC68332 SIM, §4 QSM, DS1236) for the register reference, and the
subsystem docs for each peripheral brought up here: [DISPLAY.md](DISPLAY.md) (TPU display/keyboard
serial), [GPIB.md](GPIB.md), [RS232.md](RS232.md), [MEASURE.md](MEASURE.md),
[CALIBRATION.md](CALIBRATION.md) (EEPROM cal/config data), [SCPI.md](SCPI.md) (the parser/executor
the main loop drives).

## Memory map at reset

| Range | Contents |
|---|---|
| `0x0000–0x0FFF` | **Booter** (runs from flash with VBR = 0; reset vector table at `0x0`) |
| `0x1000–0x3FFF` | **Flash-programmer** (`BOOT_UPDATE_FIRMWARE_ROMCOPY` …) — copied to RAM & run only in update mode |
| `0x4000–0x43FF` | **Firmware exception vector table** (256 × 4 bytes) |
| `0x4400…` | Firmware entry stub (`VBR ← 0x4000`) → `main` and the rest of the application |
| `0x7FFFC` | `ROM_CHECKSUM` (one's-complement 16-bit word sum of `0x00000–0x7FFFB`) |
| `0x800000` | SRAM (U12/U14) · `0x900000` TMS9914A GPIB · `$FFFxxx` MC68332 internal regs |

The booter and the flash-programmer are **position-fixed code that predates the main firmware's
vector table**; the main image only takes over exception handling once `VBR` is moved to `0x4000`.

---

## 1. Reset vector & booter entry — `VECTOR_RESET` (`0x400`)

The CPU32 fetches the reset vector from the image base: **initial SSP = `0x80E000`** (`@0x0`),
**initial PC = `0x400`** (`@0x4`) → `VECTOR_RESET`. It runs from flash with `VBR = 0` (reset default).

### 1a. SIM bring-up (clock, ports, chip selects)

| Register | Value | Meaning |
|---|---|---|
| `SIMCR`  | `0x60CF` | SIM config (module mapping, IRQ arbitration) |
| `SYNCR`  | `0x7F01` | PLL: `W=0, X=1, Y=0x3F` → **SysClk ≈ 16.78 MHz** (matches the baud-table figure in [RS232.md](RS232.md) §5 and the 16.78 MHz test-point in [SUMMARY.md](SUMMARY.md)) |
| `SYPCR`  | `0x0000` | **Software watchdog (SWT) and bus monitor disabled** — reset/​watchdog supervision is external (DS1236, see below) |
| `CSBARBT`/`CSORBT` | `0x0006` / `0x7870` | boot chip select → **flash @ `0x000000`** |
| `CSBAR1`/`CSOR1` | `0x8005` / `0x7830` | **SRAM @ `0x800000`** |
| `CSBAR2`/`CSOR2` | `0x9000` / `0x7870` | **TMS9914A GPIB @ `0x900000`** |
| `CSBAR4`/`CSOR4` | `0xFFFB` / `0x7B81` | high I/O window (`$FFF800`…) |
| `CSBAR5/7` | `0x8005` | further `0x800000` decodes (byte-lane / timing variants) |
| `CSBAR10`/`CSOR10` | `0xA000` / `0x7830` | `0xA00000` peripheral window |

Port directions are set first (`PORTC`, `PORTQS`/`DDRQS`/`PQSPAR`, `PORTE0`/`DDRE`/`PEPAR`,
`PORTF0`/`DDRF`/`PFPAR`). *(The `0xA00000` and `$FFF800` decodes are the analog-board / extra-I/O
windows; their exact targets are not pinned down here.)*

### 1b. Power-on RAM test (fail → lockup)

Immediately after chip-select setup, `VECTOR_RESET` runs a destructive RAM test over the SRAM:

1. Walk-a-bit check on the RAM module base register, then fill `0x3800` long-words with
   **`0x12345678`** and read them back.
2. Re-read writing **`0`** and verify each reads back `0`.
3. **All pass →** `VECTOR_RESET_CONTINUE_BOOT`. **Any mismatch →** an infinite `PORTE0`
   error-LED toggle (`LAB_000005DA`) — the classic "RAM fail → lockup" with no further progress.
   (`ENDLESS_TOGGLE_ERROR_BIT` at `0x620` is the same error-blink pattern used elsewhere.)

---

## 2. Boot stage 2 — `VECTOR_RESET_CONTINUE_BOOT` (`0x632`)

1. **TPU bring-up** for the front-panel link: `BOOT_TPURAM_EMULATION_INITIALIZATION`, then TPU
   channels 0/1/2/15 and 12 (`BOOT_CPU_TPU_CH*`) — the display / keyboard serial channels (see
   [DISPLAY.md](DISPLAY.md)). `BOOT_DELAY(100)`.
2. **`BOOT_CHECK_KEYBOARD`** (`0x2A3C`) reads the front-panel keyboard over the TPU link (`CISR`,
   `TPU_Parameter_RAM`). If the key code **`0x88`** is held → **firmware-update mode**
   (`LAUNCH_FIRMWARE_UPDATE_IN_RAM`).
3. **ROM checksum:** `BOOT_CALC_CHECKSUM(0, 0x7FFFC)` (`0x2D6C`, one's-complement 16-bit word sum)
   vs the stored `ROM_CHECKSUM` (`0x7FFFC`). **Mismatch → firmware-update mode.** This is the
   "ROM-checksum fail → firmware-upgrade mode auto-enabled" behaviour and backs `*TST?`.
4. Otherwise drops the two boot TPU channel priorities and calls **`main()`** (does not return).

---

## 3. Firmware-update (reflash) mode — `LAUNCH_FIRMWARE_UPDATE_IN_RAM` (`0x5EC`)

This answers "what is the `0x1000–0x3FFF` region and why is it copied to RAM":

- The ROM region `0x1000–0x374C` (`BOOT_UPDATE_FIRMWARE_ROMCOPY` @ `0x1000`, **`0x274C` bytes**) is
  the **flash programmer**: S-record reader (`BOOT_READ_SREC_LINE`), flash erase/write
  (`BOOT_FLASH_ERASE_ALL` / `BOOT_FLASH_WRITE` / `_WRITE_BLOCK` / `_ERASE_BLOCK`), flash type probe,
  and polled RS-232 I/O (`BOOT_IO_WAIT_FOR_MAGIC` / `_READ_BUFFER` / `_SEND_STR`,
  `BOOT_SETUP_GPIO_RS232` @ `0x145C`, **19200 8N1 polled** — see [RS232.md](RS232.md) §7).
- `LAUNCH_FIRMWARE_UPDATE_IN_RAM` **copies that `0x274C`-byte block into RAM** (reusing
  `gGPIB_RECEIVE_BUFFER` as scratch) and **jumps into the RAM copy** (the "bad instruction" the
  decompiler stops at is the computed jump into RAM).
- **Why RAM:** the updater erases and reprograms the two AT49F002T flash chips it would otherwise be
  executing from, so it cannot run in place. It is **not** copied on a normal boot — only on
  ROM-checksum failure or key `0x88` held at power-on. It drives the `firmware_update.py` S-record
  upload path.

---

## 4. Vector table relocation — `VBR ← 0x4000`

`VECTOR_RESET_CONTINUE_BOOT` enters the main image through the entry stub at `0x4400`, which executes
**`movec D0,VBR` at `0x4406`** to point the CPU32 vector base at **`0x4000`** — relocating all
exception/interrupt handling from the booter's table at `0x0` to the firmware's table at `0x4000`,
then falls into `main` (`0x4492`). From then on:

- **GPIB** `INT` → IRQ level 3 → autovector 27 (`0x4000 + 27*4`) → shell `0x35EA2`, dispatched via
  the RAM pointer `gGPIB_EXCEPTION_LEVEL_3_CALLBACK` (`0x801378`) — [GPIB.md](GPIB.md) §2.
- **RS-232 / QSM SCI** → user vector 64 (`0x4000 + 64*4 = 0x4100`) → `EXCEPTION_USER_64_RS232`
  (`0x3BEBC`); QSPI uses vector 65 (`0x4104` → `0x671C`) — [RS232.md](RS232.md) §2.

---

## 5. Application init — `main` (`0x4492`) and `main_additional_init` (`0x465E`)

`main` brings the instrument up in this order:

1. **`CPU_CONFIGURE_INTERNAL_REGS`** (`0x5856`): `TPUMCR=0x1E41`, `TICR=0x450`, channel priorities
   `CPR0=0x4000`/`CPR1=0`; clears run-state flags.
2. **TPU channels 0–14** (`CPU_TPU_CH*_INITIALIZE`): CH0 display, CH1 keyboard, CH12 beeper, plus
   analog/measure channels; then display + keyboard **IRQ enable**, `CPU_SETUP_PICR_TIMER_IRQ`,
   `CPU_IRQ_FORCE_ENABLE`.
3. Powerline-measurement settle (`IRQ_COUNTDOWN_POWERLINE_MEASUREMENT = 5000`, spin to 0).
4. **`DISPBOARD_INITIALIZE`** — returns the **boot key-combo** held by the user (diagnostic entries:
   display-limits loop, "secret"/built-in-test menu, burn-in toggle).
5. **`CPU_HW_CONFIG_SPCR`** — QSM/QSPI config (sets `QSMCR`, `QILR/QIVR` → SCI/QSPI vectors 64/65).
6. **`main_additional_init`** (`0x465E`), in order:
   `EventRegs_initialize` → `MEASURE_INIT_STATE_DEFAULTS` → **`CHECK_CONFIGURATION_CHECKSUMS`**
   (EEPROM config load, §6) → `FUNCTION_KEYCODE_0x65_reset_frontpanel_defaults` →
   `TRACE_BUFFER_DISARM` → `RESPONSE_INITIALIZE` → **`TMS9914A_RECEIVE_SETUP`** (GPIB RX, GPIB.md §5)
   → **RS-232 setup** (`RS232_0003B89C`) → `COMM_PARSER_STATE_PROCESS_NEXT`.
7. `DISPBOARD_SHOW_BOOT_MESSAGE`, set the Standard-event **PON** bit (`0x80`), then enter the loop.

### Scheduler loop (never returns)

```
do {
    MENU_CALL_SETUP();                  // front-panel menu / key handling
    (*FUNCPTR_008045C8)();              // measure/source step (VOIDFN slot, MEASURE.md §4b)
    (*FUNCPTR_COMM_BUILD_RESULTSTR)();  // per-protocol response pump (GPIB/RS232/488.1)
    EXECUTE_COMMAND_TILL_DONE();        // drain + run the SCPI command queue (SCPI.md)
    (*FUNCPTR_COMM_BUILD_RESULTSTR)();
    (*FUNCPTR_00803820)();              // trigger/measure step (VOIDFN slot)
    DISPLAY_UPDATE();                   // refresh the VFD (DISPLAY.md)
} while (true);
```

---

## 6. Config load from EEPROM — `CHECK_CONFIGURATION_CHECKSUMS` (`0x16934`)

Reads the **24LC16B I²C EEPROM** (U17) via the bit-banged I²C driver (`I2C_INIT` `0x50A98`,
`I2C_READ_DATA` `0x50AB2`, `I2C_WRITE_DATA` `0x50B62`) and validates each block by word checksum
(`CALC_WORD_CHECKSUM`). On a checksum mismatch it loads the in-ROM factory defaults, rewrites the
block back to EEPROM, and raises a "data lost" error — the dead/absent-battery path (`:SYST:MEM:INIT`
/ battery replacement, per [SUMMARY.md](SUMMARY.md)):

| EEPROM block | Default source on mismatch | Error raised |
|---|---|---|
| Serial number | (read only) | — |
| **Comm config** (`0x190`) | `DAT_0005B9DC` (factory comm) | `-602` GPIB addr lost, `-606` comm language lost, `-700` invalid comm |
| **Hardware config** (`0x0C`) | `FACTORY_DEFAULT_CONFIG_0x0C` | `-603` power-on state lost |
| **Current config** (`0x19E`) | `FACTORY_DEFAULT_CONFIG` | `-601` reading-buffer data lost |

It then applies the loaded comm settings: protocol mode (`commMode` GPIB/RS-232), GPIB address
(`TMS9914A_SCPI_Set_Adr` / `TMS9914A_488_1_Set_Adr`), `COMM_RS232_configure`, and installs the
**per-protocol response pump** into `FUNCPTR_COMM_BUILD_RESULTSTR` (`0x8086FC`):
`RESPONSE_RS232_BUILD_RESULTSTR` (RS-232), `RESPONSE_SCPI_BUILD_RESULTSTR` (SCPI/GPIB), or
`RESPONSE_488_1_BUILD_RESULTSTR` (488.1). It also calls `HW_CONFIGURE_MODEL`, sets the powerline
frequency, and applies the power-on setup (`SYSTEM_PRESET_RESET_APPLY`). Because changing the
interface rewrites this block, the manual's "changing interface causes a power-on reset" maps to
re-running this path.

---

## 7. DS1236 / battery-backed storage

The internal software watchdog is **disabled** (`SYPCR = 0`); reset supervision, the power-fail
reset, and **battery-backed SRAM** (reading buffers + setups) are handled by the external **DS1236**
(U-LSI reset/NV controller, [DATASHEETS.md](DATASHEETS.md)). The calibration constants and all system
setups that survive power loss live in the **24LC16B** (§6), not in the DS1236-backed RAM. *(No
explicit DS1236 watchdog-strobe write was isolated in the boot code; if present it is a periodic port
toggle in the running system rather than part of the reset path.)*

---

## 8. Peripheral bring-up order (summary)

```
reset ─► VECTOR_RESET (0x400)
          SIM: clock/ports/chip-selects ─► RAM test ──(fail)──► PORTE0 lockup
                                              │(pass)
                                              ▼
         VECTOR_RESET_CONTINUE_BOOT (0x632)
          TPU display/keyboard ─► keyboard check ─(0x88)─┐   ROM checksum ─(bad)─┐
                                              │(normal)  ▼                        ▼
                                              │     LAUNCH_FIRMWARE_UPDATE_IN_RAM (reflash via RS-232)
                                              ▼
         0x4400 stub: VBR ◄─ 0x4000 ─► main (0x4492)
          TPU CH0..14 ─► IRQ enable ─► powerline settle ─► DISPBOARD_INITIALIZE
          ─► CPU_HW_CONFIG_SPCR (QSM) ─► main_additional_init:
                EEPROM config load (CHECK_CONFIGURATION_CHECKSUMS) ─► GPIB RX setup ─► RS-232 setup
          ─► PON event bit ─► ∞ scheduler loop (menu / step / response pump / SCPI exec / display)
```

Hand-off: once in the scheduler loop, input arrives via the GPIB IRQ3 ISR or the RS-232 SCI ISR, is
drained by `COMM_PARSER_STATE_PROCESS_NEXT`, parsed/executed by the SCPI layer, and answered through
the installed response pump — all documented in [GPIB.md](GPIB.md) / [RS232.md](RS232.md) /
[SCPI.md](SCPI.md).

---

## 9. Key addresses

| Symbol | Address | Notes |
|---|---|---|
| reset vector (SSP / PC) | `0x0` / `0x4` | `0x80E000` / `0x400` |
| `VECTOR_RESET` | `0x400` | SIM setup + RAM test |
| `VECTOR_RESET_CONTINUE_BOOT` | `0x632` | TPU + keyboard + ROM checksum → main/update |
| `LAUNCH_FIRMWARE_UPDATE_IN_RAM` | `0x5EC` | copy flash-programmer to RAM & jump |
| `ENDLESS_TOGGLE_ERROR_BIT` | `0x620` | error-LED lockup blink |
| `BOOT_CHECK_KEYBOARD` | `0x2A3C` | boot key read (`0x88` → update) |
| `BOOT_CALC_CHECKSUM` | `0x2D6C` | one's-complement 16-bit word sum |
| `ROM_CHECKSUM` | `0x7FFFC` | stored flash checksum |
| `BOOT_UPDATE_FIRMWARE_ROMCOPY` | `0x1000` | flash-programmer (`0x274C` bytes, run from RAM) |
| `BOOT_READ_SREC_LINE` / `BOOT_FLASH_*` | `0x15DA` / `0x18E4…` | S-record + flash erase/write |
| `BOOT_SETUP_GPIO_RS232` | `0x145C` | booter RS-232 19200 8N1 polled |
| firmware entry stub / `VBR←0x4000` | `0x4400` / `0x4406` | `movec D0,VBR` |
| vector table | `0x4000`–`0x43FF` | 256 × 4 bytes |
| `main` | `0x4492` | application init + scheduler loop |
| `main_additional_init` | `0x465E` | subsystem init incl. config load |
| `CPU_CONFIGURE_INTERNAL_REGS` | `0x5856` | TPU master config |
| `CPU_HW_CONFIG_SPCR` | (QSM init) | QSMCR/QILR-QIVR (SCI/QSPI vectors 64/65) |
| `CHECK_CONFIGURATION_CHECKSUMS` | `0x16934` | EEPROM config load + defaults |
| `I2C_INIT` / `I2C_READ_DATA` / `I2C_WRITE_DATA` | `0x50A98` / `0x50AB2` / `0x50B62` | 24LC16B driver |
| `DISPBOARD_INITIALIZE` | — | display board init; returns boot key-combo |

---

*Discipline note: the flow, register values and addresses above are taken from the live
decompilation. `SysClk ≈ 16.78 MHz` is the `SYNCR=0x7F01` PLL setting cross-checked against the
RS-232 baud table and the service-manual test point. The `0xA00000` / `$FFF800` chip-select targets
and the DS1236 watchdog-strobe (if any) were not pinned down and are flagged as such above.*
