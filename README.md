# Keithley 2400 SourceMeter Firmware

I am looking into the firmware. It is based around a Motorola 680000 variant with some memory and EPROM for the firmware. The configuration is stored in a 2kb I2C flash. For the GPIB interface it uses the commonly used TMS9914A.

## Documentation

Reverse-engineering findings live in the Ghidra database (renamed functions, types,
comments); these Markdown files are the human-readable write-ups. Start with
[SUMMARY.md](SUMMARY.md) for the whole-instrument picture, then the per-subsystem docs below.
See [CLAUDE.md](CLAUDE.md) for the cross-reference map and analysis workflow.

**Boot & core**
- [BOOT.md](BOOT.md) — reset/boot sequence: reset vector → SIM/clock/chip-selects → RAM test → ROM checksum → firmware-update mode → `VBR`/vector table → EEPROM config load → peripheral init → scheduler loop.
- [SCPI.md](SCPI.md) — SCPI command parser and dispatch tables.
- [FLOAT.md](FLOAT.md) — Pascal soft-float arithmetic.

**Measurement & source**
- [MEASURE.md](MEASURE.md) — A/D measurement path and reading records.
- [TRIGGER.md](TRIGGER.md) — two-layer Arm/Trigger state machine, SDM step chain, Trigger-Link I/O, operation-status bits.
- [SWEEP.md](SWEEP.md) — sweep engine: staircase/log/list point generation, source-memory stepping with CALC2 pass/fail binning.
- [TRACE.md](TRACE.md) — data store (`:TRACe`) and buffer statistics (`:CALC3`).

**I/O, comms & UI**
- [GPIB.md](GPIB.md) — TMS9914A GPIB driver.
- [RS232.md](RS232.md) — QSM SCI serial RX/TX.
- [STATUS.md](STATUS.md) — IEEE-488.2/SCPI status model (STB/ESR/Operation/Questionable/Measurement), SRQ generation.
- [DISPLAY.md](DISPLAY.md) — front-panel VFD/display board link.
- [MENU.md](MENU.md) — front-panel menu system, navigation, value editing, persistence.

**Calibration & diagnostics**
- [CALIBRATION.md](CALIBRATION.md) — cal data model, `:CAL:PROT:*`, fit math, factory helpers.
- [DIAGNOSTIC.md](DIAGNOSTIC.md) — `:DIAG:KEIT:*` diagnostic commands.

**Reference** — [SCPI_REFERENCE.md](SCPI_REFERENCE.md) (command reference) · [DATASHEETS.md](DATASHEETS.md) (chip/board datasheet notes).

## Digital board chips

- Motorola MC68332ACFC16, a modular microcontroller based around the CPU32, which is a later model of the famous 68k CPU. It is clocked internally to 16588800 MHz and has an additional external 32768 Hz clock as well.
- Two 256kb FLASH memory chips for the firmware (AT49F002T-12JI)
- Two Toshiba TC551001 128kb RAM chips
- Texas Instruments TMS9914A for the GPIB communication
- Microchip 24LC16B (2kb I2C EEPROM for configuration data)
- Dallas DS1236 Micro Manager as a CPU/memory watchdog

A Panasonic BR2330 3V Lithium Cell battery is used to maintain RAM content, but all configuration data is thankfully stored in the I2C EEPROM.

## Memory Map

- 0x000000-0x07ffff - 512KB FLASH memory.
	0x000000-0x000FFF - Booter Code, HW initialization, ROM checksum
	0x001000-0x003FFF - Firmware FLASH code, needs to be copied to RAM.
	0x004000-0x07FFFF - Vector table for the main firmware
	0x004400-0x07FFFF - main Firmware
- 0x080000-0x083fff - 256KB RAM
- 0x090000-0x090007 - TMS9914A
- 0x0a0000-0x0a0001 - one word of unknown data
- 0xf00000-0xf007ff - internal 2kb TPURAM
- 0xfff000-0xffffff - internal modules (I/O register) of the micro controller
