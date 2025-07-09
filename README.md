# Keithley 2400 SourceMeter Firmware

I am looking into the firmware. It is based around a Motorola 680000 variant (MC68332ACFC16) with some memory and EPROM for the firmware. The configuration is stored in a 2kb I2C flash. For the GPIB interface it uses the commonly used TMS9914A.

## Digital board chips

- Motorola MC68332ACFC16, a modular microcontroller based around the CPU32, which is a later model of the famous 68k CPU. It is clocked internally to 16588800 MHz and has an additional external 32768 Hz clock as well.
- Two 256kb FLASH memory chips for the firmware
- Two Toshiba TC551001 128kb RAM chips
- Texas Instruments TMS9914A for the GPIB communication
- Microchip 24LC16B (2kb I2C EEPROM for configuration data)
- Dallas DS1236 Micro Manager as a CPU/memory watchdog

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
