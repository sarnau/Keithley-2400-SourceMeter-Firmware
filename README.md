# Keithley 2400 SourceMeter Firmware

I am looking into the firmware. It is based around a Motorola 680000 variant (MC68332ACFC16) with some memory and EPROM for the firmware. The configuration is stored in a 2kb I2C flash. For the GPIB interface it uses the commonly used TMS9914A.