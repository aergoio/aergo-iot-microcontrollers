# aergo-espressif-esp32

This repo contains example code on how to inteface with the aergo
blockchain on Espressif ESP32 microcontrollers.

## Requirements

* Arduino IDE
* [Arduino-esp32](https://github.com/espressif/arduino-esp32)

## Instructions

Create a sub-folder named `nanopb` under the Arduino libraries folder.

Copy there the files bellow:

* pb.h
* pb_common.h
* pb_common.c
* pb_encode.h
* pb_encode.c
* pb_decode.h
* pb_decode.c

You can find detailed instructions [here](https://techtutorialsx.com/2018/10/19/esp32-esp8266-arduino-protocol-buffers/)

Open the `aergo-espressif-esp32.ino` file, modify the WiFi credentials,
compile and upload to an ESP32 device.
