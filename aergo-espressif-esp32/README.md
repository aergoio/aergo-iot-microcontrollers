# Aergo IoT - espressif ESP32

This folder contains example code on how to inteface with the aergo
blockchain on Espressif ESP32 microcontrollers.

![esp32](https://user-images.githubusercontent.com/7624275/62760004-4bea1b00-ba59-11e9-85c0-b7075b506254.jpg)

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

## Security

ESP32 supports [Secure Boot](https://docs.espressif.com/projects/esp-idf/en/latest/security/secure-boot.html)
and [Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/latest/security/flash-encryption.html)

You can also read a compact overview on this article: [Understanding ESP32’s Security Features](https://medium.com/the-esp-journal/understanding-esp32s-security-features-14483e465724)
