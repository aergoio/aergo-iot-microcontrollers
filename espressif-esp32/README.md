# Aergo IoT - espressif ESP32

This folder contains example code on how to inteface with the aergo
blockchain on Espressif ESP32 microcontrollers.

![esp32](https://user-images.githubusercontent.com/7624275/62760004-4bea1b00-ba59-11e9-85c0-b7075b506254.jpg)

## Requirements

* [Arduino IDE](https://www.arduino.cc)
* [Arduino-esp32](https://github.com/espressif/arduino-esp32)

## Instructions

Install the requirements above.

Copy the folders `aergo-esp32` and `nanopb` to the Arduino's `libraries` folder.

Open some of the examples with the Arduino IDE, modify the WiFi credentials and
upload it to an ESP32 device.

## Security

ESP32 supports [Secure Boot](https://docs.espressif.com/projects/esp-idf/en/latest/security/secure-boot.html)
and [Flash Encryption](https://docs.espressif.com/projects/esp-idf/en/latest/security/flash-encryption.html)

You can also read a compact overview on this article: [Understanding ESP32’s Security Features](https://medium.com/the-esp-journal/understanding-esp32s-security-features-14483e465724)
