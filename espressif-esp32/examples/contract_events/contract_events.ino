#include <aergo-esp32.h>
#include "WiFi.h"

const char* ssid = "<<<include>>>";
const char* password =  "<<<include>>>";

///////////////////////////////////////////////////////////////////////////////////////////////////

void on_contract_event(contract_event *event){

  Serial.println("");
  Serial.println("------------------------------------");
  Serial.println("     Smart Contract Event");
  Serial.printf("contractAddress: %s\n", event->contractAddress);
  Serial.printf("eventName: %s\n", event->eventName);
  Serial.printf("jsonArgs: %s\n", event->jsonArgs);
  Serial.printf("eventIdx: %d\n", event->eventIdx);
  Serial.printf("blockNo: %llu\n", event->blockNo);
  Serial.printf("txIndex: %d\n", event->txIndex);
  Serial.println("------------------------------------");
  Serial.println("");

}

void http2_task(void *args){
  aergo instance;

  if (aergo_connect(&instance, "http://testnet-api.aergo.io:7845") != ESP_OK) {
    Serial.println("Error connecting to HTTP2 server");
    vTaskDelete(NULL);
  }

  Serial.println("Connected");

  bool ret = aergo_contract_events_subscribe(
    &instance,
    "AmgMhLWDzwL2Goet6k4vxKniZksuEt3Dy8ULmiyDPpSmgJ5CgGZ4",
    "",
    on_contract_event);

  if (!ret) {
    Serial.println("request FAILED");
  }

  aergo_free(&instance);
  Serial.println("Disconnected");

  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }

  Serial.println("Done. Starting HTTP2 connection...");

  xTaskCreate(http2_task, "http2_task", (1024 * 32), NULL, 5, NULL);

}

void loop() {
  vTaskDelete(NULL);
}
