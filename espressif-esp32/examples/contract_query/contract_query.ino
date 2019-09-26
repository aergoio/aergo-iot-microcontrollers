#include <aergo-esp32.h>
#include "WiFi.h"

const char* ssid = "<<<include>>>";
const char* password =  "<<<include>>>";

///////////////////////////////////////////////////////////////////////////////////////////////////

void http2_task(void *args)
{
  aergo instance;
  char response[1024];

  if (aergo_connect(&instance, "http://testnet-api.aergo.io:7845") != ESP_OK) {
    Serial.println("Error connecting to HTTP2 server");
    vTaskDelete(NULL);
  }

  Serial.println("Connected");

  bool ret = queryContract(
    &instance,
    "AmgLnRaGFLyvCPCEMHYJHooufT1c1pENTRGeV78WNPTxwQ2RYUW7",
    "{\"Name\":\"hello\"}",
    response, sizeof response
  );

  if (ret == true) {
    Serial.println("");
    Serial.println("------------------------------------");
    Serial.println("Smart Contract Query OK");
    Serial.printf("Response: %s\n", response);
    Serial.println("------------------------------------");
    Serial.println("");
  } else {
    Serial.println("FAILED when querying the smart contract");
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
