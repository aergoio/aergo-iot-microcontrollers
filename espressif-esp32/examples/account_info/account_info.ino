#include <aergo-esp32.h>
#include "WiFi.h"

const char* ssid = "<<<include>>>";
const char* password =  "<<<include>>>";

///////////////////////////////////////////////////////////////////////////////////////////////////

void http2_task(void *args)
{
  aergo instance;
  aergo_account account;

  if (aergo_connect(&instance, "http://testnet-api.aergo.io:7845") != ESP_OK) {
    Serial.println("Error connecting to HTTP2 server");
    vTaskDelete(NULL);
  }

  Serial.println("Connected");

  int rc = get_private_key(&account);

  if (aergo_get_account_state(&instance, &account) == true) {
    Serial.println("");
    Serial.println("------------------------------------");
    Serial.printf("Account address: %s\n", account.address);
    Serial.printf("Account nonce: %d\n", account.nonce);
    Serial.printf("Account balance: %f\n", account.balance);
    //Serial.printf("Account nonce: %s\n", account.state_root);
    Serial.println("------------------------------------");
    Serial.println("");
  } else {
    Serial.println("FAILED to retrieve the account state");
  }

  aergo_free_account(&account);
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
