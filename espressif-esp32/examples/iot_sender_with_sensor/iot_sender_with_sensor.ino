#include <aergo-esp32.h>
#include "WiFi.h"

const char* ssid = "<<<include>>>";
const char* password =  "<<<include>>>";

#define SENSOR_PORT 33

#define VALUE_DIFF_THRESHOLD 25

#define NUM_READINGS 5

///////////////////////////////////////////////////////////////////////////////////////////////////

int readSensor(int port){
  int sum = 0;
  int count = 0;

  while (1) {
    sum += analogRead(port);
    count++;
    if (count==NUM_READINGS) break;
    delay(100);
  }

  return sum / NUM_READINGS;
}

void http2_task(void *args){
  aergo instance;
  aergo_account account;

  if (aergo_connect(&instance, "http://testnet-api.aergo.io:7845") != ESP_OK) {
    Serial.println("Error connecting to HTTP2 server");
    vTaskDelete(NULL);
  }

  Serial.println("Connected");


  int rc = get_private_key(&account);


  requestAccountState(&instance, &account);
  Serial.println("");
  Serial.println("------------------------------------");
  Serial.printf ("Account address: %s\n", account.address);
  Serial.printf ("Account balance: %f\n", account.balance);
  Serial.printf ("Account nonce: %d\n", account.nonce);


  int prev_value = 0;

  while(1){
    // Read value from the sensor
    int value = readSensor(SENSOR_PORT);
    Serial.println(value);

    // Check if the new value differs enough from the previous sent value
    if (abs(value - prev_value) >= VALUE_DIFF_THRESHOLD) {
      // Send the value to the smart contract

      Serial.println("------------------------------------");
      Serial.printf ("Sending value: %d\n", value);

      bool ret = aergo_call_smart_contract(&instance,
        txn_hash,
        &account,
        "AmhCzNds4F9i5Duoyai6FfzSiF5Re5PEhcH8kQWkKNbBP5Z4djcX",
        "update_value", "i", value);

      Serial.println("------------------------------------");
      prev_value = value;
    }

    // Wait until next reading
    delay(500);
  }


  aergo_free_account(&account);
  aergo_free(&instance);
  Serial.println("Disconnected");

  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);

  // initialize digital pin as an output
  pinMode(SENSOR_PORT, INPUT);

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
