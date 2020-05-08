/*

Note:

When using a relay that turns ON when the input voltage is LOW, use the connections bellow:

JD-VCC ----> 5V
VCC    ----> Digital IO
IN     ----> GND
GND    ---—> GND

*/

#include <aergo-esp32.h>
#include "WiFi.h"

const char* ssid = "<<<include>>>";
const char* password =  "<<<include>>>";

#define ACTUATOR_PORT 23

///////////////////////////////////////////////////////////////////////////////////////////////////

void act_on_command(char *command){

  if (strcmp(command,"on")==0) {
    digitalWrite(ACTUATOR_PORT, HIGH);   // turn the actuator on (HIGH is the voltage level)
  }else{
    digitalWrite(ACTUATOR_PORT, LOW);    // turn the actuator off by making the voltage LOW
  }

}

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

  act_on_command(event->eventName);

}

char * unquote(char *str){
  if (str[0]=='"') {
    char *p = strchr(str+1, '"');
    if (p) *p = 0;
    return &str[1];
  }
  return str;
}

void http2_task(void *args){
  aergo instance;
  char response[128];
  bool ret;

  if (aergo_connect(&instance, "http://testnet-api.aergo.io:7845") != ESP_OK) {
    Serial.println("Error connecting to HTTP2 server");
    vTaskDelete(NULL);
  }

  Serial.println("Connected");

  // First retrieve the state in which the actuator should be

  ret = aergo_query_smart_contract(
    &instance,
    "AmhCzNds4F9i5Duoyai6FfzSiF5Re5PEhcH8kQWkKNbBP5Z4djcX",
    "{\"Name\":\"get_last_state\"}",
    response, sizeof response
  );

  if (ret == true) {
    Serial.println("");
    Serial.println("------------------------------------");
    Serial.println("Smart Contract Query OK");
    Serial.printf("Response: %s\n", response);
    Serial.println("------------------------------------");
    Serial.println("");
    act_on_command(unquote(response));
  } else {
    Serial.println("FAILED when querying the smart contract");
  }

  // Then subscribe for events on the smart contract

  ret = aergo_contract_events_subscribe(
    &instance,
    "AmhCzNds4F9i5Duoyai6FfzSiF5Re5PEhcH8kQWkKNbBP5Z4djcX",
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

  // initialize digital pin as an output
  pinMode(ACTUATOR_PORT, OUTPUT);
  digitalWrite(ACTUATOR_PORT, LOW);

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
