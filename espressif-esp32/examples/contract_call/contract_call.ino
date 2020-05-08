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

  requestAccountState(&instance, &account);
  Serial.println("");
  Serial.println("------------------------------------");
  Serial.printf("Account address: %s\n", account.address);
  Serial.printf("Account nonce: %d\n", account.nonce);


  Serial.println("");
  Serial.println("------------------------------------");
  Serial.println("Type your value for new transaction:");
  while(1){
    if(Serial.available() > 0){
      String str = Serial.readStringUntil('\n');
      int len = str.length();
      if( len > 63 ){
        Serial.println("your value is too long! max=63");
      }else{
        char buf[64];
        str.toCharArray(buf, 64);
        while( len>0 && (buf[len-1]=='\n' || buf[len-1]=='\r') ){
          len--;
          buf[len] = 0;
        }
        if( strcmp(buf,"q")==0 || strcmp(buf,"Q")==0 ) break;
        Serial.printf("you typed: %s\n", buf);

        char json[256];
        sprintf(json, "{\"Name\":\"set_name\", \"Args\":[\"%s\"]}", buf);

        aergo_call_smart_contract(&instance, "AmgLnRaGFLyvCPCEMHYJHooufT1c1pENTRGeV78WNPTxwQ2RYUW7", json, &account);

      }
      Serial.println("done.\n");
      Serial.println("------------------------------------");
      Serial.println("Type your value for new transaction:");
    }
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
