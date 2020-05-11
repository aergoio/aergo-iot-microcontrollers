
extern "C"{
#include "sh2lib.h"
}

#include "mbedtls/ecdsa.h"


// Aergo connection instance

struct aergo {
  struct sh2lib_handle hd;
};

int  aergo_connect(aergo *instance, char *host);
void aergo_free(aergo *instance);


// Accounts

struct aergo_account {
  mbedtls_ecdsa_context keypair;
  char address[64];
  uint64_t nonce;
  double balance;
  uint8_t state_root[32];
  bool init;
};

int get_private_key(aergo_account *account);

bool requestAccountState(aergo *instance, aergo_account *account);

void aergo_free_account(aergo_account *account);


// Transfer

void aergo_transfer(aergo *instance, aergo_account *from_account, char *to_account, double value);

void aergo_transfer_int(aergo *instance, aergo_account *from_account, char *to_account, uint64_t integer, uint64_t decimal);

void aergo_transfer_str(aergo *instance, aergo_account *from_account, char *to_account, char *value);

void aergo_transfer_bignum(aergo *instance, aergo_account *from_account, char *to_account, char *amount, int len);


// Call smart contract function

bool aergo_call_smart_contract_json(aergo *instance, aergo_account *account, char *contract_address, char *function, char *args);

bool aergo_call_smart_contract(aergo *instance, aergo_account *account, char *contract_address, char *function, char *types, ...);


// Query smart contract

bool aergo_query_smart_contract_json(char *result, int resultlen, aergo *instance, char *contract_address, char *function, char *args);

bool aergo_query_smart_contract(char *result, int resultlen, aergo *instance, char *contract_address, char *function, char *types, ...);


// Smart contract events

struct contract_event {
  char contractAddress[64];
  char eventName[64];
  char jsonArgs[2048];
  int32_t eventIdx;
  char txHash[32];
  char blockHash[32];
  uint64_t blockNo;
  int32_t txIndex;
};

typedef void (*contract_event_cb)(contract_event *event);

bool aergo_contract_events_subscribe(aergo *instance, char *contract_address, char *event_name, contract_event_cb cb);


// Blocks

void aergo_get_block(aergo *instance, uint64_t block_number);

void aergo_block_stream_subscribe(aergo *instance);


// Status

void aergo_get_blockchain_status(aergo *instance);
