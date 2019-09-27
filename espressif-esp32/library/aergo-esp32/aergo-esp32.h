
extern "C"{
#include "sh2lib.h"
}

#include "mbedtls/ecdsa.h"


struct aergo {
  struct sh2lib_handle hd;
};

int  aergo_connect(aergo *instance, char *host);
void aergo_free(aergo *instance);


struct aergo_account {
  mbedtls_ecdsa_context keypair;
  char address[64];
  uint64_t nonce;
  bool init;
};

int get_private_key(aergo_account *account);

bool requestAccountState(aergo *instance, aergo_account *account);

void aergo_free_account(aergo_account *account);


// Call smart contract function

void ContractCall(aergo *instance, char *contract_address, char *call_info, aergo_account *account);


// Query smart contract

bool queryContract(aergo *instance, char *contract_address, char *query_info, char *result, int size);


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

bool requestEventStream(aergo *instance, char *contract_address, char *event_name, contract_event_cb cb);


// Blocks

void requestBlock(aergo *instance, uint64_t blockNo);

void requestBlockStream(aergo *instance);

void requestBlockchainStatus(aergo *instance);
