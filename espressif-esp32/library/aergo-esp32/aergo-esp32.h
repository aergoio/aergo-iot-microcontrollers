
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

void ContractCall(aergo *instance, char *contract_address, char *call_info, aergo_account *account);

bool queryContract(aergo *instance, char *contract_address, char *query_info, char *result, int size);

void aergo_free_account(aergo_account *account);


void requestBlock(aergo *instance, uint64_t blockNo);

void requestBlockStream(aergo *instance);

void requestBlockchainStatus(aergo *instance);
