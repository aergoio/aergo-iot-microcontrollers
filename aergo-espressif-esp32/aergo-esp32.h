
extern "C"{
#include "sh2lib.h"
}

#include "mbedtls/ecdsa.h"


struct aergo {
  struct sh2lib_handle hd;
};

int  aergo_connect(aergo *instance, char *host);
void aergo_free(aergo *instance);


void ContractCall(aergo *instance, char *contract_address, char *call_info, mbedtls_ecdsa_context *account);

void queryContract(aergo *instance, char *contract_address, char *query_info);

void requestBlock(aergo *instance, uint64_t blockNo);

void requestBlockStream(aergo *instance);

void requestBlockchainStatus(aergo *instance);

void requestAccountState(aergo *instance, mbedtls_ecdsa_context *account);
