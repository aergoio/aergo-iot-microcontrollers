#include <dummy.h>

#include "WiFi.h"

#include "aergo-esp32.h"

#include "pb_common.h"
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

#include "blockchain.pb.h"

extern "C" {
#include "endianess.h"
#include "account.h"
}

State account_state = State_init_zero;

///////////////////////////////////////////////////////////////////////////////////////////////////

#if defined(DEBUG_MESSAGES)
#define DEBUG_PRINT      Serial.print
#define DEBUG_PRINTF     Serial.printf
#define DEBUG_PRINTLN    Serial.println
#define DEBUG_PRINT_BUFFER print_buffer
#else
#define DEBUG_PRINT(...)
#define DEBUG_PRINTF(...)
#define DEBUG_PRINTLN(...)
#define DEBUG_PRINT_BUFFER(...)
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_exit       exit
#define mbedtls_printf     DEBUG_PRINTF
//#define mbedtls_snprintf   Serial.snprintf
#define mbedtls_free       free
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"

static int ecdsa_rand(void *rng_state, unsigned char *output, size_t len){

#if 0
  while( len > 0 ){
    int rnd;
    size_t use_len = len;
    if( use_len > sizeof(int) )
      use_len = sizeof(int);

    rnd = rand();
    memcpy( output, &rnd, use_len );
    output += use_len;
    len -= use_len;
  }
#endif

  esp_fill_random(output, len);  /* better randomness when WiFi or Bluetooth is enabled */
  return 0;
}

static void print_buffer(const char *title, unsigned char *data, size_t len){
  size_t i;
  DEBUG_PRINTF("%s (%d bytes) ", title, len);
  for(i=0; i<len; i++){
    DEBUG_PRINTF(" %02x", data[i]);
    if(i % 16 == 15) DEBUG_PRINTLN("");
  }
  DEBUG_PRINTLN("");
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// PRIVATE KEY STORAGE
///////////////////////////////////////////////////////////////////////////////////////////////////

#include <EEPROM.h>

#define EACH         64
#define EEPROM_SIZE  (4 * EACH) + 2

int get_private_key(aergo_account *account){
  const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256K1);
  mbedtls_ecdsa_context *keypair;
  unsigned char buf[EEPROM_SIZE];
  int rc, base, i;

  if( !account ) return -2;

  keypair = &account->keypair;
  mbedtls_ecdsa_init(keypair);

  /* read data from EPROM */
  if (!EEPROM.begin(EEPROM_SIZE)){
    DEBUG_PRINTLN("failed to initialise EEPROM");
    return -1;
  }

  if( EEPROM.read(0)!=53 || EEPROM.read(1)!=79 ){
    DEBUG_PRINTLN("invalid values at EEPROM. generating a new private key");
    goto loc_notset;
  }
  base = 2;

  for (i=0; i<EEPROM_SIZE-base; i++) {
    buf[i] = EEPROM.read(base+i);
  }

  /* check if  */
  mbedtls_ecp_group_load(&keypair->grp, MBEDTLS_ECP_DP_SECP256K1);

  rc = mbedtls_mpi_read_binary(&keypair->d, buf, EACH);
  if (rc) {
    DEBUG_PRINTLN("failed read private key. probably invalid. generating a new one");
    goto loc_notset;
  }
  rc = mbedtls_mpi_read_binary(&keypair->Q.X, &buf[EACH], EACH);
  if (rc) {
    DEBUG_PRINTLN("failed read public key X. probably invalid. generating a new one");
    goto loc_notset;
  }
  rc = mbedtls_mpi_read_binary(&keypair->Q.Y, &buf[EACH*2], EACH);
  if (rc) {
    DEBUG_PRINTLN("failed read public key Y. probably invalid. generating a new one");
    goto loc_notset;
  }
  rc = mbedtls_mpi_read_binary(&keypair->Q.Z, &buf[EACH*3], EACH);
  if (rc) {
    DEBUG_PRINTLN("failed read public key Z. probably invalid. generating a new one");
    goto loc_notset;
  }


  if (rc) {
    DEBUG_PRINTLN("failed read private key. probably invalid. generating a new one");
    loc_notset:

    /* generate a new private key */
    rc = mbedtls_ecdsa_genkey(keypair, curve_info->grp_id, ecdsa_rand, NULL);
    if (rc) return rc;

    /* store the private key on the EPROM */
    rc = mbedtls_mpi_write_binary(&keypair->d, buf, EACH);
    if (rc) return rc;
    rc = mbedtls_mpi_write_binary(&keypair->Q.X, &buf[EACH], EACH);
    if (rc) return rc;
    rc = mbedtls_mpi_write_binary(&keypair->Q.Y, &buf[EACH*2], EACH);
    if (rc) return rc;
    rc = mbedtls_mpi_write_binary(&keypair->Q.Z, &buf[EACH*3], EACH);
    if (rc) return rc;

    DEBUG_PRINT("writting the private key to EEPROM.");
    EEPROM.write(0, 53);
    EEPROM.write(1, 79);
    for (i=0; i<EEPROM_SIZE-2; i++) {
      EEPROM.write(i+2, buf[i]);
      DEBUG_PRINT(".");
    }
    EEPROM.commit();
    DEBUG_PRINTLN(" done");

  }

  return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// DECODING
///////////////////////////////////////////////////////////////////////////////////////////////////

bool request_finished = false;

unsigned char* to_send = NULL;
int send_size = 0;

struct blob {
  uint8_t *ptr;
  size_t  size;
};

bool print_string(pb_istream_t *stream, const pb_field_t *field, void **arg){
    uint8_t buffer[1024] = {0};

    DEBUG_PRINTF("print_string stream->bytes_left=%d field=%p\n", stream->bytes_left, field);

    /* We could read block-by-block to avoid the large buffer... */
    if (stream->bytes_left > sizeof(buffer) - 1)
        return false;

    if (!pb_read(stream, buffer, stream->bytes_left))
        return false;

    /* Print the string, in format comparable with protoc --decode.
     * Format comes from the arg defined in main().
     */
    DEBUG_PRINTF("%s: %s\n", (char*)*arg, buffer);
    return true;
}

bool read_string(pb_istream_t *stream, const pb_field_t *field, void **arg){
    struct blob *str = *(struct blob**)arg;

    DEBUG_PRINTF("read_string arg=%p\n", str);
    if (!str) return true;
    DEBUG_PRINTF("read_string bytes_left=%d str->size=%d\n", stream->bytes_left, str->size);

    /* We could read block-by-block to avoid the large buffer... */
    if (stream->bytes_left > str->size){
        DEBUG_PRINTF("FAILED! read_string\n");
        return false;
    }

    if (!pb_read(stream, str->ptr, stream->bytes_left))
        return false;

    DEBUG_PRINTF("read_string ok\n");
    return true;
}

bool read_blob(pb_istream_t *stream, const pb_field_t *field, void **arg){
    struct blob *blob = *(struct blob**)arg;

    DEBUG_PRINTF("read_blob arg=%p\n", blob);
    if (!blob) return true;
    DEBUG_PRINTF("read_blob bytes_left=%d blob->size=%d\n", stream->bytes_left, blob->size);

    /* We could read block-by-block to avoid the large buffer... */
    if (stream->bytes_left > blob->size){
        DEBUG_PRINTF("FAILED! read_blob\n");
        return false;
    }

    if (!pb_read(stream, blob->ptr, stream->bytes_left))
        return false;

    DEBUG_PRINTF("read_blob ok\n");
    return true;
}

bool print_blob(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
    uint8_t buffer[1024] = {0};
    int len = stream->bytes_left;
    int i;

    //DEBUG_PRINTF("print_blob stream->bytes_left=%d field=%p\n", stream->bytes_left, field);

    /* We could read block-by-block to avoid the large buffer... */
    if (stream->bytes_left > sizeof(buffer) - 1)
        return false;

    if (!pb_read(stream, buffer, stream->bytes_left))
        return false;

    DEBUG_PRINT_BUFFER((char*)*arg, buffer, len);

    return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// ENCODING
///////////////////////////////////////////////////////////////////////////////////////////////////

// https://github.com/nanopb/nanopb/blob/master/tests/callbacks/encode_callbacks.c

bool encode_fixed64(pb_ostream_t *stream, const pb_field_t *field, void * const *arg){
    uint64_t value = **(uint64_t**)arg;
    uint64_t value2;

    DEBUG_PRINTF("encode_fixed64 - value=%llu\n", value);

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    //copy_be64(&value2, &value);  // convert to big endian
    value2 = value;

    return pb_encode_fixed64(stream, &value2);
}

bool encode_varuint64(pb_ostream_t *stream, const pb_field_t *field, void * const *arg){
    uint64_t value = **(uint64_t**)arg;
    uint64_t value2;
    uint8_t *ptr;
    size_t len;

    DEBUG_PRINTF("encode_varuint64 - value=%llu\n", value);

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    // convert to big endian
    copy_be64(&value2, &value);

    // skip zero bytes, unless the last one
    ptr = (uint8_t*)&value2;
    len = 8;
    while( *ptr==0 && len>1 ){ ptr++; len--; }

    DEBUG_PRINTF("encode_varuint64 - len=%u\n", len);

    return pb_encode_string(stream, ptr, len);
}

bool encode_account_address(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
    char *str = *(char**)arg;
    char decoded[128];
    bool res;

    DEBUG_PRINTF("encode_account_address '%s'\n", str);

    if (strlen(str) != EncodedAddressLength) {
      DEBUG_PRINTF("Lenght of address is invalid: %d. It should be %d\n", strlen(str), EncodedAddressLength);
    }

    res = decode_address(str, strlen(str), decoded, sizeof(decoded));

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    return pb_encode_string(stream, (uint8_t*)decoded, AddressLength);
}

bool copy_ecdsa_address(mbedtls_ecdsa_context *account, uint8_t *buf, size_t bufsize) {
    size_t len;
    bool ret;

    ret = mbedtls_ecp_point_write_binary(&account->grp, &account->Q,
                MBEDTLS_ECP_PF_COMPRESSED, &len, buf, bufsize);

    DEBUG_PRINTF("copy_ecdsa_address - ret=%d len=%d\n", ret, len);

    return ret && (len == AddressLength);
}

bool encode_ecdsa_address(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
    mbedtls_ecdsa_context *account = *(mbedtls_ecdsa_context**)arg;
    uint8_t buf[128];
    size_t len;
    bool ret;

    ret = mbedtls_ecp_point_write_binary(&account->grp, &account->Q,
                MBEDTLS_ECP_PF_COMPRESSED, &len, buf, sizeof buf);

    if( ret != 0 ){
        DEBUG_PRINTF("encode_ecdsa_address - invalid account\n");
        return false;
    }

    DEBUG_PRINTF("encode_ecdsa_address - len=%d\n", len);

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    return pb_encode_string(stream, buf, len);
}

bool encode_string(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
    char *str = *(char**)arg;

    DEBUG_PRINTF("encode_string '%s'\n", str);

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    return pb_encode_string(stream, (uint8_t*)str, strlen(str));
}

bool encode_blob(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
    struct blob *blob = *(struct blob**)arg;

    DEBUG_PRINTF("encode_blob arg=%p\n", blob);
    if (!blob) return true;

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    if (blob->ptr==0) return true;
    return pb_encode_string(stream, blob->ptr, blob->size);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// HTTP2 REQUEST CALLBACKS
///////////////////////////////////////////////////////////////////////////////////////////////////

uint8_t blockchain_id_hash[32];

int handle_blockchain_status_response(struct sh2lib_handle *handle, const char *data, size_t len, int flags) {
    if (len > 0) {
        int i, ret;
        BlockchainStatus status = BlockchainStatus_init_zero;

        DEBUG_PRINT_BUFFER("returned", data, len);

        /* Create a stream that reads from the buffer */
        pb_istream_t stream = pb_istream_from_buffer((const unsigned char *)&data[5], len-5);

        /* Set the callback functions */
        struct blob bb { .ptr = blockchain_id_hash, .size = 32 };
        status.best_chain_id_hash.arg = &bb;
        status.best_chain_id_hash.funcs.decode = &read_blob;

        /* Now we are ready to decode the message */
        ret = pb_decode(&stream, BlockchainStatus_fields, &status);

        /* Check for errors... */
        if (!ret) {
            DEBUG_PRINTF("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }

        /* Print the data contained in the message */
        //DEBUG_PRINTF("Block number: %llu\n", block.header.blockNo);
        DEBUG_PRINT_BUFFER("  + ChainIdHash: ", blockchain_id_hash, sizeof(blockchain_id_hash));

    } else {
        DEBUG_PRINTLN("returned 0 bytes");
    }

    if (flags == DATA_RECV_FRAME_COMPLETE) {
        request_finished = true;
        DEBUG_PRINTLN("COMPLETE FRAME RECEIVED");
    } else if (flags == DATA_RECV_RST_STREAM) {
        request_finished = true;
        DEBUG_PRINTLN("STREAM CLOSED");
    }
    return 0;
}

int handle_account_state_response(struct sh2lib_handle *handle, const char *data, size_t len, int flags) {
    if (len > 0) {
        int i, ret;
        //State state = State_init_zero;
        account_state = State_init_zero;

        DEBUG_PRINT_BUFFER("returned", data, len);

        /* Create a stream that reads from the buffer */
        pb_istream_t stream = pb_istream_from_buffer((const unsigned char *)&data[5], len-5);

        /* Set the callback functions */

        //state.balance.arg = &balance;
        //state.balance.funcs.decode = &read_varuint64;

        //struct blob bb { .ptr = storageRoot, .size = 32 };
        //state.storageRoot.arg = &bb;
        //state.storageRoot.funcs.decode = &read_varuint64;

        /* Now we are ready to decode the message */
        ret = pb_decode(&stream, State_fields, &account_state);

        /* Check for errors... */
        if (!ret) {
            DEBUG_PRINTF("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }

        //account_nonce = state.nonce;

        /* Print the data contained in the message */
        DEBUG_PRINTF("Account Nonce: %llu\n", account_state.nonce);
        //DEBUG_PRINT_BUFFER("  + ChainIdHash: ", storageRoot, sizeof(storageRoot));

    } else {
        DEBUG_PRINTLN("returned 0 bytes");
    }

    if (flags == DATA_RECV_FRAME_COMPLETE) {
        request_finished = true;
        DEBUG_PRINTLN("COMPLETE FRAME RECEIVED");
    } else if (flags == DATA_RECV_RST_STREAM) {
        request_finished = true;
        DEBUG_PRINTLN("STREAM CLOSED");
    }
    return 0;
}

int handle_post_response(struct sh2lib_handle *handle, const char *data, size_t len, int flags) {
    if (len > 0) {
        int i, status;
        Block block = Block_init_zero;

        DEBUG_PRINT_BUFFER("returned", data, len);

        /* Create a stream that reads from the buffer */
        pb_istream_t stream = pb_istream_from_buffer((const unsigned char *)&data[5], len-5);

        /* Set the callback functions */
        block.header.chainID.funcs.decode = &print_blob;
        block.header.chainID.arg = (void*)"chainID";
        block.header.pubKey.funcs.decode = &print_blob;
        block.header.pubKey.arg = (void*)"pubKey";
        block.body.txs.funcs.decode = &print_string;
        block.body.txs.arg = (void*)"txs";

        /* Now we are ready to decode the message */
        status = pb_decode(&stream, Block_fields, &block);

        /* Check for errors... */
        if (!status) {
            DEBUG_PRINTF("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }

        /* Print the data contained in the message */
        DEBUG_PRINTF("Block number: %llu\n", block.header.blockNo);
        DEBUG_PRINTF("Block timestamp: %llu\n", block.header.timestamp);
        DEBUG_PRINTF("Block confirms: %llu\n", block.header.confirms);

    } else {
        DEBUG_PRINTLN("returned 0 bytes");
    }

    if (flags == DATA_RECV_FRAME_COMPLETE) {
        DEBUG_PRINTLN("COMPLETE FRAME RECEIVED");
    } else if (flags == DATA_RECV_RST_STREAM) {
        request_finished = true;
        DEBUG_PRINTLN("STREAM CLOSED");
    }
    return 0;
}

int handle_contract_call_response(struct sh2lib_handle *handle, const char *data, size_t len, int flags) {
    if (len > 0) {
        int i, status;
        CommitResultList response = CommitResultList_init_zero;

        DEBUG_PRINT_BUFFER("returned", data, len);

        /* Create a stream that reads from the buffer */
        pb_istream_t stream = pb_istream_from_buffer((const unsigned char *)&data[5], len-5);

        /* Set the callback functions */
        //response.value.funcs.decode = &print_string;
        //response.value.arg = (void*)"Result";

        /* Now we are ready to decode the message */
        status = pb_decode(&stream, CommitResultList_fields, &response);

        /* Check for errors... */
        if (!status) {
            DEBUG_PRINTF("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }

        /* Print the data contained in the message */
        //DEBUG_PRINTF("response error status: %u\n", response.results.error);   TODO: fix this

    } else {
        DEBUG_PRINTLN("returned 0 bytes");
    }

    if (flags == DATA_RECV_FRAME_COMPLETE) {
        request_finished = true;
        DEBUG_PRINTLN("COMPLETE FRAME RECEIVED");
    } else if (flags == DATA_RECV_RST_STREAM) {
        request_finished = true;
        DEBUG_PRINTLN("STREAM CLOSED");
    }
    return 0;
}

int handle_query_response(struct sh2lib_handle *handle, const char *data, size_t len, int flags) {
    if (len > 0) {
        int i, status;
        SingleBytes response = SingleBytes_init_zero;

        DEBUG_PRINT_BUFFER("returned", data, len);

        /* Create a stream that reads from the buffer */
        pb_istream_t stream = pb_istream_from_buffer((const unsigned char *)&data[5], len-5);

        /* Set the callback functions */
        response.value.funcs.decode = &print_string;
        response.value.arg = (void*)"Result";

        /* Now we are ready to decode the message */
        status = pb_decode(&stream, SingleBytes_fields, &response);

        /* Check for errors... */
        if (!status) {
            DEBUG_PRINTF("Decoding failed: %s\n", PB_GET_ERROR(&stream));
            return 1;
        }

        /* Print the data contained in the message */
        //DEBUG_PRINTF("xxxxx: %llu\n", block.header.confirms);

    } else {
        DEBUG_PRINTLN("returned 0 bytes");
    }

    if (flags == DATA_RECV_FRAME_COMPLETE) {
        request_finished = true;
        DEBUG_PRINTLN("COMPLETE FRAME RECEIVED");
    } else if (flags == DATA_RECV_RST_STREAM) {
        request_finished = true;
        DEBUG_PRINTLN("STREAM CLOSED");
    }
    return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// HTTP2 SEND CALLBACK
///////////////////////////////////////////////////////////////////////////////////////////////////

int send_post_data(struct sh2lib_handle *handle, char *buf, size_t length, uint32_t *data_flags) {
    int copylen = send_size;
    int i;

    DEBUG_PRINTF("send_post_data length=%d\n", length);

    if (copylen <= length) {
        memcpy(buf, to_send, copylen);
    } else {
        copylen = 0;
    }

    DEBUG_PRINT_BUFFER("sending", buf, copylen);

    (*data_flags) |= NGHTTP2_DATA_FLAG_EOF;
    return copylen;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// AERGO SPECIFIC
///////////////////////////////////////////////////////////////////////////////////////////////////

struct txn {
  uint64_t nonce;
  unsigned char account[AddressLength];      // decoded account address
  unsigned char recipient[AddressLength];    // decoded account address
  uint64_t amount;              // variable-length big integer
  char *payload;
  uint64_t gasLimit;
  uint64_t gasPrice;            // variable-length big integer
  uint32_t type;
  unsigned char *chainIdHash;   // hash value of chain identifier in the block
  unsigned char sign[MBEDTLS_ECDSA_MAX_LEN]; // sender's signature for this TxBody
  size_t sig_len;
};

bool encode_bigint(uint8_t **pptr, uint64_t value){

  // TODO: encode the amount
  //       it can use the bignum (mpi) from mbedtls

  //len = xxx(txn->amount);
  //memcpy(ptr, txn->amount, len); ptr += len;

  // for now it is just including a single byte (zero)
  // this should be removed:
  memcpy(*pptr, &value, 1); (*pptr)++;

  return true;
}

bool calculate_tx_hash(struct txn *txn, unsigned char *hash, bool include_signature){
  uint8_t buf[1024], *ptr;
  size_t len = 0;

  ptr = buf;

  memcpy(ptr, &txn->nonce, 8); ptr += 8;

  memcpy(ptr, txn->account, AddressLength); ptr += AddressLength;

  //if (txn->recipient){
    memcpy(ptr, txn->recipient, AddressLength); ptr += AddressLength;
  //}

  encode_bigint(&ptr, txn->amount);

  if (txn->payload){
    len = strlen(txn->payload);
    memcpy(ptr, txn->payload, len); ptr += len;
  }

  memcpy(ptr, &txn->gasLimit, 8); ptr += 8;

  encode_bigint(&ptr, txn->gasPrice);

  memcpy(ptr, &txn->type, 4); ptr += 4;

  memcpy(ptr, txn->chainIdHash, 32); ptr += 32;

  if (include_signature) {
    memcpy(ptr, txn->sign, txn->sig_len); ptr += txn->sig_len;
  }

  len = ptr - buf;
  sha256(hash, buf, len);

  return true;
}

bool sign_transaction(struct txn *txn, mbedtls_ecdsa_context *account){
  uint8_t hash[32];
  bool ret;

  calculate_tx_hash(txn, hash, false);

  mbedtls_printf("sign_transaction\n");
  DEBUG_PRINT_BUFFER("  + Hash: ", hash, sizeof(hash));

  // Sign the message hash
  ret = mbedtls_ecdsa_write_signature(account, MBEDTLS_MD_SHA256,
                                      hash, sizeof(hash),
                                      txn->sign, &txn->sig_len,
                                      ecdsa_rand, NULL);

  DEBUG_PRINTF("ret_write_sign = %d\n", ret);
  mbedtls_printf( " ok (signature length = %u)\n", (unsigned int) txn->sig_len );
  DEBUG_PRINT_BUFFER("  + Signature: ", txn->sign, txn->sig_len);

  return (ret == 0);
}

bool encode_1_transaction(pb_ostream_t *stream, const pb_field_t *field, void * const *arg) {
  struct txn *txn = *(struct txn **)arg;
  uint8_t hash[32];
  Tx message = Tx_init_zero;

  if (!pb_encode_tag_for_field(stream, field))
      return false;

  calculate_tx_hash(txn, hash, true);

  /* Set the values and the encoder callback functions */
  struct blob bb { .ptr = hash, .size = 32 };
  message.hash.arg = &bb;
  message.hash.funcs.encode = &encode_blob;


  /* Set the values and the encoder callback functions */
  message.body.type = (TxType) txn->type;
  message.body.nonce = txn->nonce;

  struct blob acc { .ptr = txn->account, .size = AddressLength };
  message.body.account.arg = &acc;
  message.body.account.funcs.encode = encode_blob;

  struct blob rec { .ptr = txn->recipient, .size = AddressLength };
  message.body.recipient.arg = &rec;
  message.body.recipient.funcs.encode = encode_blob;

  message.body.payload.arg = txn->payload;
  message.body.payload.funcs.encode = &encode_string;

  message.body.amount.arg = &txn->amount;
  message.body.amount.funcs.encode = &encode_varuint64;

  message.body.gasLimit = txn->gasLimit;

  message.body.gasPrice.arg = &txn->gasPrice;
  message.body.gasPrice.funcs.encode = &encode_varuint64;

  struct blob cid { .ptr = txn->chainIdHash, .size = 32 };
  message.body.chainIdHash.arg = &cid;
  message.body.chainIdHash.funcs.encode = &encode_blob;

  struct blob sig { .ptr = txn->sign, .size = txn->sig_len };
  message.body.sign.arg = &sig;
  message.body.sign.funcs.encode = &encode_blob;


  /* Now we are ready to decode the message */
  bool status = pb_encode_submessage(stream, Tx_fields, &message);
  if (!status) {
    DEBUG_PRINTF("Encoding failed: %s\n", PB_GET_ERROR(stream));
  }
  return status;
}

bool encode_transaction(uint8_t *buffer, size_t *psize, struct txn *txn) {
  TxList message = TxList_init_zero;
  uint32_t size32;

  /* Create a stream that writes to the buffer */
  pb_ostream_t stream = pb_ostream_from_buffer(&buffer[5], *psize - 5);

  /* Set the values and the encoder callback functions */
  message.txs.arg = txn;
  message.txs.funcs.encode = &encode_1_transaction;

  /* Now we are ready to decode the message */
  bool status = pb_encode(&stream, TxList_fields, &message);
  if (!status) {
    DEBUG_PRINTF("Encoding failed: %s\n", PB_GET_ERROR(&stream));
    return false;
  }

  buffer[0] = 0;  // no compression
  size32 = stream.bytes_written;
  copy_be32((uint32_t*)&buffer[1], &size32);  // insert the size in the stream as big endian 32-bit integer
  size32 += 5;

  DEBUG_PRINT_BUFFER("Message", buffer, size32);

  *psize = size32;
  return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

bool EncodeContractCall(uint8_t *buffer, size_t *psize, char *contract_address, char *call_info, mbedtls_ecdsa_context *account) {
  struct txn txn;
  char out[64]={0};

  /* increment the account nonce */
  account_state.nonce++;

  txn.nonce = account_state.nonce;
  copy_ecdsa_address(account, txn.account, sizeof txn.account);
  decode_address(contract_address, strlen(contract_address), txn.recipient, sizeof(txn.recipient));
  txn.amount = 0;        // variable-length big integer
  txn.payload = call_info;
  txn.gasLimit = 0;
  txn.gasPrice = 0;      // variable-length big integer
  txn.type = TxType_NORMAL;
  txn.chainIdHash = blockchain_id_hash;

  encode_address(txn.account, sizeof txn.account, out, sizeof out);
  DEBUG_PRINTF("account address: %s\n", out);
  DEBUG_PRINTF("account nonce: %llu\n", account_state.nonce);

  if (sign_transaction(&txn, account) == false) {
    return false;
  }

  return encode_transaction(buffer, psize, &txn);
}

bool EncodeQuery(uint8_t *buffer, size_t *psize, char *contract_address, char *query_info){
  Query message = Query_init_zero;
  uint32_t size32;

  /* Create a stream that writes to the buffer */
  pb_ostream_t stream = pb_ostream_from_buffer(&buffer[5], *psize - 5);

  /* Set the callback functions */
  message.contractAddress.funcs.encode = &encode_account_address;
  message.contractAddress.arg = contract_address;
  message.queryinfo.funcs.encode = &encode_string;
  message.queryinfo.arg = query_info;

  /* Now we are ready to decode the message */
  bool status = pb_encode(&stream, Query_fields, &message);
  if (!status) {
    DEBUG_PRINTF("Encoding failed: %s\n", PB_GET_ERROR(&stream));
    return false;
  }

  buffer[0] = 0;  // no compression
  size32 = stream.bytes_written;
  copy_be32((uint32_t*)&buffer[1], &size32);  // insert the size in the stream as big endian 32-bit integer
  size32 += 5;

  DEBUG_PRINT_BUFFER("Message", buffer, size32);

  *psize = size32;
  return true;
}

bool EncodeAccountAddress(uint8_t *buffer, size_t *psize, mbedtls_ecdsa_context *account) {
  SingleBytes message = SingleBytes_init_zero;
  uint32_t size32;

  /* Create a stream that writes to the buffer */
  pb_ostream_t stream = pb_ostream_from_buffer(&buffer[5], *psize - 5);

  /* Set the callback functions */
  message.value.funcs.encode = &encode_ecdsa_address;
  message.value.arg = account;

  /* Now we are ready to decode the message */
  bool status = pb_encode(&stream, SingleBytes_fields, &message);
  if (!status) {
    DEBUG_PRINTF("Encoding failed: %s\n", PB_GET_ERROR(&stream));
    return false;
  }

  buffer[0] = 0;  // no compression
  size32 = stream.bytes_written;
  copy_be32((uint32_t*)&buffer[1], &size32);  // insert the size in the stream as big endian 32-bit integer
  size32 += 5;

  DEBUG_PRINT_BUFFER("Message", buffer, size32);

  *psize = size32;
  return true;
}

bool EncodeBlockNo(uint8_t *buffer, size_t *psize, uint64_t blockNo){
  SingleBytes message = SingleBytes_init_zero;
  //  BlockMetadata blockmeta = BlockMetadata_init_zero;
  //  Block block = Block_init_zero;
  uint32_t size32;

  /* Create a stream that writes to the buffer */
  pb_ostream_t stream = pb_ostream_from_buffer(&buffer[5], *psize - 5);

  /* Set the callback functions */
  message.value.funcs.encode = &encode_fixed64;
  message.value.arg = &blockNo;

  /* Now we are ready to decode the message */
  bool status = pb_encode(&stream, SingleBytes_fields, &message);
  if (!status) {
    DEBUG_PRINTF("Encoding failed: %s\n", PB_GET_ERROR(&stream));
    return false;
  }

  buffer[0] = 0;  // no compression
  size32 = stream.bytes_written;
  copy_be32((uint32_t*)&buffer[1], &size32);  // insert the size in the stream as big endian 32-bit integer
  size32 += 5;

  DEBUG_PRINT_BUFFER("Message", buffer, size32);

  *psize = size32;
  return true;
}

bool EncodeEmptyMessage(uint8_t *buffer, size_t *psize){
  Empty message = Empty_init_zero;
  uint32_t size32;

  /* Create a stream that writes to the buffer */
  pb_ostream_t stream = pb_ostream_from_buffer(&buffer[5], *psize - 5);

  /* Now we are ready to decode the message */
  bool status = pb_encode(&stream, Empty_fields, &message);
  if (!status) {
    DEBUG_PRINTF("Encoding failed: %s\n", PB_GET_ERROR(&stream));
    return false;
  }

  buffer[0] = 0;  // no compression
  size32 = stream.bytes_written;
  copy_be32((uint32_t*)&buffer[1], &size32);  // insert the size in the stream as big endian 32-bit integer
  size32 += 5;

  DEBUG_PRINT_BUFFER("Message", buffer, size32);

  *psize = size32;
  return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

void send_grpc_request(struct sh2lib_handle *hd, char *service, uint8_t *buffer, size_t size, sh2lib_frame_data_recv_cb_t response_callback) {
  char path[64];
  char len[8];

  to_send = buffer;
  send_size = size;

  sprintf(path, "/types.AergoRPCService/%s", service);
  sprintf(len, "%d", size);

  const nghttp2_nv nva[] = { SH2LIB_MAKE_NV(":method", "POST"),
                             SH2LIB_MAKE_NV(":scheme", "https"),
                             SH2LIB_MAKE_NV(":authority", hd->hostname),
                             SH2LIB_MAKE_NV(":path", path),
                             //SH2LIB_MAKE_NV("te", "trailers"),
                             SH2LIB_MAKE_NV("Content-Type", "application/grpc"),
                             //SH2LIB_MAKE_NV("grpc-encoding", "identity")
                             SH2LIB_MAKE_NV("content-length", len)
                           };

  request_finished = false;
  sh2lib_do_putpost_with_nv(hd, nva, sizeof(nva) / sizeof(nva[0]), send_post_data, response_callback);

  while (!request_finished) {
    DEBUG_PRINTLN("sh2lib_execute");
    if (sh2lib_execute(hd) != ESP_OK) {
      DEBUG_PRINTLN("Error in execute");
      break;
    }
    vTaskDelay(25);
  }

  DEBUG_PRINTLN("Request done. returning");
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// EXPORTED FUNCTIONS
///////////////////////////////////////////////////////////////////////////////////////////////////

void ContractCall(aergo *instance, char *contract_address, char *call_info, aergo_account *account){
  uint8_t buffer[1024];
  size_t size;

  size = sizeof(buffer);
  if (EncodeContractCall(buffer, &size, contract_address, call_info, &account->keypair)){
    send_grpc_request(&instance->hd, "CommitTX", buffer, size, handle_contract_call_response);
  }

}

void queryContract(aergo *instance, char *contract_address, char *query_info){
  uint8_t buffer[256];
  size_t size;

  size = sizeof(buffer);
  if (EncodeQuery(buffer, &size, contract_address, query_info)){
    send_grpc_request(&instance->hd, "QueryContract", buffer, size, handle_query_response);
  }

}

void requestBlock(aergo *instance, uint64_t blockNo){
  uint8_t buffer[128];
  size_t size;

  size = sizeof(buffer);
  if (EncodeBlockNo(buffer, &size, blockNo)){
    send_grpc_request(&instance->hd, "GetBlockMetadata", buffer, size, handle_post_response);
  }

}

void requestBlockStream(aergo *instance){
  uint8_t buffer[128];
  size_t size;

  size = sizeof(buffer);
  if (EncodeEmptyMessage(buffer, &size)){
    send_grpc_request(&instance->hd, "ListBlockStream", buffer, size, handle_post_response);
  }

}

void requestBlockchainStatus(aergo *instance){
  uint8_t buffer[128];
  size_t size;

  size = sizeof(buffer);
  if (EncodeEmptyMessage(buffer, &size)){
    send_grpc_request(&instance->hd, "Blockchain", buffer, size, handle_blockchain_status_response);
  }

}

void requestAccountState(aergo *instance, aergo_account *account){
  uint8_t buffer[128];
  size_t size;

  size = sizeof(buffer);
  if (EncodeAccountAddress(buffer, &size, &account->keypair)){
    send_grpc_request(&instance->hd, "GetState", buffer, size, handle_account_state_response);
  }

  // copy values to the account structure

  copy_ecdsa_address(&account->keypair, buffer, sizeof buffer);
  encode_address(buffer, AddressLength, account->address, sizeof account->address);

  account->nonce = account_state.nonce;

}

///////////////////////////////////////////////////////////////////////////////////////////////////

int aergo_connect(aergo *instance, char *host) {
  return sh2lib_connect(&instance->hd, host);  // ESP_OK
}

void aergo_free(aergo *instance) {
  sh2lib_free(&instance->hd);
}

void aergo_free_account(aergo_account *account) {
  mbedtls_ecdsa_free(&account->keypair);
}
