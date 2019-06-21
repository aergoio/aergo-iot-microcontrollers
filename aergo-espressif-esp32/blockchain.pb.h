/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.3 at Thu Jun 20 05:02:06 2019. */

#ifndef PB_BLOCKCHAIN_PB_H_INCLUDED
#define PB_BLOCKCHAIN_PB_H_INCLUDED
#include <pb.h>

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _TxType {
    TxType_NORMAL = 0,
    TxType_GOVERNANCE = 1,
    TxType_REDEPLOY = 2
} TxType;
#define _TxType_MIN TxType_NORMAL
#define _TxType_MAX TxType_REDEPLOY
#define _TxType_ARRAYSIZE ((TxType)(TxType_REDEPLOY+1))

typedef enum _CommitStatus {
    CommitStatus_TX_OK = 0,
    CommitStatus_TX_NONCE_TOO_LOW = 1,
    CommitStatus_TX_ALREADY_EXISTS = 2,
    CommitStatus_TX_INVALID_HASH = 3,
    CommitStatus_TX_INVALID_SIGN = 4,
    CommitStatus_TX_INVALID_FORMAT = 5,
    CommitStatus_TX_INSUFFICIENT_BALANCE = 6,
    CommitStatus_TX_HAS_SAME_NONCE = 7,
    CommitStatus_TX_INTERNAL_ERROR = 9
} CommitStatus;
#define _CommitStatus_MIN CommitStatus_TX_OK
#define _CommitStatus_MAX CommitStatus_TX_INTERNAL_ERROR
#define _CommitStatus_ARRAYSIZE ((CommitStatus)(CommitStatus_TX_INTERNAL_ERROR+1))

/* Struct definitions */
typedef struct _ABI {
    pb_callback_t version;
    pb_callback_t language;
    pb_callback_t functions;
    pb_callback_t state_variables;
/* @@protoc_insertion_point(struct:ABI) */
} ABI;

typedef struct _AccountAddress {
    pb_callback_t value;
/* @@protoc_insertion_point(struct:AccountAddress) */
} AccountAddress;

typedef struct _BlockBody {
    pb_callback_t txs;
/* @@protoc_insertion_point(struct:BlockBody) */
} BlockBody;

typedef struct _CommitResultList {
    pb_callback_t results;
/* @@protoc_insertion_point(struct:CommitResultList) */
} CommitResultList;

typedef struct _Empty {
    char dummy_field;
/* @@protoc_insertion_point(struct:Empty) */
} Empty;

typedef struct _FnArgument {
    pb_callback_t name;
/* @@protoc_insertion_point(struct:FnArgument) */
} FnArgument;

typedef struct _Query {
    pb_callback_t contractAddress;
    pb_callback_t queryinfo;
/* @@protoc_insertion_point(struct:Query) */
} Query;

typedef struct _SingleBytes {
    pb_callback_t value;
/* @@protoc_insertion_point(struct:SingleBytes) */
} SingleBytes;

typedef struct _TxList {
    pb_callback_t txs;
/* @@protoc_insertion_point(struct:TxList) */
} TxList;

typedef struct _AccountAndRoot {
    pb_callback_t Account;
    pb_callback_t Root;
    bool Compressed;
/* @@protoc_insertion_point(struct:AccountAndRoot) */
} AccountAndRoot;

typedef struct _BlockHeader {
    pb_callback_t chainID;
    pb_callback_t prevBlockHash;
    uint64_t blockNo;
    int64_t timestamp;
    pb_callback_t blocksRootHash;
    pb_callback_t txsRootHash;
    pb_callback_t receiptsRootHash;
    uint64_t confirms;
    pb_callback_t pubKey;
    pb_callback_t coinbaseAccount;
    pb_callback_t sign;
/* @@protoc_insertion_point(struct:BlockHeader) */
} BlockHeader;

typedef struct _BlockchainStatus {
    pb_callback_t best_block_hash;
    uint64_t best_height;
    pb_callback_t consensus_info;
    pb_callback_t best_chain_id_hash;
/* @@protoc_insertion_point(struct:BlockchainStatus) */
} BlockchainStatus;

typedef struct _CommitResult {
    pb_callback_t hash;
    CommitStatus error;
    pb_callback_t detail;
/* @@protoc_insertion_point(struct:CommitResult) */
} CommitResult;

typedef struct _ContractVarProof {
    pb_callback_t value;
    bool inclusion;
    pb_callback_t proofKey;
    pb_callback_t proofVal;
    pb_callback_t bitmap;
    uint32_t height;
    pb_callback_t auditPath;
    pb_callback_t key;
/* @@protoc_insertion_point(struct:ContractVarProof) */
} ContractVarProof;

typedef struct _Event {
    pb_callback_t contractAddress;
    pb_callback_t eventName;
    pb_callback_t jsonArgs;
    int32_t eventIdx;
    pb_callback_t txHash;
    pb_callback_t blockHash;
    uint64_t blockNo;
    int32_t txIndex;
/* @@protoc_insertion_point(struct:Event) */
} Event;

typedef struct _FilterInfo {
    pb_callback_t contractAddress;
    pb_callback_t eventName;
    uint64_t blockfrom;
    uint64_t blockto;
    bool desc;
    pb_callback_t argFilter;
    int32_t recentBlockCnt;
/* @@protoc_insertion_point(struct:FilterInfo) */
} FilterInfo;

typedef struct _Function {
    pb_callback_t name;
    pb_callback_t arguments;
    bool payable;
    bool view;
/* @@protoc_insertion_point(struct:Function) */
} Function;

typedef struct _Receipt {
    pb_callback_t contractAddress;
    pb_callback_t status;
    pb_callback_t ret;
    pb_callback_t txHash;
    pb_callback_t feeUsed;
    pb_callback_t cumulativeFeeUsed;
    pb_callback_t bloom;
    pb_callback_t events;
    uint64_t blockNo;
    pb_callback_t blockHash;
    int32_t txIndex;
    pb_callback_t from;
    pb_callback_t to;
/* @@protoc_insertion_point(struct:Receipt) */
} Receipt;

typedef struct _State {
    uint64_t nonce;
    pb_callback_t balance;
    pb_callback_t codeHash;
    pb_callback_t storageRoot;
    uint64_t sqlRecoveryPoint;
/* @@protoc_insertion_point(struct:State) */
} State;

typedef struct _StateQuery {
    pb_callback_t contractAddress;
    pb_callback_t root;
    bool compressed;
    pb_callback_t storageKeys;
/* @@protoc_insertion_point(struct:StateQuery) */
} StateQuery;

typedef struct _StateVar {
    pb_callback_t name;
    pb_callback_t type;
    int32_t len;
/* @@protoc_insertion_point(struct:StateVar) */
} StateVar;

typedef struct _TxBody {
    uint64_t nonce;
    pb_callback_t account;
    pb_callback_t recipient;
    pb_callback_t amount;
    pb_callback_t payload;
    uint64_t gasLimit;
    pb_callback_t gasPrice;
    TxType type;
    pb_callback_t chainIdHash;
    pb_callback_t sign;
/* @@protoc_insertion_point(struct:TxBody) */
} TxBody;

typedef struct _TxIdx {
    pb_callback_t blockHash;
    int32_t idx;
/* @@protoc_insertion_point(struct:TxIdx) */
} TxIdx;

typedef struct _AccountProof {
    State state;
    bool inclusion;
    pb_callback_t key;
    pb_callback_t proofKey;
    pb_callback_t proofVal;
    pb_callback_t bitmap;
    uint32_t height;
    pb_callback_t auditPath;
/* @@protoc_insertion_point(struct:AccountProof) */
} AccountProof;

typedef struct _Block {
    pb_callback_t hash;
    BlockHeader header;
    BlockBody body;
/* @@protoc_insertion_point(struct:Block) */
} Block;

typedef struct _BlockMetadata {
    pb_callback_t hash;
    BlockHeader header;
    int32_t txcount;
    int64_t size;
/* @@protoc_insertion_point(struct:BlockMetadata) */
} BlockMetadata;

typedef struct _Tx {
    pb_callback_t hash;
    TxBody body;
/* @@protoc_insertion_point(struct:Tx) */
} Tx;

typedef struct _StateQueryProof {
    AccountProof contractProof;
    pb_callback_t varProofs;
/* @@protoc_insertion_point(struct:StateQueryProof) */
} StateQueryProof;

typedef struct _TxInBlock {
    TxIdx txIdx;
    Tx tx;
/* @@protoc_insertion_point(struct:TxInBlock) */
} TxInBlock;

/* Default values for struct fields */

/* Initializer values for message structs */
#define Empty_init_default                       {0}
#define SingleBytes_init_default                 {{{NULL}, NULL}}
#define BlockchainStatus_init_default            {{{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define AccountAddress_init_default              {{{NULL}, NULL}}
#define AccountAndRoot_init_default              {{{NULL}, NULL}, {{NULL}, NULL}, 0}
#define BlockMetadata_init_default               {{{NULL}, NULL}, BlockHeader_init_default, 0, 0}
#define Block_init_default                       {{{NULL}, NULL}, BlockHeader_init_default, BlockBody_init_default}
#define BlockHeader_init_default                 {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define BlockBody_init_default                   {{{NULL}, NULL}}
#define TxList_init_default                      {{{NULL}, NULL}}
#define Tx_init_default                          {{{NULL}, NULL}, TxBody_init_default}
#define TxBody_init_default                      {0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, _TxType_MIN, {{NULL}, NULL}, {{NULL}, NULL}}
#define TxIdx_init_default                       {{{NULL}, NULL}, 0}
#define TxInBlock_init_default                   {TxIdx_init_default, Tx_init_default}
#define State_init_default                       {0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0}
#define AccountProof_init_default                {State_init_default, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}}
#define ContractVarProof_init_default            {{{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define StateQueryProof_init_default             {AccountProof_init_default, {{NULL}, NULL}}
#define Receipt_init_default                     {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define Event_init_default                       {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}, 0, 0}
#define FnArgument_init_default                  {{{NULL}, NULL}}
#define Function_init_default                    {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0}
#define StateVar_init_default                    {{{NULL}, NULL}, {{NULL}, NULL}, 0}
#define ABI_init_default                         {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define Query_init_default                       {{{NULL}, NULL}, {{NULL}, NULL}}
#define StateQuery_init_default                  {{{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}}
#define FilterInfo_init_default                  {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, 0, {{NULL}, NULL}, 0}
#define CommitResult_init_default                {{{NULL}, NULL}, _CommitStatus_MIN, {{NULL}, NULL}}
#define CommitResultList_init_default            {{{NULL}, NULL}}
#define Empty_init_zero                          {0}
#define SingleBytes_init_zero                    {{{NULL}, NULL}}
#define BlockchainStatus_init_zero               {{{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define AccountAddress_init_zero                 {{{NULL}, NULL}}
#define AccountAndRoot_init_zero                 {{{NULL}, NULL}, {{NULL}, NULL}, 0}
#define BlockMetadata_init_zero                  {{{NULL}, NULL}, BlockHeader_init_zero, 0, 0}
#define Block_init_zero                          {{{NULL}, NULL}, BlockHeader_init_zero, BlockBody_init_zero}
#define BlockHeader_init_zero                    {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define BlockBody_init_zero                      {{{NULL}, NULL}}
#define TxList_init_zero                         {{{NULL}, NULL}}
#define Tx_init_zero                             {{{NULL}, NULL}, TxBody_init_zero}
#define TxBody_init_zero                         {0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, _TxType_MIN, {{NULL}, NULL}, {{NULL}, NULL}}
#define TxIdx_init_zero                          {{{NULL}, NULL}, 0}
#define TxInBlock_init_zero                      {TxIdx_init_zero, Tx_init_zero}
#define State_init_zero                          {0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0}
#define AccountProof_init_zero                   {State_init_zero, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}}
#define ContractVarProof_init_zero               {{{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define StateQueryProof_init_zero                {AccountProof_init_zero, {{NULL}, NULL}}
#define Receipt_init_zero                        {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}}
#define Event_init_zero                          {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}, {{NULL}, NULL}, 0, 0}
#define FnArgument_init_zero                     {{{NULL}, NULL}}
#define Function_init_zero                       {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0}
#define StateVar_init_zero                       {{{NULL}, NULL}, {{NULL}, NULL}, 0}
#define ABI_init_zero                            {{{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}, {{NULL}, NULL}}
#define Query_init_zero                          {{{NULL}, NULL}, {{NULL}, NULL}}
#define StateQuery_init_zero                     {{{NULL}, NULL}, {{NULL}, NULL}, 0, {{NULL}, NULL}}
#define FilterInfo_init_zero                     {{{NULL}, NULL}, {{NULL}, NULL}, 0, 0, 0, {{NULL}, NULL}, 0}
#define CommitResult_init_zero                   {{{NULL}, NULL}, _CommitStatus_MIN, {{NULL}, NULL}}
#define CommitResultList_init_zero               {{{NULL}, NULL}}

/* Field tags (for use in manual encoding/decoding) */
#define ABI_version_tag                          1
#define ABI_language_tag                         2
#define ABI_functions_tag                        3
#define ABI_state_variables_tag                  4
#define AccountAddress_value_tag                 1
#define BlockBody_txs_tag                        1
#define CommitResultList_results_tag             1
#define FnArgument_name_tag                      1
#define Query_contractAddress_tag                1
#define Query_queryinfo_tag                      2
#define SingleBytes_value_tag                    1
#define TxList_txs_tag                           1
#define AccountAndRoot_Account_tag               1
#define AccountAndRoot_Root_tag                  2
#define AccountAndRoot_Compressed_tag            3
#define BlockHeader_chainID_tag                  1
#define BlockHeader_prevBlockHash_tag            2
#define BlockHeader_blockNo_tag                  3
#define BlockHeader_timestamp_tag                4
#define BlockHeader_blocksRootHash_tag           5
#define BlockHeader_txsRootHash_tag              6
#define BlockHeader_receiptsRootHash_tag         7
#define BlockHeader_confirms_tag                 8
#define BlockHeader_pubKey_tag                   9
#define BlockHeader_coinbaseAccount_tag          10
#define BlockHeader_sign_tag                     11
#define BlockchainStatus_best_block_hash_tag     1
#define BlockchainStatus_best_height_tag         2
#define BlockchainStatus_consensus_info_tag      3
#define BlockchainStatus_best_chain_id_hash_tag  4
#define CommitResult_hash_tag                    1
#define CommitResult_error_tag                   2
#define CommitResult_detail_tag                  3
#define ContractVarProof_value_tag               1
#define ContractVarProof_inclusion_tag           2
#define ContractVarProof_proofKey_tag            4
#define ContractVarProof_proofVal_tag            5
#define ContractVarProof_bitmap_tag              6
#define ContractVarProof_height_tag              7
#define ContractVarProof_auditPath_tag           8
#define ContractVarProof_key_tag                 9
#define Event_contractAddress_tag                1
#define Event_eventName_tag                      2
#define Event_jsonArgs_tag                       3
#define Event_eventIdx_tag                       4
#define Event_txHash_tag                         5
#define Event_blockHash_tag                      6
#define Event_blockNo_tag                        7
#define Event_txIndex_tag                        8
#define FilterInfo_contractAddress_tag           1
#define FilterInfo_eventName_tag                 2
#define FilterInfo_blockfrom_tag                 3
#define FilterInfo_blockto_tag                   4
#define FilterInfo_desc_tag                      5
#define FilterInfo_argFilter_tag                 6
#define FilterInfo_recentBlockCnt_tag            7
#define Function_name_tag                        1
#define Function_arguments_tag                   2
#define Function_payable_tag                     3
#define Function_view_tag                        4
#define Receipt_contractAddress_tag              1
#define Receipt_status_tag                       2
#define Receipt_ret_tag                          3
#define Receipt_txHash_tag                       4
#define Receipt_feeUsed_tag                      5
#define Receipt_cumulativeFeeUsed_tag            6
#define Receipt_bloom_tag                        7
#define Receipt_events_tag                       8
#define Receipt_blockNo_tag                      9
#define Receipt_blockHash_tag                    10
#define Receipt_txIndex_tag                      11
#define Receipt_from_tag                         12
#define Receipt_to_tag                           13
#define State_nonce_tag                          1
#define State_balance_tag                        2
#define State_codeHash_tag                       3
#define State_storageRoot_tag                    4
#define State_sqlRecoveryPoint_tag               5
#define StateQuery_contractAddress_tag           1
#define StateQuery_root_tag                      3
#define StateQuery_compressed_tag                4
#define StateQuery_storageKeys_tag               5
#define StateVar_name_tag                        1
#define StateVar_type_tag                        2
#define StateVar_len_tag                         3
#define TxBody_nonce_tag                         1
#define TxBody_account_tag                       2
#define TxBody_recipient_tag                     3
#define TxBody_amount_tag                        4
#define TxBody_payload_tag                       5
#define TxBody_gasLimit_tag                      6
#define TxBody_gasPrice_tag                      7
#define TxBody_type_tag                          8
#define TxBody_chainIdHash_tag                   9
#define TxBody_sign_tag                          10
#define TxIdx_blockHash_tag                      1
#define TxIdx_idx_tag                            2
#define AccountProof_state_tag                   1
#define AccountProof_inclusion_tag               2
#define AccountProof_key_tag                     3
#define AccountProof_proofKey_tag                4
#define AccountProof_proofVal_tag                5
#define AccountProof_bitmap_tag                  6
#define AccountProof_height_tag                  7
#define AccountProof_auditPath_tag               8
#define Block_hash_tag                           1
#define Block_header_tag                         2
#define Block_body_tag                           3
#define BlockMetadata_hash_tag                   1
#define BlockMetadata_header_tag                 2
#define BlockMetadata_txcount_tag                3
#define BlockMetadata_size_tag                   4
#define Tx_hash_tag                              1
#define Tx_body_tag                              2
#define StateQueryProof_contractProof_tag        1
#define StateQueryProof_varProofs_tag            2
#define TxInBlock_txIdx_tag                      1
#define TxInBlock_tx_tag                         2

/* Struct field encoding specification for nanopb */
extern const pb_field_t Empty_fields[1];
extern const pb_field_t SingleBytes_fields[2];
extern const pb_field_t BlockchainStatus_fields[5];
extern const pb_field_t AccountAddress_fields[2];
extern const pb_field_t AccountAndRoot_fields[4];
extern const pb_field_t BlockMetadata_fields[5];
extern const pb_field_t Block_fields[4];
extern const pb_field_t BlockHeader_fields[12];
extern const pb_field_t BlockBody_fields[2];
extern const pb_field_t TxList_fields[2];
extern const pb_field_t Tx_fields[3];
extern const pb_field_t TxBody_fields[11];
extern const pb_field_t TxIdx_fields[3];
extern const pb_field_t TxInBlock_fields[3];
extern const pb_field_t State_fields[6];
extern const pb_field_t AccountProof_fields[9];
extern const pb_field_t ContractVarProof_fields[9];
extern const pb_field_t StateQueryProof_fields[3];
extern const pb_field_t Receipt_fields[14];
extern const pb_field_t Event_fields[9];
extern const pb_field_t FnArgument_fields[2];
extern const pb_field_t Function_fields[5];
extern const pb_field_t StateVar_fields[4];
extern const pb_field_t ABI_fields[5];
extern const pb_field_t Query_fields[3];
extern const pb_field_t StateQuery_fields[5];
extern const pb_field_t FilterInfo_fields[8];
extern const pb_field_t CommitResult_fields[4];
extern const pb_field_t CommitResultList_fields[2];

/* Maximum encoded size of messages (where known) */
#define Empty_size                               0
/* SingleBytes_size depends on runtime parameters */
/* BlockchainStatus_size depends on runtime parameters */
/* AccountAddress_size depends on runtime parameters */
/* AccountAndRoot_size depends on runtime parameters */
/* BlockMetadata_size depends on runtime parameters */
/* Block_size depends on runtime parameters */
/* BlockHeader_size depends on runtime parameters */
/* BlockBody_size depends on runtime parameters */
/* TxList_size depends on runtime parameters */
/* Tx_size depends on runtime parameters */
/* TxBody_size depends on runtime parameters */
/* TxIdx_size depends on runtime parameters */
/* TxInBlock_size depends on runtime parameters */
/* State_size depends on runtime parameters */
/* AccountProof_size depends on runtime parameters */
/* ContractVarProof_size depends on runtime parameters */
/* StateQueryProof_size depends on runtime parameters */
/* Receipt_size depends on runtime parameters */
/* Event_size depends on runtime parameters */
/* FnArgument_size depends on runtime parameters */
/* Function_size depends on runtime parameters */
/* StateVar_size depends on runtime parameters */
/* ABI_size depends on runtime parameters */
/* Query_size depends on runtime parameters */
/* StateQuery_size depends on runtime parameters */
/* FilterInfo_size depends on runtime parameters */
/* CommitResult_size depends on runtime parameters */
/* CommitResultList_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define BLOCKCHAIN_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
