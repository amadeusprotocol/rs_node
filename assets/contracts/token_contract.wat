;; Simple Token Contract - ERC-20 style functionality
;; Demonstrates coin operations and cross-contract calls

(module
  ;; Import host functions
  (import "bic" "storage_kv_get" (func $storage_kv_get (param i32 i32) (result i32 i32)))
  (import "bic" "storage_kv_put" (func $storage_kv_put (param i32 i32 i32 i32) (result i32)))
  (import "bic" "storage_kv_increment" (func $storage_kv_increment (param i32 i32 i64) (result i64)))
  (import "bic" "coin_get_balance" (func $coin_get_balance (param i32 i32 i32 i32) (result i64)))
  (import "env" "env_get_tx_signer" (func $env_get_tx_signer (param i32) (result i32)))
  (import "env" "log_info" (func $log_info (param i32 i32)))
  (import "env" "system_return" (func $system_return (param i32 i32)))

  ;; Memory for data storage
  (memory 1)
  (export "memory" (memory 0))

  ;; Constants in memory
  (data (i32.const 0) "total_supply")     ;; key at 0, length 12
  (data (i32.const 16) "balance:")        ;; prefix at 16, length 8
  (data (i32.const 32) "MYTOKEN")         ;; token symbol at 32, length 7
  (data (i32.const 48) "Token operation successful") ;; log message at 48, length 26

  ;; Initialize token contract
  (func $init (export "init") (param $initial_supply i64)
    (local $supply_str_len i32)
    
    ;; Convert initial supply to string (simplified)
    i32.const 200  ;; buffer for supply string
    local.get $initial_supply
    call $i64_to_string
    local.set $supply_str_len
    
    ;; Set total supply
    i32.const 0     ;; "total_supply" key
    i32.const 12    ;; key length
    i32.const 200   ;; supply string
    local.get $supply_str_len
    call $storage_kv_put
    drop
    
    ;; Log initialization
    i32.const 48    ;; log message
    i32.const 26    ;; message length
    call $log_info
  )

  ;; Get balance of an account
  (func $balance_of (export "balance_of") (param $account_ptr i32) (param $account_len i32) (result i64)
    ;; Build balance key: "balance:" + account
    i32.const 100   ;; buffer for balance key
    i32.const 16    ;; "balance:" prefix
    i32.const 8     ;; prefix length
    call $memcpy    ;; copy prefix to buffer
    
    i32.const 108   ;; buffer + prefix length
    local.get $account_ptr
    local.get $account_len
    call $memcpy    ;; append account to key
    
    ;; Get balance from storage (simplified)
    i32.const 100   ;; balance key
    i32.const 8     ;; key length (simplified)
    local.get $account_len
    i32.add         ;; total key length
    call $storage_kv_get
    drop
    drop
    
    ;; Return placeholder balance
    i64.const 1000
  )

  ;; Transfer tokens between accounts
  (func $transfer (export "transfer") (param $to_ptr i32) (param $to_len i32) (param $amount i64) (result i32)
    (local $from_key_len i32)
    (local $to_key_len i32)
    
    ;; Get transaction signer (from address)
    i32.const 300   ;; buffer for signer
    call $env_get_tx_signer
    drop            ;; ignore length for now
    
    ;; Build from balance key
    i32.const 400   ;; from balance key buffer
    i32.const 16    ;; "balance:" prefix
    i32.const 8     ;; prefix length
    call $memcpy
    
    i32.const 408   ;; append signer address (simplified)
    i32.const 300   ;; signer buffer
    i32.const 48    ;; BLS key length
    call $memcpy
    
    ;; Build to balance key  
    i32.const 500   ;; to balance key buffer
    i32.const 16    ;; "balance:" prefix
    i32.const 8     ;; prefix length
    call $memcpy
    
    i32.const 508   ;; append to address
    local.get $to_ptr
    local.get $to_len
    call $memcpy
    
    ;; Decrement from balance
    i32.const 400   ;; from key
    i32.const 56    ;; from key length (8 + 48)
    local.get $amount
    i64.const -1
    i64.mul         ;; negate amount
    call $storage_kv_increment
    drop
    
    ;; Increment to balance
    i32.const 500   ;; to key
    i32.const 8     ;; to key length
    local.get $to_len
    i32.add         ;; total key length
    local.get $amount
    call $storage_kv_increment
    drop
    
    ;; Return success
    i32.const 1
  )

  ;; Get total token supply
  (func $total_supply (export "total_supply") (result i64)
    ;; Get total supply from storage
    i32.const 0     ;; "total_supply" key
    i32.const 12    ;; key length
    call $storage_kv_get
    drop
    drop
    
    ;; Return placeholder supply
    i64.const 1000000
  )

  ;; Helper function: copy memory
  (func $memcpy (param $dest i32) (param $src i32) (param $len i32)
    (local $i i32)
    i32.const 0
    local.set $i
    
    (loop $copy_loop
      local.get $i
      local.get $len
      i32.lt_u
      (if
        (then
          local.get $dest
          local.get $i
          i32.add
          local.get $src
          local.get $i
          i32.add
          i32.load8_u
          i32.store8
          
          local.get $i
          i32.const 1
          i32.add
          local.set $i
          br $copy_loop
        )
      )
    )
  )

  ;; Helper function: convert i64 to string (simplified)
  (func $i64_to_string (param $buffer i32) (param $value i64) (result i32)
    ;; Simplified: just store "1000000"
    local.get $buffer
    i32.const 49  ;; '1'
    i32.store8
    
    local.get $buffer
    i32.const 1
    i32.add
    i32.const 48  ;; '0'
    i32.store8
    
    ;; ... continue for other digits (simplified implementation)
    
    ;; Return length
    i32.const 7
  )
)