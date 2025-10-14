;; Simple Counter Contract - WebAssembly Text Format
;; This demonstrates basic storage operations and environment queries

(module
  ;; Import host functions from the BIC runtime
  (import "bic" "storage_kv_get" (func $storage_kv_get (param i32 i32) (result i32 i32)))
  (import "bic" "storage_kv_put" (func $storage_kv_put (param i32 i32 i32 i32) (result i32)))
  (import "bic" "storage_kv_increment" (func $storage_kv_increment (param i32 i32 i64) (result i64)))
  (import "env" "env_get_block_height" (func $env_get_block_height (result i64)))
  (import "env" "log_info" (func $log_info (param i32 i32)))

  ;; Memory for string storage
  (memory 1)
  (export "memory" (memory 0))

  ;; Store constant strings in memory
  (data (i32.const 0) "counter")           ;; key at offset 0, length 7
  (data (i32.const 16) "Counter incremented") ;; log message at offset 16, length 19

  ;; Initialize contract (called once after deployment)
  (func $init (export "init")
    ;; Set initial counter value to 0
    ;; storage_kv_put(key_ptr, key_len, value_ptr, value_len)
    i32.const 0    ;; key pointer ("counter")
    i32.const 7    ;; key length
    i32.const 100  ;; value pointer (will store "0")
    i32.const 1    ;; value length
    
    ;; Store "0" at offset 100
    i32.const 100
    i32.const 48   ;; ASCII '0'
    i32.store8
    
    call $storage_kv_put
    drop           ;; ignore return value
  )

  ;; Increment the counter
  (func $increment (export "increment")
    (local $height i64)
    
    ;; Get current block height for logging
    call $env_get_block_height
    local.set $height
    
    ;; Increment counter using atomic increment
    i32.const 0    ;; key pointer ("counter")
    i32.const 7    ;; key length
    i64.const 1    ;; increment by 1
    call $storage_kv_increment
    drop           ;; ignore return value
    
    ;; Log the increment
    i32.const 16   ;; log message pointer
    i32.const 19   ;; log message length
    call $log_info
  )

  ;; Get current counter value
  (func $get_counter (export "get_counter") (result i32)
    ;; This would typically read from storage and return the value
    ;; For now, return a placeholder
    i32.const 42
  )

  ;; Reset counter to zero
  (func $reset (export "reset")
    ;; Set counter value back to 0
    i32.const 0    ;; key pointer ("counter")
    i32.const 7    ;; key length
    i32.const 100  ;; value pointer
    i32.const 1    ;; value length
    
    ;; Store "0" at offset 100
    i32.const 100
    i32.const 48   ;; ASCII '0'
    i32.store8
    
    call $storage_kv_put
    drop
  )
)