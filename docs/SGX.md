# SGX Attestation

Remote attestation proves that an Amadeus node is running in a genuine Intel SGX enclave with the expected code and that its public key is bound to that enclave.

## What It Proves

- **Code Integrity**: MRENCLAVE matches the Amadeus binary
- **Platform Trust**: SGX hardware is genuine Intel
- **Key Binding**: Node's public key is cryptographically bound to the enclave

## API

**`GET /api/attestation/quote`**

Returns an SGX DCAP quote with the node's public key hash embedded in the report data.

```bash
curl http://localhost:3000/api/attestation/quote | jq
```

Response:
```json
{
  "quote": "AwACAAAAAAAHAA4Ak5pyM/ECAAAAAAAAAAAA...",
  "attestation_type": "dcap",
  "node_public_key": "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn",
  "pubkey_hash": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
}
```

## Verification

```bash
# Extract and verify quote
curl http://localhost:3000/api/attestation/quote | jq -r '.quote' | base64 -d > quote.bin
gramine-sgx-quote-dump quote.bin

# Verify signature and check:
# 1. MRENCLAVE matches expected value
# 2. Report data first 32 bytes = SHA256(node_public_key)
# 3. TCB status is up-to-date
```

## Deployment

1. **Enable in manifest** (`amadeusd.manifest.template`):
```toml
[sgx]
remote_attestation = "dcap"
```

2. **Build and sign**:
```bash
gramine-manifest amadeusd.manifest.template amadeusd.manifest
gramine-sgx-sign --manifest amadeusd.manifest --output amadeusd.manifest.sgx
```

3. **Get measurements** (save for verification):
```bash
gramine-sgx-sigstruct-view amadeusd.sig
```

4. **Run**:
```bash
gramine-sgx amadeusd
```

## Production

- Run your own PCCS (Provisioning Certificate Caching Service)
- Verify quotes before trusting nodes
- Monitor TCB status for security updates
- Use TLS for encrypted communication (attestation doesn't encrypt)
