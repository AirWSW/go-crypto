# go-crypto

### Usage

- `github.com/AirWSW/go-crypto`: Counter mode (ctrStream) [Documentation](https://pkg.go.dev/github.com/AirWSW/go-crypto)
- `github.com/AirWSW/go-crypto/aes`: Advanced Encryption Standard (aesCipher) [Documentation](https://pkg.go.dev/github.com/AirWSW/go-crypto/aes)
- `github.com/AirWSW/go-crypto/des`: Data Encryption Standard (desCipher, tripleDESCipher) [Documentation](https://pkg.go.dev/github.com/AirWSW/go-crypto/des)

```bash
$ go run .
#  DES CTR 7d2ed15ba0ff5c7f9d0a027bf66413f1ad0dd612e9a3731f712930f200835097caa0aa136bcee3f640f980641c0df56ac98be8924c1dc63151829068fa9d737e
# 3DES CTR 3db2c3199be15c485d3812e95a9b315b48567349a7a0a313a5995bf2279316b79980fa6c3a624d54f54ea29a16c8114c06072aab63bbdfccec595031192e9b7c
#  AES CTR 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee
```

You can also using your own `key`, `iv`, and `plain/encrypted` by replacing the function inputs to get `encrypted/plain` outputs in CTR mode with a certain encrypt algorithm.

### Unit tests

```bash
$ go test ./...
# ok      github.com/AirWSW/go-crypto     1.107s
# ok      github.com/AirWSW/go-crypto/aes 0.721s
# ok      github.com/AirWSW/go-crypto/des 1.414s
```
