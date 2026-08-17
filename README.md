# web3-php

A lightweight PHP library for working with Ethereum (EVM) transactions. It decodes raw **EIP-1559** transactions (`0x02...`) into a readable object and recovers the sender address (`from`) from the ECDSA signature, without needing to connect to an RPC node.

## Features

- Decoding a raw (RLP) EIP-1559 transaction into an `Eip1559Transaction` object
- Recovering the sender address from the signature (`ecrecover`) using the secp256k1 curve
- `accessList` support (`AccessListEntry`)
- Input validation (throws `InvalidArgumentException` for invalid transactions)

## Requirements

- PHP >= 8.1
- `gmp` extension

## Installation

```bash
composer require reynevan/web3-php
```

## Usage example

```php
use Reynevan\Web3\Eip1559TransactionDecoder;

$decoder = new Eip1559TransactionDecoder();

$transaction = $decoder->decode('0x02f8...');

echo $transaction->from;
echo $transaction->to;
echo $transaction->value;
```

## Tests

```bash
composer install
vendor/bin/phpunit
```

## License

MIT
