<?php

declare(strict_types=1);

namespace Reynevan\Web3;

use InvalidArgumentException;
use kornrunner\Keccak;

final class Eip1559TransactionDecoder
{
    private const SECP256K1_N =
        'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';

    private const SECP256K1_HALF_N =
        '7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0';


    public function decode(string $rawTransaction): array
    {
        $hex = $this->stripHexPrefix($rawTransaction);

        if ($hex === '') {
            throw new InvalidArgumentException('Empty raw transaction');
        }

        if (!ctype_xdigit($hex)) {
            throw new InvalidArgumentException(
                'Raw transaction contains non-hexadecimal characters'
            );
        }

        if (strlen($hex) % 2 !== 0) {
            throw new InvalidArgumentException(
                'Raw transaction must contain an even number of hex characters'
            );
        }

        $raw = hex2bin($hex);

        if ($raw === false || $raw === '') {
            throw new InvalidArgumentException('Cannot decode raw transaction');
        }

        if (ord($raw[0]) !== 0x02) {
            throw new InvalidArgumentException(
                'Unsupported transaction type; expected EIP-1559 type 0x02'
            );
        }

        $rlpPayload = substr($raw, 1);
        $offset = 0;

        $fields = $this->decodeRlpItem($rlpPayload, $offset);

        if ($offset !== strlen($rlpPayload)) {
            throw new InvalidArgumentException(
                'Unexpected bytes after the RLP transaction'
            );
        }

        if (!is_array($fields) || count($fields) !== 12) {
            throw new InvalidArgumentException(
                'EIP-1559 signed transaction must contain exactly 12 fields'
            );
        }

        if ($this->encodeRlp($fields) !== $rlpPayload) {
            throw new InvalidArgumentException(
                'Transaction uses non-canonical RLP encoding'
            );
        }

        [
            $chainId,
            $nonce,
            $maxPriorityFeePerGas,
            $maxFeePerGas,
            $gasLimit,
            $destination,
            $amount,
            $data,
            $accessList,
            $yParity,
            $r,
            $s,
        ] = $fields;

        foreach ([
                     'chainId' => $chainId,
                     'nonce' => $nonce,
                     'maxPriorityFeePerGas' => $maxPriorityFeePerGas,
                     'maxFeePerGas' => $maxFeePerGas,
                     'gasLimit' => $gasLimit,
                     'amount' => $amount,
                     'yParity' => $yParity,
                     'r' => $r,
                     's' => $s,
                 ] as $fieldName => $value) {
            $this->assertRlpInteger($value, $fieldName);
        }

        if (!is_string($destination)) {
            throw new InvalidArgumentException('Invalid destination field');
        }

        if (strlen($destination) !== 0 && strlen($destination) !== 20) {
            throw new InvalidArgumentException(
                'Destination must be empty or exactly 20 bytes'
            );
        }

        if (!is_string($data)) {
            throw new InvalidArgumentException('Invalid transaction data');
        }

        $this->validateAccessList($accessList);

        $yParityInt = $this->quantityToInt($yParity, 'yParity');

        if ($yParityInt !== 0 && $yParityInt !== 1) {
            throw new InvalidArgumentException(
                'EIP-1559 yParity must equal 0 or 1'
            );
        }

        $this->validateSignatureValues($r, $s);


        $unsignedFields = array_slice($fields, 0, 9);

        $signingPayload = "\x02" . $this->encodeRlp($unsignedFields);
        $signingHash = Keccak::hash($signingPayload, 256);

        $rHex = bin2hex($r);
        $sHex = bin2hex($s);
        $yParityHex = bin2hex($yParity);
        $from = Secp256k1::recoverAddress($signingHash, $rHex, $sHex, self::hexToInt($yParityHex));

        if (!is_string($from) || !preg_match('/^0x[0-9a-fA-F]{40}$/', $from)) {
            throw new InvalidArgumentException(
                'Cannot recover sender address from transaction signature'
            );
        }

        $transactionHash = '0x' . Keccak::hash($raw, 256);

        return [
            'type' => '0x2',
            'hash' => strtolower($transactionHash),
            'from' => strtolower($from),

            'chainId' => $this->quantityToHex($chainId),
            'nonce' => $this->quantityToHex($nonce),

            'maxPriorityFeePerGas' =>
                $this->quantityToHex($maxPriorityFeePerGas),

            'maxFeePerGas' =>
                $this->quantityToHex($maxFeePerGas),

            'gas' => $this->quantityToHex($gasLimit),

            'to' => $destination === ''
                ? null
                : '0x' . bin2hex($destination),

            'value' => $this->quantityToHex($amount),
            'input' => '0x' . bin2hex($data),

            'accessList' => $this->formatAccessList($accessList),

            'yParity' => '0x' . dechex($yParityInt),
            'r' => '0x' . $this->leftPadTo32Bytes($r, 'r'),
            's' => '0x' . $this->leftPadTo32Bytes($s, 's'),

            'signingHash' => '0x' . $signingHash,
            'raw' => '0x' . $hex,
        ];
    }

    private function stripHexPrefix(string $value): string
    {
        $value = trim($value);

        if (str_starts_with($value, '0x') || str_starts_with($value, '0X')) {
            return substr($value, 2);
        }

        return $value;
    }


    private function decodeRlpItem(string $input, int &$offset): string|array
    {
        $inputLength = strlen($input);

        if ($offset >= $inputLength) {
            throw new InvalidArgumentException('Unexpected end of RLP data');
        }

        $prefix = ord($input[$offset]);

        if ($prefix <= 0x7f) {
            $offset++;

            return chr($prefix);
        }

        if ($prefix <= 0xb7) {
            $length = $prefix - 0x80;
            $offset++;

            $this->assertAvailable($input, $offset, $length);

            $value = substr($input, $offset, $length);
            $offset += $length;

            if ($length === 1 && ord($value[0]) <= 0x7f) {
                throw new InvalidArgumentException(
                    'Non-canonical RLP string encoding'
                );
            }

            return $value;
        }

        if ($prefix <= 0xbf) {
            $lengthOfLength = $prefix - 0xb7;
            $offset++;

            $length = $this->readRlpLength(
                $input,
                $offset,
                $lengthOfLength
            );

            if ($length < 56) {
                throw new InvalidArgumentException(
                    'Non-canonical long RLP string'
                );
            }

            $this->assertAvailable($input, $offset, $length);

            $value = substr($input, $offset, $length);
            $offset += $length;

            return $value;
        }

        if ($prefix <= 0xf7) {
            $length = $prefix - 0xc0;
            $offset++;

            return $this->decodeRlpList($input, $offset, $length);
        }

        $lengthOfLength = $prefix - 0xf7;
        $offset++;

        $length = $this->readRlpLength(
            $input,
            $offset,
            $lengthOfLength
        );

        if ($length < 56) {
            throw new InvalidArgumentException(
                'Non-canonical long RLP list'
            );
        }

        return $this->decodeRlpList($input, $offset, $length);
    }

    private function decodeRlpList(
        string $input,
        int &$offset,
        int $payloadLength
    ): array {
        $this->assertAvailable($input, $offset, $payloadLength);

        $end = $offset + $payloadLength;
        $result = [];

        while ($offset < $end) {
            $result[] = $this->decodeRlpItem($input, $offset);

            if ($offset > $end) {
                throw new InvalidArgumentException(
                    'RLP element exceeds list boundary'
                );
            }
        }

        if ($offset !== $end) {
            throw new InvalidArgumentException('Invalid RLP list length');
        }

        return $result;
    }

    private function readRlpLength(
        string $input,
        int &$offset,
        int $lengthOfLength
    ): int {
        if ($lengthOfLength < 1) {
            throw new InvalidArgumentException('Invalid RLP length');
        }

        if ($lengthOfLength > 8) {
            throw new InvalidArgumentException('RLP item is too large');
        }

        $this->assertAvailable($input, $offset, $lengthOfLength);

        $lengthBytes = substr($input, $offset, $lengthOfLength);
        $offset += $lengthOfLength;

        if ($lengthBytes[0] === "\x00") {
            throw new InvalidArgumentException(
                'RLP length contains a leading zero'
            );
        }

        $length = 0;

        for ($i = 0; $i < $lengthOfLength; $i++) {
            if ($length > intdiv(PHP_INT_MAX - ord($lengthBytes[$i]), 256)) {
                throw new InvalidArgumentException(
                    'RLP length exceeds PHP integer range'
                );
            }

            $length = ($length * 256) + ord($lengthBytes[$i]);
        }

        return $length;
    }

    private function assertAvailable(
        string $input,
        int $offset,
        int $requiredLength
    ): void {
        if (
            $requiredLength < 0
            || $offset < 0
            || $requiredLength > strlen($input) - $offset
        ) {
            throw new InvalidArgumentException('Truncated RLP data');
        }
    }

    private function encodeRlp(string|array $value): string
    {
        if (is_array($value)) {
            $payload = '';

            foreach ($value as $item) {
                if (!is_string($item) && !is_array($item)) {
                    throw new InvalidArgumentException(
                        'RLP value must be a string or list'
                    );
                }

                $payload .= $this->encodeRlp($item);
            }

            return $this->encodeRlpLength(strlen($payload), 0xc0, 0xf7)
                . $payload;
        }

        $length = strlen($value);

        if ($length === 1 && ord($value[0]) <= 0x7f) {
            return $value;
        }

        return $this->encodeRlpLength($length, 0x80, 0xb7) . $value;
    }

    private function encodeRlpLength(
        int $length,
        int $shortOffset,
        int $longOffset
    ): string {
        if ($length <= 55) {
            return chr($shortOffset + $length);
        }

        $encodedLength = $this->integerToBinary($length);

        return chr($longOffset + strlen($encodedLength))
            . $encodedLength;
    }

    private function integerToBinary(int $value): string
    {
        if ($value < 0) {
            throw new InvalidArgumentException('Negative RLP length');
        }

        if ($value === 0) {
            return "\x00";
        }

        $result = '';

        while ($value > 0) {
            $result = chr($value & 0xff) . $result;
            $value = intdiv($value, 256);
        }

        return $result;
    }

    private function assertRlpInteger(
        mixed $value,
        string $fieldName
    ): void {
        if (!is_string($value)) {
            throw new InvalidArgumentException(
                "{$fieldName} must be an RLP byte string"
            );
        }

        if ($value !== '' && $value[0] === "\x00") {
            throw new InvalidArgumentException(
                "{$fieldName} contains a leading zero"
            );
        }
    }

    private function quantityToInt(
        string $value,
        string $fieldName
    ): int {
        $number = $this->binaryToGmp($value);

        if (gmp_cmp($number, PHP_INT_MAX) > 0) {
            throw new InvalidArgumentException(
                "{$fieldName} exceeds PHP integer range"
            );
        }

        return gmp_intval($number);
    }

    private function quantityToHex(string $value): string
    {
        if ($value === '') {
            return '0x0';
        }

        $hex = ltrim(bin2hex($value), '0');

        return '0x' . ($hex === '' ? '0' : $hex);
    }

    private function binaryToGmp(string $value): \GMP
    {
        if ($value === '') {
            return gmp_init(0, 10);
        }

        return gmp_init(bin2hex($value), 16);
    }

    private function leftPadTo32Bytes(
        string $value,
        string $fieldName
    ): string {
        $hex = bin2hex($value);

        if (strlen($hex) > 64) {
            throw new InvalidArgumentException(
                "{$fieldName} is longer than 32 bytes"
            );
        }

        return str_pad($hex, 64, '0', STR_PAD_LEFT);
    }

    private function validateSignatureValues(string $r, string $s): void
    {
        $rNumber = $this->binaryToGmp($r);
        $sNumber = $this->binaryToGmp($s);

        $curveOrder = gmp_init(self::SECP256K1_N, 16);
        $halfCurveOrder = gmp_init(self::SECP256K1_HALF_N, 16);

        if (
            gmp_cmp($rNumber, 0) <= 0
            || gmp_cmp($rNumber, $curveOrder) >= 0
        ) {
            throw new InvalidArgumentException(
                'Signature r must satisfy 0 < r < secp256k1n'
            );
        }

        if (
            gmp_cmp($sNumber, 0) <= 0
            || gmp_cmp($sNumber, $curveOrder) >= 0
        ) {
            throw new InvalidArgumentException(
                'Signature s must satisfy 0 < s < secp256k1n'
            );
        }

        if (gmp_cmp($sNumber, $halfCurveOrder) > 0) {
            throw new InvalidArgumentException(
                'Signature s is not canonical: high-s signature'
            );
        }
    }

    private function validateAccessList(mixed $accessList): void
    {
        if (!is_array($accessList)) {
            throw new InvalidArgumentException(
                'EIP-1559 accessList must be an RLP list'
            );
        }

        foreach ($accessList as $entry) {
            if (!is_array($entry) || count($entry) !== 2) {
                throw new InvalidArgumentException(
                    'Each accessList entry must contain address and storage keys'
                );
            }

            [$address, $storageKeys] = $entry;

            if (!is_string($address) || strlen($address) !== 20) {
                throw new InvalidArgumentException(
                    'Access-list address must contain exactly 20 bytes'
                );
            }

            if (!is_array($storageKeys)) {
                throw new InvalidArgumentException(
                    'Access-list storage keys must be a list'
                );
            }

            foreach ($storageKeys as $storageKey) {
                if (!is_string($storageKey) || strlen($storageKey) !== 32) {
                    throw new InvalidArgumentException(
                        'Access-list storage key must contain exactly 32 bytes'
                    );
                }
            }
        }
    }

    private function formatAccessList(array $accessList): array
    {
        return array_map(
            static function (array $entry): array {
                [$address, $storageKeys] = $entry;

                return [
                    'address' => '0x' . bin2hex($address),
                    'storageKeys' => array_map(
                        static fn(string $key): string => '0x' . bin2hex($key),
                        $storageKeys
                    ),
                ];
            },
            $accessList
        );
    }

    private static function hexToInt(string $hex): int
    {
        if ($hex === '' || $hex === '0x') {
            return 0;
        }

        $hex = str_starts_with($hex, '0x') ? substr($hex, 2) : $hex;

        return (int) gmp_strval(gmp_init($hex, 16), 10);
    }
}