<?php

declare(strict_types=1);

namespace Tests;

use InvalidArgumentException;
use Reynevan\Web3\Eip1559TransactionDecoder;
use PHPUnit\Framework\TestCase;

final class Eip1559TransactionDecoderTest extends TestCase
{
    private const VALID_RAW_TRANSACTION = '0x02f87382053980843b9aca008477359400825208941111111111111111111111111111111111111111872386f26fc1000080c001a04e811a9d1a526bcfb808dfbe9f4d287175399cf0078865e16205c593d14b8fa8a0578959440e638ed98f6f4aaefd23536b25a091fffcbae55c9a239dbdf74ba672';

    public function testDecodesValidTransaction(): void
    {
        $decoder = new Eip1559TransactionDecoder();

        $result = $decoder->decode(self::VALID_RAW_TRANSACTION);

        $this->assertSame('0x2', $result->type);
        $this->assertMatchesRegularExpression('/^0x[0-9a-f]{40}$/', $result->from);
        $this->assertSame('0xfe00abd4079a8c1692f258a1ecfc7c60a4497ecd', $result->from);
        $this->assertSame(
            '0x3fcb84218659810319cceef5d58073b8aba97948646c7e52dadd5a41cc918035',
            $result->hash
        );
        $this->assertSame('0x539', $result->chainId);
        $this->assertSame('0x0', $result->nonce);
        $this->assertSame('0x3b9aca00', $result->maxPriorityFeePerGas);
        $this->assertSame('0x77359400', $result->maxFeePerGas);
        $this->assertSame('0x5208', $result->gas);
        $this->assertSame('0x1111111111111111111111111111111111111111', $result->to);
        $this->assertSame('0x2386f26fc10000', $result->value);
        $this->assertSame('0x', $result->input);
        $this->assertSame([], $result->accessList);
        $this->assertSame('0x1', $result->yParity);
        $this->assertSame(
            '0x4e811a9d1a526bcfb808dfbe9f4d287175399cf0078865e16205c593d14b8fa8',
            $result->r
        );
        $this->assertSame(
            '0x578959440e638ed98f6f4aaefd23536b25a091fffcbae55c9a239dbdf74ba672',
            $result->s
        );
        $this->assertSame(
            '0xf450acd5cfdc33f6d7df043664de6da22a55d58f29be9f01d10b353f045ebf65',
            $result->signingHash
        );
        $this->assertSame(self::VALID_RAW_TRANSACTION, $result->raw);
    }

    public function testThrowsOnEmptyTransaction(): void
    {
        $decoder = new Eip1559TransactionDecoder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Empty raw transaction');

        $decoder->decode('');
    }

    public function testThrowsOnNonHexadecimalCharacters(): void
    {
        $decoder = new Eip1559TransactionDecoder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-hexadecimal characters');

        $decoder->decode('0x02zz');
    }

    public function testThrowsOnOddNumberOfHexCharacters(): void
    {
        $decoder = new Eip1559TransactionDecoder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('even number of hex characters');

        $decoder->decode('0x123');
    }

    public function testThrowsOnUnsupportedTransactionType(): void
    {
        $decoder = new Eip1559TransactionDecoder();

        $wrongType = '0x01' . substr(self::VALID_RAW_TRANSACTION, 4);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('expected EIP-1559 type 0x02');

        $decoder->decode($wrongType);
    }

    public function testThrowsOnTruncatedTransaction(): void
    {
        $decoder = new Eip1559TransactionDecoder();

        $truncated = substr(self::VALID_RAW_TRANSACTION, 0, -4);

        $this->expectException(InvalidArgumentException::class);

        $decoder->decode($truncated);
    }
}
