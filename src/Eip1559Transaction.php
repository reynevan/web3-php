<?php

declare(strict_types=1);

namespace Reynevan\Web3;

final class Eip1559Transaction
{
    /**
     * @param AccessListEntry[] $accessList
     */
    public function __construct(
        public string $type,
        public string $hash,
        public string $from,
        public string $chainId,
        public string $nonce,
        public string $maxPriorityFeePerGas,
        public string $maxFeePerGas,
        public string $gas,
        public ?string $to,
        public string $value,
        public string $input,
        public array $accessList,
        public string $yParity,
        public string $r,
        public string $s,
        public string $signingHash,
        public string $raw,
    ) {
    }
}
