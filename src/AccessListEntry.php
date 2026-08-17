<?php

declare(strict_types=1);

namespace Reynevan\Web3;

final readonly class AccessListEntry
{
    /**
     * @param string[] $storageKeys
     */
    public function __construct(
        public string $address,
        public array $storageKeys,
    ) {
    }
}
