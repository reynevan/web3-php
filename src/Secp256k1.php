<?php

declare(strict_types=1);

namespace Reynevan\Web3;

use InvalidArgumentException;
use kornrunner\Keccak;


final class Secp256k1
{
    private const P  = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F';
    private const N  = '0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141';
    private const GX = '0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
    private const GY = '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';

    public static function recoverAddress(string $hashHex, string $rHex, string $sHex, int $recoveryId): string
    {
        $point = self::recoverPublicKey($hashHex, $rHex, $sHex, $recoveryId);

        $xBin = self::gmpToBin($point['x'], 32);
        $yBin = self::gmpToBin($point['y'], 32);
        $pubKeyBin = $xBin . $yBin;

        $hash = Keccak::hash($pubKeyBin, 256);

        return '0x' . substr($hash, -40);
    }


    public static function recoverPublicKey(string $hashHex, string $rHex, string $sHex, int $recoveryId): array
    {
        if ($recoveryId !== 0 && $recoveryId !== 1) {
            throw new InvalidArgumentException("recoveryId must be 0 or 1, got: {$recoveryId}");
        }

        $p = gmp_init(self::P);
        $n = gmp_init(self::N);

        $z = self::hexToGmp($hashHex);
        $r = self::hexToGmp($rHex);
        $s = self::hexToGmp($sHex);

        if (gmp_cmp($r, 0) <= 0 || gmp_cmp($r, $n) >= 0) {
            throw new InvalidArgumentException('Invalid signature value r.');
        }
        if (gmp_cmp($s, 0) <= 0 || gmp_cmp($s, $n) >= 0) {
            throw new InvalidArgumentException('Invalid signature value s.');
        }

        $x = $r;
        $y = self::recoverYCoordinate($x, $recoveryId, $p);
        $R = ['x' => $x, 'y' => $y];

        $rInv = gmp_invert($r, $n);

        $u1 = gmp_mod(gmp_mul(gmp_mod(gmp_neg($z), $n), $rInv), $n);
        $u2 = gmp_mod(gmp_mul($s, $rInv), $n);

        $G = ['x' => gmp_init(self::GX), 'y' => gmp_init(self::GY)];

        $u1G = self::scalarMult($u1, $G, $p);
        $u2R = self::scalarMult($u2, $R, $p);

        $Q = self::pointAdd($u1G, $u2R, $p);

        if ($Q === null) {
            throw new InvalidArgumentException('Recovered public key point is the point at infinity — invalid signature.');
        }

        return $Q;
    }

    private static function hexToGmp(string $hex): \GMP
    {
        $hex = self::stripHexPrefix($hex);

        if ($hex === '') {
            throw new InvalidArgumentException('An empty hex string was provided.');
        }

        if (!ctype_xdigit($hex)) {
            throw new InvalidArgumentException("Invalid hex string: '{$hex}'");
        }

        return gmp_init($hex, 16);
    }

    private static function stripHexPrefix(string $hex): string
    {
        $hex = trim($hex);

        return str_starts_with($hex, '0x') || str_starts_with($hex, '0X')
            ? substr($hex, 2)
            : $hex;
    }


    private static function recoverYCoordinate(\GMP $x, int $recoveryId, \GMP $p): \GMP
    {
        $ySquared = gmp_mod(
            gmp_add(gmp_powm($x, gmp_init(3), $p), gmp_init(7)),
            $p
        );

        $exp = gmp_div_q(gmp_add($p, gmp_init(1)), gmp_init(4));
        $y = gmp_powm($ySquared, $exp, $p);

        if (gmp_cmp(gmp_powm($y, gmp_init(2), $p), $ySquared) !== 0) {
            throw new InvalidArgumentException('Point r does not lie on the secp256k1 curve — invalid signature.');
        }

        $yIsOdd = gmp_intval(gmp_mod($y, gmp_init(2))) === 1;
        $wantOdd = ($recoveryId & 1) === 1;

        if ($yIsOdd !== $wantOdd) {
            $y = gmp_sub($p, $y);
        }

        return $y;
    }

    private static function pointAdd(?array $p1, ?array $p2, \GMP $p): ?array
    {
        if ($p1 === null) {
            return $p2;
        }
        if ($p2 === null) {
            return $p1;
        }

        if (gmp_cmp($p1['x'], $p2['x']) === 0) {
            if (gmp_cmp($p1['y'], $p2['y']) !== 0) {
                return null;
            }
            return self::pointDouble($p1, $p);
        }

        $slope = gmp_mod(
            gmp_mul(
                gmp_sub($p2['y'], $p1['y']),
                gmp_invert(gmp_mod(gmp_sub($p2['x'], $p1['x']), $p), $p)
            ),
            $p
        );

        $x3 = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $p1['x']), $p2['x']), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($p1['x'], $x3)), $p1['y']), $p);

        return ['x' => $x3, 'y' => $y3];
    }

    private static function pointDouble(array $point, \GMP $p): ?array
    {
        if (gmp_cmp($point['y'], 0) === 0) {
            return null;
        }

        $numerator = gmp_mul(gmp_init(3), gmp_pow($point['x'], 2));
        $denominator = gmp_invert(gmp_mod(gmp_mul(gmp_init(2), $point['y']), $p), $p);
        $slope = gmp_mod(gmp_mul($numerator, $denominator), $p);

        $x3 = gmp_mod(gmp_sub(gmp_pow($slope, 2), gmp_mul(gmp_init(2), $point['x'])), $p);
        $y3 = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($point['x'], $x3)), $point['y']), $p);

        return ['x' => $x3, 'y' => $y3];
    }

    private static function scalarMult(\GMP $k, array $point, \GMP $p): ?array
    {
        $result = null;
        $addend = $point;

        $binary = gmp_strval($k, 2);

        for ($i = strlen($binary) - 1; $i >= 0; $i--) {
            if ($binary[$i] === '1') {
                $result = self::pointAdd($result, $addend, $p);
            }
            $addend = self::pointDouble($addend, $p);

            if ($addend === null && $i > 0) {
                break;
            }
        }

        return $result;
    }

    private static function gmpToBin(\GMP $num, int $length): string
    {
        $hex = gmp_strval($num, 16);
        $hex = str_pad($hex, $length * 2, '0', STR_PAD_LEFT);

        return hex2bin($hex);
    }
}