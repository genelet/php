<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Scoder;

final class ScoderTest extends TestCase
{
    public function testCreatedScoder(): void
    {
        $this->assertInstanceOf(
            Scoder::class,
            new Scoder("../conf/test.confmjsondb")
        );
    }

    public function testScoder(): void
    {
        $crypt = "../conf/test.confmjsondb";
        $plain = "1234567890qwertyuiop[]asdfghjkl;'zxcvbnm,.!@#$%^&*()_+=-";
        $got = Scoder::Encode_scoder($plain, $crypt);
        $this->assertEquals(
            "NwfY6LNVYSHOmOE3S3IHkKLhHR1fpt79YlOMtOwIOiLQ0ugjWGIdhPumUy0n35rQIB/D9dlIazQ=",
            $got
        );
        $rev = Scoder::Decode_scoder($got, $crypt);
        $this->assertEquals(
            $plain,
            $rev
        );
        $got = Scoder::Encode_scoder($crypt, $plain);
        $this->assertEquals(
            "GMj9t2hFnP/mEltuqpREFSnUgdJ5Jd6I",
            $got
        );
        $rev = Scoder::Decode_scoder($got, $plain);
        $this->assertEquals(
            $crypt,
            $rev
        );
    }
}
