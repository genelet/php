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
            new Scoder("conf/test.confmjsondb")
        );
    }

    public function testScoder(): void
    {
        $crypt = "conf/test.confmjsondb";
        $plain = "1234567890qwertyuiop[]asdfghjkl;'zxcvbnm,.!@#$%^&*()_+=-";
        $got = Scoder::Encode_scoder($plain, $crypt);
        $this->assertEquals(
			'jBz5VTKRdMShDa8Uado72u5eqRwO4E+5BWHAK5bzUeVEdtAs1flZq0B7nG7pRSL5ZdawFIFIMYU=',
            $got
        );
        $rev = Scoder::Decode_scoder($got, $crypt);
        $this->assertEquals(
            $plain,
            $rev
        );
        $got = Scoder::Encode_scoder($crypt, $plain);
        $this->assertEquals(
            "VYm8sihfn6PmWUt16pFGETzWhcV0",
            $got
        );
        $rev = Scoder::Decode_scoder($got, $plain);
        $this->assertEquals(
            $crypt,
            $rev
        );
    }
}
