<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Gerror;

final class GerrorTest extends TestCase
{
    public function testErrorCreatedTwo(): void
    {
        $this->assertInstanceOf(
            Gerror::class,
            new Gerror(100, "aaa")
        );
    }

    public function testErrorCreatedOne(): void
    {
        $this->assertInstanceOf(
            Gerror::class,
            new Gerror(1000)
        );
    }

    public function testErrorAsTwo(): void
    {
        $g = new Gerror(100, "aaa");
        $this->assertEquals(
            100,
            $g->error_code
        );
        $this->assertEquals(
            "aaa",
            $g->error_string
        );
    }

    public function testErrorAsOne(): void
    {
        $g = new Gerror(1000);
        $this->assertEquals(
            1000,
            $g->error_code
        );
        $this->assertEquals(
            "Application error.",
            $g->error_string
        );
    }

    public function testErrorAsOneMissing(): void
    {
        $g = new Gerror(999);
        $this->assertEquals(
            999,
            $g->error_code
        );
        $this->assertEquals(
            "999",
            $g->error_string
        );
    }
}
