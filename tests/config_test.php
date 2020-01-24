<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Config;

final class ConfigTest extends TestCase
{
    public function testCreatedConfig(): void
    {
        $content = file_get_contents("conf/test.conf");
        $config = json_decode($content);
        $this->assertInstanceOf(
            Config::class,
            new Config(json_decode(file_get_contents("conf/test.conf")))
        );
    }

    public function testConfig(): void
    {
        $g = new Config(json_decode(file_get_contents("conf/test.conf")));
        $this->assertEquals(
            "aa",
            $g->document_root
        );
        $this->assertEquals(
            "/bb",
            $g->script
        );
        $this->assertEquals(
            "mysql:host=localhost;dbname=test",
            $g->db[0]
        );
        $this->assertEquals(
            "application/json; charset=\"UTF-8\"",
            $g->chartags["json"]->content_type
        );
        $this->assertEquals(
            360000,
            $g->roles["m"]->duration
        );
		$issuers = $g->roles["m"]->issuers;
        $this->assertEquals(
            "email",
            $issuers["db"]->credential[0]
        );
    }
}
