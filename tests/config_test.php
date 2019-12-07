<?php
declare (strict_types = 1);
namespace Genelet;

use PHPUnit\Framework\TestCase;
use Genelet\Config;

final class ConfigTest extends TestCase
{
    public function testCreatedConfig(): void
    {
        $content = file_get_contents("../conf/test.conf");
        $config = json_decode($content);
        $this->assertInstanceOf(
            Config::class,
            new Config(json_decode(file_get_contents("../conf/test.conf")))
        );
    }

    public function testConfig(): void
    {
        $c = new Config(json_decode(file_get_contents("../conf/test.conf")));
        $g = $c->config;
        $this->assertEquals(
            "aa",
            $g->{"Document_root"}
        );
        $this->assertEquals(
            "/bb",
            $g->{"Script"}
        );
        $this->assertEquals(
            "mysql:host=localhost;dbname=test",
            $g->{"Db"}[0]
        );
        $this->assertEquals(
            "application/json; charset=\"UTF-8\"",
            $g->{"Chartags"}->{"json"}->{"Content_type"}
        );
        $this->assertEquals(
            360000,
            $g->{"Roles"}->{"m"}->{"Duration"}
        );
        $this->assertEquals(
            "email",
            $g->{"Roles"}->{"m"}->{"Issuers"}->{"db"}->{"Credential"}[0]
        );
    }
}
