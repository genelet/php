<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Base;

final class BaseTest extends TestCase
{
    public function testCreatedBase(): void
    {
        $this->assertInstanceOf(
            Base::class,
            new Base(json_decode(file_get_contents("conf/test.conf")), "m", "json")
        );
    }

    public function testCreatedBaseMissingProvider(): void
    {
        $this->assertInstanceOf(
            Base::class,
            new Base(json_decode(file_get_contents("conf/test.conf")), "m", "json")
        );
    }

    public function testBaseSimple(): void
    {
        $b = new Base(json_decode(file_get_contents("conf/test.conf")), "m", "json");
        $this->assertEquals(
            "m",
            $b->Role_name
        );
        $this->assertEquals(
            "json",
            $b->Tag_name
        );
    }

    public function testBaseIp(): void
    {
        $base = new Base(json_decode(file_get_contents("conf/test.conf")), "m", "json");
        $_SERVER['HTTP_X_FORWARDED_FOR'] = "1.1.1.1";
        $this->assertEquals(
            "1.1.1.1",
            $base->Get_ip()
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testBaseCookie(): void
    {
        $base = new Base(json_decode(file_get_contents("conf/test.conf")), "m", "json");
        $_SERVER["HTTP_HOST"] = "aaa.bbb.ccc";
        $base->Set_cookie("cname", "1234567", 1000);
        $this->assertEquals(
            false,
            headers_sent()
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testLogout(): void
    {
        $base = new Base(json_decode(file_get_contents("conf/test.conf")), "m", "e");
        $_SERVER["HTTP_HOST"] = "aaa.bbb.ccc";
        $base->Set_cookie("cname", "1234567", 1000);
        $str = $base->Handler_logout();
        $this->assertEquals("/", $str);
    }

}
