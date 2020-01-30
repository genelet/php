<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Gate;

final class GateTest extends TestCase
{
    public function testCreatedGate(): void
    {
        $this->assertInstanceOf(
            Gate::class,
            new Gate(json_decode(file_get_contents("conf/test.conf")), "m", "json")
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testGateForbid(): void
    {
        $gate = new Gate(json_decode(file_get_contents("conf/test.conf")), "m", "e");
        $_SERVER["REQUEST_TIME"] = "0";
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $fields = array("aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee");
        $s = $gate->Signature($fields);
        $_COOKIE["mc"] = $s;
        $err = $gate->Verify_cookie();
        $this->assertNull($err);

        $_SERVER["REQUEST_URI"] = "/bb/m/e/comp?action=act";
        $_SERVER["HTTP_HOST"] = "aaa.bbb.ccc";
        $_COOKIE["mc"] .= "21";
        $err = $gate->Verify_cookie();
        $this->assertIsObject($err);
		$str = $gate->Forbid();
        $this->assertEquals("/bb/m/e/login?go_uri=%2Fbb%2Fm%2Fe%2Fcomp%3Faction%3Dact&go_err=1025&provider=db", $str);
    }

    /**
     * @runInSeparateProcess
     */
    public function testGateGetAttributes(): void
    {
        $gate = new Gate(json_decode(file_get_contents("conf/test.conf")), "m", "e");
        $_SERVER["REQUEST_TIME"] = "0";
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $fields = array("aaaaaemail", 11111, "bbbbbfirst", "ccccclast", "dddddaddr", "eeeeecomp");
        $s = $gate->Signature($fields);
        $_COOKIE["mc"] = $s;
		$err = $gate->Verify_cookie($s);
        $this->assertNull($err);
        $ref = $gate->Decoded;
        $this->assertEquals($fields[0], $ref["email"]);
        $this->assertEquals($fields[1], $ref["m_id"]);
        $this->assertEquals($fields[2], $ref["first_name"]);
        $this->assertEquals($fields[3], $ref["last_name"]);
        $this->assertEquals($fields[4], $ref["address"]);
        $this->assertEquals($fields[5], $ref["company"]);
    }
}
