<?php
declare (strict_types = 1);

use PHPUnit\Framework\TestCase;
use Genelet\Gate;

final class GateTest extends TestCase
{
    public function testCreatedGate(): void
    {
        $this->assertInstanceOf(
            Gate::class,
            new Gate(json_decode(file_get_contents("../conf/test.conf")), "m", "json")
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testGateForbid(): void
    {
        $gate = new Gate(json_decode(file_get_contents("../conf/test.conf")), "m", "e");
        $_SERVER["REQUEST_TIME"] = "0";
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $fields = array("aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee");
        $s = $gate->Signature($fields);
        $_COOKIE["mc"] = $s;
        $err = $gate->Forbid();
        $this->assertNull($err);

        $_SERVER["REQUEST_URI"] = "/bb/m/e/comp?action=act";
        $_SERVER["HTTP_HOST"] = "aaa.bbb.ccc";
        $_COOKIE["mc"] .= "21";
        $err = $gate->Forbid();
        $this->assertIsObject($err);
        $this->assertEquals(303, $err->error_code);
        $this->assertEquals("/bb/m/e/login?go_uri=%2Fbb%2Fm%2Fe%2Fcomp%3Faction%3Dact&go_err=1025&role=m&tag=e&provider=db", $err->error_string);
    }

    /**
     * @runInSeparateProcess
     */
    public function testGateLogout(): void
    {
        $gate = new Gate(json_decode(file_get_contents("../conf/test.conf")), "m", "e");
        $_SERVER["HTTP_HOST"] = "aaa.bbb.ccc";
        $err = $gate->Handler_logout();
        $this->assertIsObject($err);
        $this->assertEquals(303, $err->error_code);
        $this->assertEquals("/", $err->error_string);
        $gate = new Gate(json_decode(file_get_contents("../conf/test.conf")), "m", "json");
        $err = $gate->Handler_logout();
        $this->assertIsObject($err);
        $this->assertEquals(200, $err->error_code);
        $this->assertEquals("logout", $err->error_string);
    }

    /**
     * @runInSeparateProcess
     */
    public function testGateGetAttributes(): void
    {
        $gate = new Gate(json_decode(file_get_contents("../conf/test.conf")), "m", "e");
        $_SERVER["REQUEST_TIME"] = "0";
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $fields = array("aaaaaemail", 11111, "bbbbbfirst", "ccccclast", "dddddaddr", "eeeeecomp");
        $s = $gate->Signature($fields);
        $_COOKIE["mc"] = $s;
        $ref = array();
        $err = $gate->Get_attributes($ref);
        $this->assertNull($err);
        $this->assertEquals($fields[0], $ref["email"]);
        $this->assertEquals($fields[1], $ref["m_id"]);
        $this->assertEquals($fields[2], $ref["first_name"]);
        $this->assertEquals($fields[3], $ref["last_name"]);
        $this->assertEquals($fields[4], $ref["address"]);
        $this->assertEquals($fields[5], $ref["company"]);
    }
}
