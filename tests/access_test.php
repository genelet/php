<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Access;

final class AccessTest extends TestCase
{
    public function testCreatedAccess(): void
    {
        $this->assertInstanceOf(
            Access::class,
            new Access(json_decode(file_get_contents("conf/test.conf")), "m", "json")
        );
    }

	public function testAccessDigest(): void
	{
        $access = new Access(json_decode(file_get_contents("conf/test.conf")), "m", "json");
		$access->Endtime = 88888;
		$stamp = 123456;
		$str = "sdfdsgfsdgd";
		$token = $access->Token($stamp, $str);
		$this->assertEquals($stamp, Access::Get_tokentime($token));
		$stamp = 4294967295;
		$token = $access->Token($stamp, $str);
		$this->assertEquals($stamp, Access::Get_tokentime($token));
	}

    public function testAccessSetip(): void
    {
        $access = new Access(json_decode(file_get_contents("conf/test.conf")), "m", "json");
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $ip = $access->Set_ip();
        $this->assertEquals("192.168.29.30", $ip);
        $access->roles["m"]->length = 6;
        $ip = $access->Set_ip();
        $this->assertEquals("C0A81D", $ip);
    }

    public function testAccessSignature(): void
    {
        $access = new Access(json_decode(file_get_contents("conf/test.conf")), "m", "json");
        $_SERVER["REQUEST_TIME"] = "0";
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $fields = array("aaaaa", "bbbbb", "ccccc", "ddddd", "eeeee");
        $s = $access->Signature($fields);
        $a = $access->Verify_cookie($s);
        $this->assertNull($a);
		$ref = $access->Raw;
        $this->assertEquals("192.168.29.30", $ref[0]);
        $this->assertEquals("aaaaa", $ref[1]);
        $this->assertEquals("bbbbb|ccccc|ddddd|eeeee", $ref[2]);
        $this->assertEquals(360000, $ref[3]);
        $this->assertEquals("kGib0q06IqzY1qSmHALJiIt-m-kRfzmsYSmfEnA3ipE", $ref[4]);
        $_SERVER["REQUEST_TIME"] = "360000";
        $a = $access->Verify_cookie($s);
        $this->assertNull($a);
        $_SERVER["REQUEST_TIME"] = "360001";
        $a = $access->Verify_cookie($s);
        $this->assertIsObject($a);
        $this->assertEquals(1024, $a->error_code);
    }
}
