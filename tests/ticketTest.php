<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Ticket;

final class TicketTest extends TestCase
{
    public function testCreatedTicket(): void
    {
        $this->assertInstanceOf(
            Ticket::class,
            new Ticket("/bb/m/e/comp?action=act", json_decode(file_get_contents("conf/test.conf")), "m", "json", "db")
        );
    }

    public function testTicketProvider(): void
    {
        $base = new Ticket("/bb/m/e/comp?action=act", json_decode(file_get_contents("conf/test.conf")), "m", "json");
        $this->assertEquals(
            "db",
            $base->Provider
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testTicketAuthenticate(): void
    {

        $ticket = new Ticket("/bb/m/e/comp?action=act", json_decode(file_get_contents("conf/test.conf")), "m", "json", "db");
        $err = $ticket->Authenticate("hello", "world");
        $this->assertNull($err);
        $this->assertEquals("hello", $ticket->Out_hash["login"]);
        $this->assertEquals("db", $ticket->Out_hash["provider"]);
        $err = $ticket->Authenticate("hellx", "world");
        $this->assertIsObject($err);
        $this->assertEquals(1031, $err->error_code);
    }

    /**
     * @runInSeparateProcess
     */
    public function testTicketHandler(): void
    {
        $ticket = new Ticket("/bb/m/e/comp?action=act", json_decode(file_get_contents("conf/test.conf")), "m", "json", "db");
        $_SERVER["REQUEST_URI"] = "/bb/m/e/login?request_uri=xxxx";
        $_SERVER["HTTP_HOST"] = "aaa.bbb.com";
        $err = $ticket->Handler();
        $this->assertIsObject($err);
        $this->assertEquals(1036, $err->error_code);

        $_COOKIE["go_probe"] = "/bb/m/e/comp?action=act";
        $_REQUEST["go_err"] = "1037";
        $_SERVER["REQUEST_METHOD"] = "GET";
        $err = $ticket->Handler();
        $this->assertIsObject($err);
        $this->assertEquals($_COOKIE["go_probe"], $ticket->Uri);
        $this->assertEquals(1037, $err->error_code);

        unset($_REQUEST["go_err"]);
        $err = $ticket->Handler();
        $this->assertIsObject($err);
        $this->assertEquals(1026, $err->error_code);

        $_REQUEST["email"] = "hello";
        $err = $ticket->Handler();
        $this->assertIsObject($err);
        $this->assertEquals(1031, $err->error_code);

        $_REQUEST["passwd"] = "xxxxx";
        $err = $ticket->Handler();
        $this->assertIsObject($err);
        $this->assertEquals(1031, $err->error_code);

        $_REQUEST["passwd"] = "world";
        $_SERVER["REQUEST_TIME"] = "0";
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $err = $ticket->Handler();
        $this->assertNull($err);
		$fields = $ticket->Get_fields();
        $this->assertEquals($fields[0], "hello");
        $this->assertEquals($fields[1], "db");
    }
}
