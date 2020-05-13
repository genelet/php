<?php

declare(strict_types=1);

namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Config;
use Genelet\Dbi;
use Genelet\Oauth2;

final class Oauth2Test extends TestCase
{
    public function testCreatedOauth2(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $dbi = new Dbi(new \PDO(...$conf->db));

        $this->assertInstanceOf(
            Oauth2::class,
            new Oauth2($dbi, "/bb/m/e/comp?action=act", json_decode(file_get_contents("conf/test.conf")), "m", "json", "github")
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testOauth2Callback(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $dbi  = new Dbi(new \PDO(...$conf->db));
        $proc = new Oauth2($dbi, "/bb/m/e/comp?action=act", json_decode(file_get_contents("conf/test.conf")), "m", "json", "github");
        $_SERVER["HTTPS"] = "Yes";
        $_SERVER["HTTP_HOST"] = "aaa.bbb.com";
        $this->assertEquals(
            "https://aaa.bbb.com/bb/m/json/github",
            $proc->Callback_address()
        );
        $this->assertEquals($proc->Defaults["authorize_url"], "https://github.com/login/oauth/authorize");
        $err = $proc->Build_authorize("1");
        $this->assertEquals($err->error_code, 303);
        $this->assertEquals($proc->Uri, "https://github.com/login/oauth/authorize?client_id=1111111111111111&redirect_uri=http%3A%2F%2Fsandy%2Fapp.php%2Fa%2Fhtml%2Fgithub&scope=repo_deployment%2Crepo%3Ainvite%2Cread%3Auser%2Cuser%3Aemail&state=1&response_type=code");
    }

    /*
    public function testOauth2Authenticate(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $dbi = new Dbi(new \PDO(...$conf->db));
        $err = $dbi->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "create table testing (autoid int not null auto_increment, id int not null, x varchar(255), primary key (autoid)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $dbi->Do_sql(
            "INSERT INTO testing (id, x) VALUES (?,?)", 1, "aaa");
        $this->assertNull($err);
        $err = $dbi->Do_sqls(
            "INSERT INTO testing (id, x) VALUES (?,?)", array(2, "bbb"), array(3, "ccc"));
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "drop procedure if exists test_proc");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "drop procedure if exists test_proc_as");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "CREATE PROCEDURE test_proc(
IN idd int,
IN xx varchar(255),
OUT email varchar(255),
OUT m_id int,
OUT first_name varchar(255),
OUT last_name varchar(255),
OUT address varchar(255),
OUT company varchar(255)
)
BEGIN
    SELECT x, autoid, 'f', 'l', 'a', 'c' INTO email, m_id, first_name, last_name, address, company FROM testing WHERE id=idd and x=xx;
END
");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "CREATE PROCEDURE test_proc_as(
IN idd int,
OUT email varchar(255),
OUT m_id int,
OUT first_name varchar(255),
OUT last_name varchar(255),
OUT address varchar(255),
OUT company varchar(255)
)
BEGIN
    SELECT x, autoid, 'f', 'l', 'a', 'c' INTO email, m_id, first_name, last_name, address, company FROM testing WHERE id=idd;
END
");
        $this->assertNull($err);

        $proc = new Oauth2($dbi, "/bb/m/e/comp?action=act", json_decode(file_get_contents("conf/test.conf")), "m", "json", "db");
        $err = $proc->Run_sql(
            "SELECT x, autoid, 'ff', 'll', 'aa', 'cc' FROM testing WHERE id=? and x=?", 3, "ccc");
        $this->assertNull($err);
        $hash = $proc->Out_hash;
        $this->assertEquals("ccc", $hash["email"]);
        $this->assertEquals(3, $hash["m_id"]);
        $this->assertEquals('ff', $hash["first_name"]);
        $this->assertEquals('ll', $hash["last_name"]);
        $this->assertEquals('aa', $hash["address"]);
        $this->assertEquals('cc', $hash["company"]);
        $proc->Out_hash = null;
        $err = $proc->Run_sql("test_proc_as", 3);
        $this->assertNull($err);
        $hash = $proc->Out_hash;
        $this->assertEquals("ccc", $hash["email"]);
        $this->assertEquals(3, $hash["m_id"]);
        $this->assertEquals('f', $hash["first_name"]);
        $this->assertEquals('l', $hash["last_name"]);
        $this->assertEquals('a', $hash["address"]);
        $this->assertEquals('c', $hash["company"]);
    }
*/
}
