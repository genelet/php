<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Config;
use Genelet\Dbi;

final class DbiTest extends TestCase
{
    public function testCreatedDbi(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $this->assertInstanceOf(
            Dbi::class,
            new Dbi($pdo)
        );
    }

    public function testDbiExec(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $dbi = new Dbi($pdo);
        $err = $dbi->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "create table testing (id int not null, x varchar(255), primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "create table testing (x varchar(2), primary key (x)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertIsObject($err);
        $this->assertEquals(1071, $err->error_code);
        $this->assertEquals("42S01; 1050; Table 'testing' already exists", $err->error_string);
    }

    public function testDbiDoSelect(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $dbi = new Dbi($pdo);
        $err = $dbi->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "create table testing (id int not null, x varchar(255), primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $dbi->Do_sql(
            "INSERT INTO testing (id, x) VALUES (?,?)", 1, "aaa");
        $this->assertNull($err);
        $err = $dbi->Do_sqls(
            "INSERT INTO testing (id, x) VALUES (?,?)", array(2, "bbb"), array(3, "ccc"));
        $this->assertNull($err);
        $lists = array();
        $err = $dbi->Select_sql($lists,
            "SELECT id, x FROM testing WHERE id<?", 3);
        $this->assertNull($err);
        $this->assertEquals(1, $lists[0]["id"]);
        $this->assertEquals("aaa", $lists[0]["x"]);
        $this->assertEquals(2, $lists[1]["id"]);
        $this->assertEquals("bbb", $lists[1]["x"]);
        $lists = array();
        $err = $dbi->Select_sql_label($lists, array("aid", "ax"),
            "SELECT id, x FROM testing WHERE id<?", 3);
        $this->assertNull($err);
        $this->assertEquals(1, $lists[0]["aid"]);
        $this->assertEquals("aaa", $lists[0]["ax"]);
        $this->assertEquals(2, $lists[1]["aid"]);
        $this->assertEquals("bbb", $lists[1]["ax"]);
        $ARGS = array();
        $err = $dbi->Get_args($ARGS,
            "SELECT id, x FROM testing WHERE id=?", 3);
        $this->assertNull($err);
        $this->assertEquals(3, $ARGS["id"]);
        $this->assertEquals("ccc", $ARGS["x"]);
    }

    public function testDbiProcedure(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $dbi = new Dbi($pdo);
        $err = $dbi->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "create table testing (id int not null, x varchar(255), primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
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
            "CREATE PROCEDURE test_proc(
IN idd int,
OUT counts int,
OUT sums int)
BEGIN
	SELECT COUNT(*), 1+COUNT(*) INTO counts, sums FROM testing;
	SELECT id, x FROM testing WHERE id<=idd;
END
");
        $this->assertNull($err);
        $lists = array();
        $labels = array("bid", "bx");
        $hash = array();
        $names = array("total", "sums");
        $err = $dbi->Select_do_proc_label($lists, $labels, $hash, $names, "test_proc", 3);
        $this->assertNull($err);
        $this->assertEquals(1, $lists[0]["bid"]);
        $this->assertEquals(2, $lists[1]["bid"]);
        $this->assertEquals(3, $lists[2]["bid"]);
        $this->assertEquals("aaa", $lists[0]["bx"]);
        $this->assertEquals("bbb", $lists[1]["bx"]);
        $this->assertEquals("ccc", $lists[2]["bx"]);
        $this->assertEquals("3", $hash["total"]);
        $this->assertEquals("4", $hash["sums"]);

        $err = $dbi->Exec_sql(
            "drop procedure if exists test_proc");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "CREATE PROCEDURE test_proc(
IN idd int)
BEGIN
	SELECT id, x FROM testing WHERE id<=idd;
END
");
        $this->assertNull($err);
        $lists = array();
        $labels = array("bid", "bx");
        $err = $dbi->Select_proc_label($lists, $labels, "test_proc", 3);
        $this->assertNull($err);
        $this->assertEquals(1, $lists[0]["bid"]);
        $this->assertEquals(2, $lists[1]["bid"]);
        $this->assertEquals(3, $lists[2]["bid"]);
        $this->assertEquals("aaa", $lists[0]["bx"]);
        $this->assertEquals("bbb", $lists[1]["bx"]);
        $this->assertEquals("ccc", $lists[2]["bx"]);

        $err = $dbi->Exec_sql(
            "drop procedure if exists test_proc");
        $this->assertNull($err);
        $err = $dbi->Exec_sql(
            "CREATE PROCEDURE test_proc(
IN idd int,
OUT counts int,
OUT sums int)
BEGIN
	SELECT COUNT(*), 1+COUNT(*) INTO counts, sums FROM testing;
END
");
        $this->assertNull($err);
        $lists = array();
        $labels = array("bid", "bx");
        $hash = array();
        $names = array("total", "sums");
        $err = $dbi->Do_proc_label($hash, $names, "test_proc", 3);
        $this->assertNull($err);
        $this->assertEquals("3", $hash["total"]);
        $this->assertEquals("4", $hash["sums"]);

    }
}
