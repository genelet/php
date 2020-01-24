<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Config;
use Genelet\Crud;

final class CrudTest extends TestCase
{
    public function testCreatedCrud(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $this->assertInstanceOf(
            Crud::class,
            new Crud($pdo, "testing")
        );
    }

    public function testCrudExec(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $crud = new Crud($pdo, "testing");
        $err = $crud->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "create table testing (id int not null, x varchar(255), primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
    }

    public function testCrudStrings(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $crud = new Crud($pdo, "testing");

        $select_pars = array("a", "b", "c", "d");
        $labels = $crud->Select_label_string($select_pars);
        $sql = array_shift($labels);
        $this->assertEquals("a, b, c, d", $sql);
        $this->assertEquals("a", $labels[0]);
        $this->assertEquals("b", $labels[1]);
        $this->assertEquals("c", $labels[2]);
        $this->assertEquals("d", $labels[3]);

        $select_pars = array("x.a" => "aa", "x.b" => "bb", "y.c" => "cc", "y.d" => "dd");
        $labels = $crud->Select_label_string($select_pars);
        $sql = array_shift($labels);
        $this->assertEquals("x.a, x.b, y.c, y.d", $sql);
        $this->assertEquals("aa", $labels[0]);
        $this->assertEquals("bb", $labels[1]);
        $this->assertEquals("cc", $labels[2]);
        $this->assertEquals("dd", $labels[3]);

        $extra = array("x.a" => "aa", "x.b" => array(1, 2, 3), "_gsql" => "cc=ccc", "d" => "dd");
        $values = $crud->Select_condition_string($extra, "tab");
        $sql = array_shift($values);
        $this->assertEquals("(x.a=?) AND (x.b IN (?,?,?)) AND (cc=ccc) AND (tab.d=?)", $sql);
        $this->assertEquals("aa", $values[0]);
        $this->assertEquals(1, $values[1]);
        $this->assertEquals(2, $values[2]);
        $this->assertEquals(3, $values[3]);
        $this->assertEquals("dd", $values[4]);

        $keyname = "autoid";
        $ids = array(11, 22, 33, 44);
        $values = $crud->Single_condition_string(array($keyname => $ids), $extra);
        $sql = array_shift($values);
        $this->assertEquals("(autoid IN (?,?,?,?)) AND (x.a=?) AND (x.b IN (?,?,?)) AND (cc=ccc) AND (d=?)", $sql);
        $this->assertEquals(11, $values[0]);
        $this->assertEquals(22, $values[1]);
        $this->assertEquals(33, $values[2]);
        $this->assertEquals(44, $values[3]);
        $this->assertEquals("aa", $values[4]);
        $this->assertEquals(1, $values[5]);
        $this->assertEquals(2, $values[6]);
        $this->assertEquals(3, $values[7]);
        $this->assertEquals("dd", $values[8]);
    }

    public function testCrudActions(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $crud = new Crud($pdo, "testing");

        $err = $crud->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "create table testing (id int not null, x varchar(255), primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $crud->Do_sql(
            "INSERT INTO testing (id, x) VALUES (?,?)", 1, "aaa");
        $this->assertNull($err);
        $err = $crud->Do_sqls(
            "INSERT INTO testing (id, x) VALUES (?,?)", array(2, "bbb"), array(3, "ccc"));
        $this->assertNull($err);

        $field_values = array("id" => 4, "x" => "ddd");
        $err = $crud->Insert_hash($field_values);
        $this->assertNull($err);
        $field_values = array("id" => 4, "x" => "eee");
        $err = $crud->Replace_hash($field_values);
        $this->assertNull($err);
        $field_values = array("id" => 4, "x" => "fff");
        $err = $crud->Update_hash($field_values, array("id" => 4));
        $this->assertNull($err);

        $err = $crud->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "create table testing (id int not null, x varchar(255), y varchar(255) default null, primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $crud->Do_sql(
            "INSERT INTO testing (id, x) VALUES (?,?)", 1, "aaa");
        $this->assertNull($err);
        $err = $crud->Do_sqls(
            "INSERT INTO testing (id, x) VALUES (?,?)", array(2, "bbb"), array(3, "ccc"));
        $this->assertNull($err);
        $field_values = array("id" => 4, "x" => "ddd", "y" => "yyy");
        $err = $crud->Insert_hash($field_values);
        $this->assertNull($err);
        $field_values = array("id" => 5, "x" => "eee", "y" => "yyy");
        $err = $crud->Replace_hash($field_values);
        $this->assertNull($err);
        $field_values = array("id" => 4, "x" => "fff", "y" => "zzz");
        $err = $crud->Update_hash($field_values, array("id" => 4));
        $this->assertNull($err);
        $field_values = array("id" => 5, "x" => "ggg");
        $err = $crud->Update_hash_nulls($field_values, array("id" => 5), array("y"));
        $this->assertNull($err);

        $err = $crud->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "create table testing (id int not null auto_increment, x varchar(255), y varchar(255) default null, primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $crud->Do_sqls(
            "INSERT INTO testing (x,y) VALUES (?,?)", array("aaa", "zzz"), array("bbb", "yyy"), array("ccc", "xxx"), array("ddd", "www"), array("eee", "vvv"));
        $this->assertNull($err);
        $field_values = array("x" => "fff", "y" => "uuu");
        $which = "";
        $err = $crud->Insupd_table($field_values, "id", array("x"), $which);
        $this->assertNull($err);
        $this->assertEquals("insert", $which);
        $field_values = array("x" => "fff", "y" => "vvv");
        $err = $crud->Insupd_table($field_values, "id", array("x"), $which);
        $this->assertNull($err);
        $this->assertEquals("update", $which);

        $err = $crud->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "create table testing (id int not null auto_increment, x varchar(255), y varchar(255), z varchar(255) default null, primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $crud->Do_sqls(
            "INSERT INTO testing (x,y,z) VALUES (?,?,?)", array("aaa", "zzz", "1"), array("bbb", "yyy", "1"), array("ccc", "xxx", "1"), array("ddd", "www", "1"), array("eee", "vvv", "1"));
        $this->assertNull($err);
        $field_values = array("x" => "fff", "y" => "uuu", "z" => "2");
        $which = "";
        $err = $crud->Insupd_table($field_values, "id", array("x", "y"), $which);
        $this->assertNull($err);
        $this->assertEquals("insert", $which);
        $field_values = array("x" => "fff", "y" => "vvv", "z" => "2");
        $err = $crud->Insupd_table($field_values, "id", array("x", "y"), $which);
        $this->assertNull($err);
        $this->assertEquals("insert", $which);
        $field_values = array("x" => "fff", "y" => "uuu", "z" => "3");
        $err = $crud->Insupd_table($field_values, "id", array("x", "y"), $which);
        $this->assertNull($err);
        $this->assertEquals("update", $which);

        $err = $crud->Delete_hash(array("x" => "fff"), array("y" => "ttt"));
        $this->assertNull($err);
        $err = $crud->Delete_hash(array("x" => "eee"));
        $this->assertNull($err);

        $lists = array();
        $err = $crud->Edit_hash($lists, array("id", "x", "y", "z"), array("id" => [1, 2, 3]));
        $this->assertNull($err);
        $this->assertEquals(1, $lists[0]["id"]);
        $this->assertEquals(2, $lists[1]["id"]);
        $this->assertEquals(3, $lists[2]["id"]);
        $this->assertEquals("aaa", $lists[0]["x"]);
        $this->assertEquals("bbb", $lists[1]["x"]);
        $this->assertEquals("ccc", $lists[2]["x"]);
        $this->assertEquals("zzz", $lists[0]["y"]);
        $this->assertEquals("yyy", $lists[1]["y"]);
        $this->assertEquals("xxx", $lists[2]["y"]);
        $this->assertEquals(1, $lists[0]["z"]);
        $this->assertEquals(1, $lists[1]["z"]);
        $this->assertEquals(1, $lists[2]["z"]);
        $lists = array();
        $err = $crud->Edit_hash($lists, array("id", "x", "y", "z"), array("id" => [1, 2, 3]), array("x" => "aaa"));
        $this->assertNull($err);
        $this->assertEquals(1, sizeof($lists));
        $this->assertEquals(1, $lists[0]["id"]);
        $this->assertEquals("aaa", $lists[0]["x"]);
        $this->assertEquals("zzz", $lists[0]["y"]);
        $this->assertEquals(1, $lists[0]["z"]);

        $hash = array();
        $err = $crud->Total_hash($hash, "manys");
        $this->assertNull($err);
        $this->assertEquals(6, $hash["manys"]);
        $err = $crud->Total_hash($hash, "manys", array("x" => "fff"));
        $this->assertNull($err);
        $this->assertEquals(2, $hash["manys"]);

        $lists = array();
        $select_pars = array("id", "x", "y", "z");
        $err = $crud->Topics_hash($lists, $select_pars, "");
        $this->assertNull($err);
        $this->assertEquals(6, sizeof($lists));
        $lists = array();
        $err = $crud->Topics_hash($lists, $select_pars, "", array("x" => "fff"));
        $this->assertNull($err);
        $this->assertEquals(2, sizeof($lists));

        $err = $crud->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $crud->Exec_sql(
            "create table testing_f (fid int not null auto_increment, id int not null, a varchar(255), primary key (fid), foreign key (id) references testing (id) on delete cascade) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $crud->Do_sqls(
            "INSERT INTO testing_f (id,a) VALUES (?,?)", array(1, "111"), array(2, "222"), array(3, "333"), array(4, "444"), array(6, "666"), array(7, "777"));
        $this->assertNull($err);
        $lists = array();
        $select_pars = array("t.id" => "id", "t.x" => "x", "t.y" => "y", "t.z" => "z", "f.a" => "a");
        $crud->Current_tables = array(
            array("name" => "testing", "alias" => "t"),
            array("name" => "testing_f", "alias" => "f", "type" => "inner", "using" => "id"));
        $err = $crud->Topics_hash($lists, $select_pars, "");
        $this->assertNull($err);
        $this->assertEquals(6, sizeof($lists));
        $lists = array();
        $err = $crud->Topics_hash($lists, $select_pars, "", array("x" => "fff"));
        $this->assertNull($err);
        $this->assertEquals(2, sizeof($lists));
        $this->assertEquals(6, $lists[0]["id"]);
        $this->assertEquals(7, $lists[1]["id"]);
        $this->assertEquals("fff", $lists[0]["x"]);
        $this->assertEquals("fff", $lists[1]["x"]);
        $this->assertEquals("uuu", $lists[0]["y"]);
        $this->assertEquals("vvv", $lists[1]["y"]);
        $this->assertEquals(3, $lists[0]["z"]);
        $this->assertEquals(2, $lists[1]["z"]);
        $this->assertEquals(666, $lists[0]["a"]);
        $this->assertEquals(777, $lists[1]["a"]);
    }
}
