<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Config;
use Genelet\Model;

final class ModelTest extends TestCase
{
    private function init(): object
    {
        $str = '{
    "current_table": "testing",
	"current_key" : "id",
	"current_id_auto" : "id",
    "insupd_pars" : ["x","y"],
    "insert_pars" : ["x","y","z"],
    "update_pars" : ["x","y","z","id"],
    "edit_pars" : ["x","y","z","id"],
	"topics_pars" : ["id","x"]
	}';
        return json_decode($str);
    }

    public function testCreatedModel(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $this->assertInstanceOf(
            Model::class,
            new Model($pdo, self::init())
        );
    }

    public function testModelExec(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $model = new Model($pdo, self::init());
        $err = $model->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $model->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $model->Exec_sql(
            "create table testing (id int not null auto_increment, x varchar(255), y varchar(255), z varchar(255) default null, primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $model->Exec_sql(
            "create table testing_f (fid int not null auto_increment, id int not null, a varchar(255), primary key (fid), foreign key (id) references testing (id) on delete cascade) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $args = ["id" => 1, "x" => "aaa", "y" => "bbb", "fields" => ["id", "x", "y", "z"]];
        $lists = array();
        $other = array();
        $model->Set_defaults($args, $lists, $other);
        $this->assertEquals("aaa", $model->ARGS["x"]);
        $ret = $model->filtered_fields($model->Topics_pars);
        $this->assertEquals(2, sizeof($ret));
        $this->assertEquals("id", $ret[0]);
        $this->assertEquals("x", $ret[1]);

        $ret = $model->get_id_val();
        $id_name = array_shift($ret);
        $this->assertEquals("id", $id_name);
        $this->assertEquals(1, $ret[0][0]);

        $model->ARGS = ["x" => "aaa", "y" => "bbb"];
        $ret = $model->get_id_val();
        $id_name = array_shift($ret);
        $this->assertEquals("id", $id_name);
        $this->assertEmpty($ret);

        $err = $model->Do_sqls(
            "INSERT INTO testing (x,y,z) VALUES (?,?,?)", array("aaa", "zzz", "1"), array("bbb", "yyy", "1"), array("ccc", "xxx", "1"), array("ddd", "www", "1"), array("eee", "vvv", "1"));
        $this->assertNull($err);
        $err = $model->existing("testing", "id", 1);
        $this->assertIsObject($err);
        $this->assertEquals(1075, $err->error_code);
        $err = $model->existing("testing", "id", 5);
        $this->assertIsObject($err);
        $this->assertEquals(1075, $err->error_code);
        $err = $model->existing("testing", "id", 6);
        $this->assertNull($err);
        $err = $model->randomid("testing", "id");
        $this->assertNull($err);
        $this->assertEquals("ORDER BY id", $model->get_order_string());
        $model->ARGS["sortreverse"] = 1;
        $this->assertEquals("ORDER BY id DESC", $model->get_order_string());
        $model->ARGS["rowcount"] = 50;
        $this->assertEquals("ORDER BY id DESC LIMIT 50 OFFSET 0", $model->get_order_string());
        $model->ARGS["pageno"] = 3;
        $this->assertEquals("ORDER BY id DESC LIMIT 50 OFFSET 100", $model->get_order_string());
        unset($model->ARGS["sortreverse"]);
        unset($model->ARGS["rowcount"]);
        unset($model->ARGS["pageno"]);
        $args = array("x" => "fff", "y" => "uuu", "z" => "2");
        $model->Set_defaults($args, $lists, $other);
        $err = $model->insert();
        $this->assertNull($err);
        $this->assertEquals(6, $model->ARGS["id"]);
        $extra = array("x" => "fff", "y" => "www", "z" => "2");
        $err = $model->insert($extra);
        $this->assertNull($err);
        $this->assertEquals(7, $model->ARGS["id"]);
        $extra = array("x" => "fff", "y" => "www", "z" => "3");
        $err = $model->insupd($extra);
        $this->assertNull($err);
        $this->assertEquals(7, $model->ARGS["id"]);
        $extra = array("x" => "fff", "y" => "xxx", "z" => "4");
        $err = $model->insupd($extra);
        $this->assertNull($err);
        $this->assertEquals(8, $model->ARGS["id"]);
        $args = array("id" => 8, "x" => "fff", "y" => "uuu", "z" => "5");
        $model->Set_defaults($args, $lists, $other);
        $err = $model->update();
        $this->assertNull($err);
        $err = $model->delete();
        $this->assertNull($err);
        $this->assertEquals(8, $model->LISTS[0]["id"]);

        $model->ARGS["id"] = [1, 2, 3];
        $model->LISTS = [];
        $err = $model->edit();
        $this->assertNull($err);
        $lists = $model->LISTS;
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

        $model->LISTS = [];
        $err = $model->topics();
        $this->assertNull($err);
        $this->assertEquals(7, sizeof($model->LISTS));
        $extra = ["x" => "fff"];
        $model->LISTS = [];
        $err = $model->topics($extra);
        $this->assertNull($err);
        $this->assertEquals(2, sizeof($model->LISTS));

        $err = $model->Do_sqls(
            "INSERT INTO testing_f (id,a) VALUES (?,?)", array(1, "111"), array(2, "222"), array(3, "333"), array(4, "444"), array(6, "666"), array(7, "777"));
        $this->assertNull($err);
        $model->Current_tables = [
            ["name" => "testing", "alias" => "t"],
            ["name" => "testing_f", "alias" => "f", "type" => "inner", "using" => "id"]];
        $model->Topics_hashpars = ["t.id" => "id", "t.x" => "x", "t.y" => "y", "t.z" => "z", "f.a" => "a"];
        $model->LISTS = [];
        $err = $model->topics();
        $this->assertNull($err);
        $lists = $model->LISTS;
        $this->assertEquals(6, sizeof($lists));
        $this->assertEquals(1, $lists[0]["id"]);
        $this->assertEquals(7, $lists[5]["id"]);
        $this->assertEquals("aaa", $lists[0]["x"]);
        $this->assertEquals("fff", $lists[5]["x"]);
        $this->assertEquals("zzz", $lists[0]["y"]);
        $this->assertEquals("www", $lists[5]["y"]);
        $this->assertEquals(1, $lists[0]["z"]);
        $this->assertEquals(3, $lists[5]["z"]);
        $this->assertEquals(111, $lists[0]["a"]);
        $this->assertEquals(777, $lists[5]["a"]);
    }

    private function init2(): object
    {
        $str = '{
	"nextpages" : {
		"topics" : [
			{"model":"tf", "action":"topics", "relate_item":{"id":"id"}}
		]
	},
    "current_table": "testing",
	"current_key" : "id",
	"current_id_auto" : "id",
    "insupd_pars" : ["x","y"],
    "insert_pars" : ["x","y","z"],
    "update_pars" : ["x","y","z","id"],
    "edit_pars" : ["x","y","z","id"],
	"topics_pars" : ["id","x"],
	"current_tables" : [
            {"name" : "testing", "alias" : "t"},
            {"name" : "testing_f", "alias" : "f", "type" : "inner", "using" : "id"}
	],
	"topics_hash" : {"t.id" : "id", "t.x" : "x", "t.y" : "y", "t.z" : "z", "f.a" : "a"}

	}';
        return json_decode($str);
    }

    private function init3(): object
    {
        $str = '{
    "current_table": "testing_f",
	"current_key" : "fid",
	"current_id_auto" : "fid",
    "insert_pars" : ["id","a"],
    "update_pars" : ["id","a","fid"],
    "edit_pars"   : ["id","a","fid"],
	"topics_pars" : ["id","a","fid"]
	}';
        return json_decode($str);
    }

    public function testModelNextpages(): void
    {
        $conf = new Config(json_decode(file_get_contents("conf/test.conf")));
        $pdo = new \PDO(...$conf->db);
        $model = new Model($pdo, self::init2());
        $t  = new Model($pdo, self::init2());
		$tf = new Model($pdo, self::init3());
		$storage = ["t"=>$t, "tf"=>$tf];

        $err = $model->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $model->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $model->Exec_sql(
            "create table testing (id int not null auto_increment, x varchar(255), y varchar(255), z varchar(255) default null, primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $model->Exec_sql(
            "create table testing_f (fid int not null auto_increment, id int not null, a varchar(255), primary key (fid), foreign key (id) references testing (id) on delete cascade) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);

        $args = [];
		$lists = array();
        $other = array();
        $model->Set_defaults($args, $lists, $other, $storage);
		$err = $model->Do_sqls(
"INSERT INTO testing (x,y,z) VALUES (?,?,?)", array("aaa", "zzz", "1"), array("bbb", "yyy", "1"), array("ccc", "xxx", "1"), array("ddd", "www", "1"), array("eee", "vvv", "1"));
        $this->assertNull($err);
		$err = $model->Do_sqls(
"INSERT INTO testing_f (id,a) VALUES (?,?)", array(1, "11"), array(1, "111"), array(2, "22"), array(2, "222"), array(3, "33"), array(3, "333"), array(4, "444"), array(5, "555"));
        $this->assertNull($err);
        $err = $model->topics();
        $this->assertNull($err);
		$this->assertEquals(8, sizeof($model->LISTS));
		$items = $model->LISTS[4]["tf_topics"];
		$this->assertEquals(5, $items[0]["fid"]);
		$this->assertEquals(3, $items[0]["id"]);
		$this->assertEquals("33", $items[0]["a"]);
		$this->assertEquals(6, $items[1]["fid"]);
		$this->assertEquals(3, $items[1]["id"]);
		$this->assertEquals("333", $items[1]["a"]);
		$items = $model->LISTS[7]["tf_topics"];
		$this->assertEquals(1, sizeof($items));
	}
}
