<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Filter;
use Genelet\Model;

final class FilterTest extends TestCase
{
    private function init(): object
    {
        $_SERVER["REQUEST_URI"] = "/bb/m/e/comp?action=act";
        $str = '{
	"actions":{
		"startnew":{"groups":["cc","m"],"options":["no_db","no_method"]},
		"topics":{},
		"edit":{"groups":["m"],"validate":["id"]},
		"delete":{"groups":["m"]}
	},
	"fks":{
		"m":["m_id",false,"id","id_md5"]
	},
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

    public function testCreatedFilter(): void
    {
        $this->assertInstanceOf(
            Filter::class,
            new Filter(self::init(), "startnew", "testing", json_decode(file_get_contents("conf/test.conf")), "m", "json", "db")
        );
    }

    public function testFilterCan(): void
    {
        $filter = new Filter(self::init(), "startnew", "testing", json_decode(file_get_contents("conf/test.conf")), "cc", "e", "db");
		$ARGS =& $filter->ARGS;
		$_REQUEST["x"] = "bbb";
        $this->assertEquals("bbb", $ARGS["x"]);
        $this->assertEquals("cc", $filter->actionHash["groups"][0]);
        $this->assertEquals("m", $filter->actionHash["groups"][1]);
		$this->assertTrue($filter->Is_public());
		$this->assertFalse($filter->Is_admin());
		$this->assertFalse($filter->Is_normal_role());

        $filter = new Filter(self::init(), "filter", "testing", json_decode(file_get_contents("conf/test.conf")), "a", "e", "db");
		$ARGS =& $filter->ARGS;
		$this->assertFalse($filter->Is_public());
		$this->assertTrue($filter->Is_admin());
		$this->assertFalse($filter->Is_normal_role());

        $filter = new Filter(self::init(), "edit", "testing", json_decode(file_get_contents("conf/test.conf")), "m", "e", "db");
		$ARGS =& $filter->ARGS;
		$_REQUEST["m_id"] = 100;
		$_REQUEST["x"] = "bbb";
		$_REQUEST["y"] = ["ccc","ddd"];
        $this->assertEquals("bbb", $ARGS["x"]);
        $this->assertEquals("ccc", $ARGS["y"][0]);
		$this->assertTrue($filter->Role_can());
		$this->assertTrue($filter->Is_normal_role());
		$this->assertFalse($filter->Is_admin());
		$this->assertFalse($filter->Is_public());
    }

    public function testFilterBefore(): void
    {
		$_SERVER["X-Forwarded-ID"] = 4;
        $filter = new Filter(self::init(), "edit", "testing", json_decode(file_get_contents("conf/test.conf")), "m", "e", "db");
		$ARGS =& $filter->ARGS;

        $pdo = new \PDO(...$filter->db);
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
        $err = $model->Do_sqls(
            "INSERT INTO testing (x,y,z) VALUES (?,?,?)", array("aaa", "zzz", "1"), array("bbb", "yyy", "1"), array("ccc", "xxx", "1"), array("ddd", "www", "1"), array("eee", "vvv", "1"));
        $this->assertNull($err);

		$err = $filter->Preset();
        $this->assertNull($err);

		$extra = array();
		$nextextras = array();
		$err = $filter->Before($model, $extra, $nextextras);
		$this->assertIsObject($err);
		$this->assertEquals(1035, $err->error_code);

		$_REQUEST["id"] = 4;
		unset($_REQUEST["m_id"]);
		$err = $filter->Before($model, $extra, $nextextras);
		$this->assertIsObject($err);
		$this->assertEquals(1041, $err->error_code);

		$_REQUEST["m_id"] = 100;
		$err = $filter->Before($model, $extra, $nextextras);
		$this->assertNull($err);

		$filter->fkArray[0] = "junk0";
		$_REQUEST["junk0"] = "junk1";
		$err = $filter->Before($model, $extra, $nextextras);
		$this->assertIsObject($err);
		$this->assertEquals(1054, $err->error_code);

		$filter->fkArray[1] = "junk_md5";
		$_REQUEST["junk_md5"] = "aaaa";
		$err = $filter->Before($model, $extra, $nextextras);
		$this->assertIsObject($err);
		$this->assertEquals(1052, $err->error_code);

		// Endtime=0
		$_REQUEST["junk_md5"] = "j0aaXgvlb-w_60PM_xHTLrClN4sP20e2-M713anfTv0";
		$err = $filter->Before($model, $extra, $nextextras);
		$this->assertNull($err);
	}

    public function testFilterAfter(): void
    {
		$_SERVER["X-Forwarded-ID"] = 4;
        $filter = new Filter(self::init(), "edit", "testing", json_decode(file_get_contents("conf/test.conf")), "m", "e", "db");
		$ARGS =& $filter->ARGS;

        $pdo = new \PDO(...$filter->db);
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
        $err = $model->Do_sqls(
            "INSERT INTO testing (x,y,z) VALUES (?,?,?)", array("aaa", "zzz", "1"), array("bbb", "yyy", "1"), array("ccc", "xxx", "1"), array("ddd", "www", "1"), array("eee", "vvv", "1"));
        $this->assertNull($err);
	
		$_REQUEST["m_id"] = 100;
		$_SERVER["REQUEST_METHOD"] = "POST";
		$filter->fkArray[2] = "junk0";
		$filter->fkArray[3] = "junk_md5";
		$model->LISTS = [ ["junk0"=>"junk1", "x"=>"aa", "y"=>"bb"] ];
		$err = $filter->After($model);
		$this->assertNull($err);
		$list0 = $model->LISTS[0];
		$this->assertEquals("junk1", $list0["junk0"]);
		// Endtime=0
		$this->assertEquals("j0aaXgvlb-w_60PM_xHTLrClN4sP20e2-M713anfTv0", $list0["junk_md5"]);
		$this->assertEquals("aa", $list0["x"]);
		$this->assertEquals("bb", $list0["y"]);
	}
}
