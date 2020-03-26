<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use Twig;

use PHPUnit\Framework\TestCase;
use Genelet\Controller;
use Genelet\Logger;
use Genelet\Model;
use Genelet\Filter;

class tFilter extends Filter {};

final class ControllerTest extends TestCase
{
	private function getRender($resp, $c): ?Array {
		if ($resp->is_json==false && $resp->code==200) {
			$loader = ($resp->page_type=="error" || $resp->page_type=="login") ?
new \Twig\Loader\FilesystemLoader( $c->{"Template"}."/".$resp->role) :
new \Twig\Loader\FilesystemLoader([$c->{"Template"}."/".$resp->role, $c->{"Template"}."/".$resp->role ."/". $resp->component]);
			$twig = new \Twig\Environment($loader);
			return Array($twig, "render");
		}
		return null;
	}

    private function init2(): object
    {
        $str = '{
    "actions":{
        "startnew":{"groups":["cc","m"],"options":["no_db","no_method"]},
        "topics":{"groups":["m"]},
        "edit":{"groups":["m"],"validate":["id"]},
        "delete":{"groups":["m"]}
    },
    "fks":{
        "m":["m_id",false,"id","id_md5"]
    },
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

    public function testCreatedController(): void
    {
		$c = json_decode(file_get_contents("conf/test.conf"));
        $pdo = new \PDO(...$c->{"Db"});
        $t  = new Model($pdo, self::init2());
        $tf = new Model($pdo, self::init3());
        $storage = ["t"=>$t, "tf"=>$tf];
		$logger = new Logger($c->{"Log"}->{"Filename"}, $c->{"Log"}->{"Level"});

        $this->assertInstanceOf(
            Controller::class,
            new Controller($c, $pdo, ["t"=>self::init2(),self::init3()], $storage, $logger)
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testRunController(): void
    {
		$c = json_decode(file_get_contents("conf/test.conf"));
        $pdo = new \PDO(...$c->{"Db"});
        $t  = new Model($pdo, self::init2());
        $tf = new Model($pdo, self::init3());
        $storage = ["t"=>$t, "tf"=>$tf];
		$logger = new Logger($c->{"Log"}->{"Filename"}, $c->{"Log"}->{"Level"});

		$controller = new Controller($c, $pdo, ["t"=>self::init2(),self::init3()], $storage, $logger);

        $err = $t->Exec_sql(
            "drop table if exists testing_f");
        $this->assertNull($err);
        $err = $t->Exec_sql(
            "drop table if exists testing");
        $this->assertNull($err);
        $err = $t->Exec_sql(
            "create table testing (id int not null auto_increment, m_id int, x varchar(255), y varchar(255), z varchar(255) default null, primary key (id)) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $t->Exec_sql(
            "create table testing_f (fid int not null auto_increment, id int not null, a varchar(255), primary key (fid), foreign key (id) references testing (id) on delete cascade) ENGINE=InnoDB DEFAULT CHARSET=utf8");
        $this->assertNull($err);
        $err = $t->Do_sqls(
"INSERT INTO testing (m_id,x,y,z) VALUES (?,?,?,?)", array(1,"aaa", "zzz", "1"), array(1,"bbb", "yyy", "1"), array(1,"ccc", "xxx", "1"), array(1,"ddd", "www", "1"), array(1,"eee", "vvv", "1"));
        $this->assertNull($err);
        $err = $t->Do_sqls(
"INSERT INTO testing_f (id,a) VALUES (?,?)", array(1, "11"), array(1, "111"), array(2, "22"), array(2, "222"), array(3, "33"), array(3, "333"), array(4, "444"), array(5, "555"));
        $this->assertNull($err);

		$_SERVER["REQUEST_METHOD"] = "OPTIONS";
        $_SERVER["REQUEST_URI"] = "/bb/m/e/comp?action=act";
		$resp = $controller->Run();
		$this->assertIsObject($resp);
		$this->assertEquals(200, $resp->code);

		unset($_SERVER["REQUEST_METHOD"]);
        $_SERVER["REQUEST_TIME"] = "0";
        $_SERVER["REMOTE_ADDR"] = "192.168.29.30";
        $_SERVER["REQUEST_URI"] = "/bb/m/e/comp?action=act";
        $_SERVER["HTTP_HOST"] = "aaa.bbb.ccc";
        $_SERVER["HTTP_USER_AGENT"] = "ua";
		$_SERVER["REQUEST_METHOD"] = "GET";
		$resp = $controller->Run();
		$this->assertEquals(404, $resp->code);

        $_SERVER["REQUEST_URI"] = "/bb/m/e/t?action=act";
		$_REQUEST["action"] = "act";
		$resp = $controller->Run();
		$this->assertEquals(404, $resp->code);

        $_SERVER["REQUEST_URI"] = "/bb/m/json/t?action=topics";
		$_REQUEST["action"] = "topics";
		$resp = $controller->Run();
		$this->assertEquals(401, $resp->code);
		$this->assertEquals('{"success":false,"error_code":1020,"error_string":"Login required."}', $resp->report(self::getRender($resp, $c)));

        $_SERVER["REQUEST_URI"] = "/bb/m/e/t?action=topics";
		$_REQUEST["action"] = "topics";
		$resp = $controller->Run();
		$this->assertEquals(303, $resp->code);
		$this->assertEquals("/bb/m/e/login?go_uri=%2Fbb%2Fm%2Fe%2Ft%3Faction%3Dtopics&go_err=1025&provider=db", $resp->results["Location"]);

		$_SERVER["REQUEST_URI"] = "/bb/m/e/login?go_uri=%2Fbb%2Fm%2Fe%2Ft%3Faction%3Dtopics&go_err=1025&provider=db";
		$resp = $controller->Run();
		$this->assertEquals(200, $resp->code);
		$this->assertEquals("1036:Please make sure your browser supports cookie.\n", $resp->report(self::getRender($resp, $c)));
		
		$_COOKIE["go_probe"] = "1";
		$resp = $controller->Run();
		$this->assertEquals(200, $resp->code);
		$this->assertEquals("1026:Missing login or password\n", $resp->report(self::getRender($resp, $c)));
		
		$_REQUEST["email"] = "1";
		$_REQUEST["passwd"] = "aaaJunk";
		$resp = $controller->Run();
		$this->assertEquals(200, $resp->code);
		$this->assertEquals("1032:Login failed\n", $resp->report(self::getRender($resp, $c)));
		
		$_SERVER["REQUEST_URI"] = "/bb/m/json/login";
		$_SERVER['PHP_AUTH_USER'] = "1";
		$_SERVER['PHP_AUTH_PW'] = "aaaJunk";
		$resp = $controller->Run();
		$this->assertEquals(400, $resp->code);
		$this->assertEquals('{"success":false,"error_code":1032,"error_string":"Login failed"}', $resp->report(self::getRender($resp, $c)));
		$_SERVER['PHP_AUTH_PW'] = "aaa";
		$resp = $controller->Run();
		$this->assertTrue(empty($_COOKIE["SET_COOKIE"]["mc"]));
		$this->assertEquals(200, $resp->code);
		//$this->assertEquals('{"token_type":"bearer","access_token":"9uNG7G11p5_Poz0Lou23bOHnAtpditPH6UaCsI1lRmwaaiYBrWmkVEuSsDh3cZ3banilWdb5n34k9TPV9kJ3DXurZtquYUAUrtDyWtvgsmmgz6JD5Q9P_7C1VBQEJEyNmXALstsPdk-sC9_Q-BBn9WFP_MNKMRTrwWX9ZrBoL00","expires_in":360000}', $err->error_string);
		unset($_COOKIE["SET_COOKIE"]);

		$_SERVER["REQUEST_URI"] = "/bb/m/json/login";
		unset($_SERVER['PHP_AUTH_USER']);
		unset($_SERVER['PHP_AUTH_PW']);
		$_REQUEST["email"] = "1";
		$_REQUEST["passwd"] = "aaaJunk";
		$resp = $controller->Run();
		$this->assertEquals(400, $resp->code);
		$this->assertEquals('{"success":false,"error_code":1032,"error_string":"Login failed"}', $resp->report(self::getRender($resp, $c)));
		$_REQUEST["passwd"] = "aaa";
		$resp = $controller->Run();
		$this->assertTrue(isset($_COOKIE["SET_COOKIE"]["mc"]));
		$this->assertEquals(200, $resp->code);
		//$this->assertEquals('{"token_type":"bearer","access_token":"9uNG7G11p5_Poz0Lou23bOHnAtpditPH6UaCsI1lRmwaaiYBrWmkVEuSsDh3cZ3banilWdb5n34k9TPV9kJ3DXurZtquYUAUrtDyWtvgsmmgz6JD5Q9P_7C1VBQEJEyNmXALstsPdk-sC9_Q-BBn9WFP_MNKMRTrwWX9ZrBoL00","expires_in":360000}', $err->error_string);
		unset($_COOKIE["SET_COOKIE"]);

		$_SERVER["REQUEST_URI"] = "/bb/m/e/login?go_uri=%2Fbb%2Fm%2Fe%2Ft%3Faction%3Dtopics&go_err=1025&provider=db";
		$_REQUEST["email"] = "1";
		$_REQUEST["passwd"] = "aaa";
		$resp = $controller->Run();
		$this->assertEquals(303, $resp->code);
		$this->assertEquals("/bb/m/e/t?action=topics", $resp->results["Location"]);

		unset($_REQUEST["email"]);
		unset($_REQUEST["passwd"]);
		$_SERVER["REQUEST_URI"] = "/bb/m/e/t?action=topics";
		$_REQUEST["action"] = "act";
		$_COOKIE["mc"] = "gEbtIcunRGFmNgEHJrxbm53j4ZgzfCJcjwqbygPYhOMRaM2qDqVP9hXvJ7_ybp5AiDtBIL_atxYRp-F5wU86KFYG5SQs1CKI251n0kVcEr6oUHpc8IeYZMzIyLb1ggqQHwoaJNH11eirGUi1iOj0NZYMxqJwzTkrjKViWwvXq90";
        $resp = $controller->Run();
		$this->assertEquals(404, $resp->code);

		$_SERVER["REQUEST_URI"] = "/bb/m/e/t?action=edit";
		$_REQUEST["action"] = "edit";
        $resp = $controller->Run();
		$this->assertEquals(200, $resp->code);
		$this->assertEquals("1035:id\n", $resp->report(self::getRender($resp, $c)));

		foreach (["email","m_id","first_name","last_name","address","company"] as $var) {
			unset($_REQUEST[$var]);
		}
		$_REQUEST["id"] = 4;
		$_SERVER["REQUEST_URI"] = "/bb/m/json/t?action=edit";
        $resp = $controller->Run();
		$this->assertEquals(200, $resp->code);
		$this->assertEquals('{"success":true,"incoming":{"action":"edit","id":4},"data":[{"x":"ddd","y":"www","z":"1","id":"4","id_md5":"WBDuVepn54OOmgFH5TllK3ccX0Euok_SBby2pJEBjqc"}],"included":{"csrf_token":"AAAAAE_CbxN0zA2c7g-Jw_sYoPJLwhnhRNYtBgUc0tHtV9rn","cache_url":"\/bb\/m\/t\/4.json","json_url":"\/bb\/m\/json\/t?action=edit"}}', $resp->report(self::getRender($resp, $c)));

		$_SERVER["REQUEST_URI"] = "/bb/m/json/t?action=topics";
		foreach (["email","m_id","first_name","last_name","address","company"] as $var) {
			unset($_REQUEST[$var]);
		}
		unset($_REQUEST["id"]);
		$_REQUEST["action"] = "topics";
		$controller = new Controller($c, $pdo, ["t"=>self::init2(),self::init3()], $storage, $logger);
        $resp = $controller->Run();
		$this->assertEquals(200, $resp->code);
		$this->assertEquals('{"success":true,"incoming":{"action":"topics"},"data":[{"id":"1","x":"aaa","y":"zzz","z":"1","a":"11","tf_topics":[{"id":"1","a":"11","fid":"1"},{"id":"1","a":"111","fid":"2"}],"id_md5":"NqbjaOTdKgeU-u1En0zf9uIOOsOGBWOr9I5fasQ-YxM"},{"id":"1","x":"aaa","y":"zzz","z":"1","a":"111","tf_topics":[{"id":"1","a":"11","fid":"1"},{"id":"1","a":"111","fid":"2"}],"id_md5":"NqbjaOTdKgeU-u1En0zf9uIOOsOGBWOr9I5fasQ-YxM"},{"id":"2","x":"bbb","y":"yyy","z":"1","a":"22","tf_topics":[{"id":"2","a":"22","fid":"3"},{"id":"2","a":"222","fid":"4"}],"id_md5":"L9-9OwSaFmPnoCPNKpYF1M2gOAYpTN3PKsESn9EfdWs"},{"id":"2","x":"bbb","y":"yyy","z":"1","a":"222","tf_topics":[{"id":"2","a":"22","fid":"3"},{"id":"2","a":"222","fid":"4"}],"id_md5":"L9-9OwSaFmPnoCPNKpYF1M2gOAYpTN3PKsESn9EfdWs"},{"id":"3","x":"ccc","y":"xxx","z":"1","a":"33","tf_topics":[{"id":"3","a":"33","fid":"5"},{"id":"3","a":"333","fid":"6"}],"id_md5":"XGz0HstPHvpOD2tmf9jz3CsvnTUiOB-KW9IVX5KJ630"},{"id":"3","x":"ccc","y":"xxx","z":"1","a":"333","tf_topics":[{"id":"3","a":"33","fid":"5"},{"id":"3","a":"333","fid":"6"}],"id_md5":"XGz0HstPHvpOD2tmf9jz3CsvnTUiOB-KW9IVX5KJ630"},{"id":"4","x":"ddd","y":"www","z":"1","a":"444","tf_topics":[{"id":"4","a":"444","fid":"7"}],"id_md5":"WBDuVepn54OOmgFH5TllK3ccX0Euok_SBby2pJEBjqc"},{"id":"5","x":"eee","y":"vvv","z":"1","a":"555","tf_topics":[{"id":"5","a":"555","fid":"8"}],"id_md5":"Gv6nPAvRmIrGVwZiqF0K84XjlP-v4g8S5Y42B9rpF5c"}],"included":{"csrf_token":"AAAAAE_CbxN0zA2c7g-Jw_sYoPJLwhnhRNYtBgUc0tHtV9rn","cache_url":"\/bb\/m\/t\/topics.json","json_url":"\/bb\/m\/json\/t?action=topics"}}', $resp->report(self::getRender($resp, $c)));

		$_SERVER["REQUEST_URI"] = "/bb/m/e/t?action=topics";
		foreach (["email","m_id","first_name","last_name","address","company"] as $var) {
			unset($_REQUEST[$var]);
		}
		unset($_REQUEST["id"]);
		$_REQUEST["action"] = "topics";
		$controller = new Controller($c, $pdo, ["t"=>self::init2(),self::init3()], $storage, $logger);
        $resp = $controller->Run();
		$this->assertEquals(200, $resp->code);
		$this->assertEquals('id=1,id=1,id=2,id=2,id=3,id=3,id=4,id=5,', $resp->report(self::getRender($resp, $c)));
	}
}
