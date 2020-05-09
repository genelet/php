<?php
declare (strict_types = 1);

namespace Genelet;

class Chartag
{
	public $content_type;
	public $case;
	public $challenge;
	public $logged;
	public $logout;
	public $failed;
	public function __construct(object $t) {
		$this->content_type = $t->{"Content_type"};
		$this->case = isset($t->{"Case"}) ? $t->{"Case"} : 0;
		if ($this->case > 0) {
			$this->challenge = isset($t->{"Challenge"}) ? $t->{"Challenge"} : "challenge";
			$this->logged = isset($t->{"Logged"}) ? $t->{"Logged"} : "logged";
			$this->logout = isset($t->{"Logout"}) ? $t->{"Logout"} : "logout";
			$this->failed = isset($t->{"Failed"}) ? $t->{"Failed"} : "failed";
		}
	}
}

class Condition {
	public $marker;
	public $leading;
	public $component;
	public $redirect;
	public function __construct(array $arr)
	{
		$this->marker = $arr[0];
		$this->leading = $arr[1];
		$this->component = $arr[2];
		$this->redirect = $arr[3];
	}
}

class Issuer
{
	public $credential;
	public $sql;
	public $sql_as;
	public $out_pars;
	public $default;
	public $screen;
	public $conditions;
	public $in_pars;
	public $provider_pars;
	public function __construct(object $issuer)
	{
		$this->credential = $issuer->{"Credential"};
		$this->default = isset($issuer->{"Default"}) ? $issuer->{"Default"} : false;
		$this->screen = isset($issuer->{"Screen"}) ? $issuer->{"Screen"} : 0;
		$this->sql = $issuer->{"Sql"};
		if (isset($issuer->{"Sql_as"})) {
			$this->sql_as = $issuer->{"Sql_as"};
		}
		$this->provider_pars = array();
		if (isset($issuer->{"Provider_pars"})) {
			foreach ($issuer->{"Provider_pars"} as $k=>$v) {
				$this->provider_pars[$k] = $v;
			}
		}
		$this->in_pars = array();
		if (isset($issuer->{"In_pars"})) {
			foreach ($issuer->{"In_pars"} as $k) {
				array_push($this->in_pars, $k);
			}
		}
		$this->out_pars = array();
		if (isset($issuer->{"Out_pars"})) {
			foreach ($issuer->{"Out_pars"} as $k) {
				array_push($this->out_pars, $k);
			}
		}
		$this->conditions = array();
		if (isset($issuer->{"Condition_uri"})) {
			foreach ($issuer->{"Condition_uri"} as $obj) {
				array_push($this->conditions, new Condition($obj));
			}
		}
	}
}

class Role {
	public $idname;
	public $is_admin;
	public $attributes;
	public $typeid;
	public $surface;
	public $domain;
	public $path;
	public $length;
	public $duration;
	public $secret;
	public $coding;
	public $logout;
	public $userlist;
	public $issuers;
	public function __construct(object $role)
	{
		$this->idname = $role->{"Id_name"};
		$this->is_admin = isset($role->{"Is_admin"}) ? $role->{"Is_admin"} : false;
		$this->attributes = $role->{"Attributes"};
		$this->typeid = isset($role->{"Type_id"}) ? $role->{"Type_id"} : 0;
		$this->surface = $role->{"Surface"};
		if (isset($role->{"Domain"})) {
			$this->domain = $role->{"Domain"};
		}
		$this->path = isset($role->{"Path"}) ? $role->{"Path"} : "/";
		$this->length = isset($role->{"Length"}) ? $role->{"Length"} : 0;
		$this->duration = $role->{"Duration"};
		$this->secret = hex2bin($role->{"Secret"});
		$this->coding = hex2bin($role->{"Coding"});
		$this->logout = isset($role->{"Logout"}) ? $role->{"Logout"} : "/";
		$this->userlist = array();
		if (isset($role->{"Userlist"})) {
			foreach ($role->{"Userlist"} as $k) {
				array_push($this->userlist, $k);
			}
		}
		$this->issuers = array();
		foreach ($role->{"Issuers"} as $k=>$issuer) {
			$this->issuers[$k] = new Issuer($issuer);
		}
	}
}

class Config
{
	public $project;
	public $server_url;
	public $document_root;
	public $script;
	public $pubrole;
	public $template;
	public $uploaddir;
	public $cachetop;
	public $db;
	public $logger;
	public $chartags;
	public $roles;
	public $ttl;
	public $default_actions;
	public $oauth2s;
	public $oauth1s;

	protected $original;

	protected $action_name;
	protected $provider_name;
	protected $go_uri_name;
	protected $go_err_name;
	protected $go_probe_name;
	protected $login_name;
	protected $logout_name;
	protected $csrf_name;
	protected $cache_url_name;
	protected $json_url_name;
	protected $loginas_name;

	public function __construct(object $c) {
		$this->original = $c;
		$this->project = $c->{"Project"};
		$this->server_url = isset($c->{"Server_url"}) ? $c->{"Server_url"} : "/";
		$this->document_root = $c->{"Document_root"};
		$this->script = $c->{"Script"};
		$this->pubrole = $c->{"Pubrole"};
		$this->template = $c->{"Template"};
		if (isset($c->{"Uploaddir"})) {
			$this->uploaddir = $c->{"Uploaddir"};
		}
		if (isset($c->{"Cachetop"})) {
			$this->cachetop = $c->{"Cachetop"};
		}
		if (isset($c->{"Db"})) {
			$this->db = array($c->{"Db"}[0], $c->{"Db"}[1], $c->{"Db"}[2]);
		}
		if (isset($c->{"Log"})) {
			$this->logger = new Logger($c->{"Log"}->{"Filename"}, $c->{"Log"}->{"Level"});
		}
		$c_html = new Chartag(json_decode('{"Content_type":"text/html; charset=\"UTF-8\""}'));
		$c_csv  = new Chartag(json_decode('{"Content_type":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}'));
		$c_pdf  = new Chartag(json_decode('{"Content_type":"application/pdf"}'));
		$c_txt  = new Chartag(json_decode('{"Content_type":"text/plain; charset=\"UTF-8\""}'));
		$c_xml = new Chartag(json_decode('{"Content_type":"application/xml; charset=\"UTF-8\"", "Challenge":"challenge", "Logged":"logged", "Logout":"logout", "Failed":"failed", "Case":2}'));
		$c_json  = new Chartag(json_decode('{"Content_type":"application/json; charset=\"UTF-8\"", "Challenge":"challenge", "Logged":"logged", "Logout":"logout", "Failed":"failed", "Case":1}'));
		$this->chartags = array("html"=>$c_html, "json"=>$c_json, "xml"=>$c_xml, "csv"=>$c_csv, "pdf"=>$c_pdf, "txt"=>$c_txt);
		if (isset($c->{"Chartags"})) {
			foreach ($c->{"Chartags"} as $short => $tag) {
				$this->chartags[$short] = new Chartag($tag);
			}
		}
		$this->roles = array();
		foreach ($c->{"Roles"} as $short => $role) {
			$this->roles[$short] = new Role($role);
		}
		$this->ttl = isset($c->{"Ttl"}) ? $c->{"Ttl"} : 30*24*3600;
		$this->default_actions = array("GET"=>"dashboard", "GET_item"=>"edit", "PUT"=>"update", "POST"=>"insert", "DELETE"=>"delete");
		if (isset($c->{"Default_actions"})) {
			foreach ($c->{"Default_actions"} as $k => $v) {
				$this->default_actions[$k] = $v;
			}
		}
		$this->oauth2s = array();
		if (isset($c->{"Oauth2s"})) {
			foreach ($c->{"Oauth2s"} as $k) {
				array_push($this->oauth2s, $k);
			}
		} else {
			$this->oauth2s = ["google", "zoom", "github", "facebook", "microsoft", "qq"];
		}
		$this->oauth1s = array();
		if (isset($c->{"Oauth1s"})) {
			foreach ($c->{"Oauth1s"} as $k) {
				array_push($this->oauth1s, $k);
			}
		}
		
		$this->action_name = isset($c->{"Action_name"}) ? $c->{"Action_name"} : "action";
		$this->provider_name = isset($c->{"Provider_name"}) ? $c->{"Provider_name"} : "provider";
		$this->go_uri_name = isset($c->{"Go_uri_name"}) ? $c->{"Go_uri_name"} : "go_uri";
		$this->go_err_name = isset($c->{"Go_err_name"}) ? $c->{"Go_err_name"} : "go_err";
		$this->go_probe_name = isset($c->{"Go_probe_name"}) ? $c->{"Go_probe_name"} : "go_probe";
		$this->login_name = isset($c->{"Login_name"}) ? $c->{"Login_name"} : "login";
		$this->logout_name = isset($c->{"Logout_name"}) ? $c->{"Logout_name"} : "logout";
		$this->csrf_name = isset($c->{"Csrf_name"}) ? $c->{"Csrf_name"} : "csrf_token";
		$this->cache_url_name = isset($c->{"CacheURL_name"}) ? $c->{"CacheURL_name"} : "cache_url";
		$this->json_url_name = isset($c->{"JsonURL_name"}) ? $c->{"JsonURL_name"} : "json_url";
		$this->loginas_name = isset($c->{"Loginas_name"}) ? $c->{"Loginas_name"} : "loginas";
    }
	protected function Is_oauth2(string $name) : bool {
		return array_search($name, $this->oauth2s) !== false;
	}
	protected function Is_oauth1(string $name) : bool {
		return array_search($name, $this->oauth1s) !== false;
	}
	protected function Is_login(string $name) : bool {
		return $this->login_name == $name;
	}
	protected function Is_loginas(string $name) : bool {
		return $this->loginas_name == $name;
	}
	protected function Is_logout(string $name) : bool {
		return $this->logout_name == $name;
	}
    protected function Is_json_tag(string $tag_name) : bool {
        if (empty($this->chartags[$tag_name])) {
            return false;
        }
        $chartag = $this->chartags[$tag_name];
        return $chartag->case == 1;
    }
}
