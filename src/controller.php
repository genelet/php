<?php
declare (strict_types = 1);

namespace Genelet;
use Twig;

class Controller extends Config
{
    public $pdo;
    public $components;
    public $Storage;
	public $logger;
    public function __construct(object $c, \PDO $pdo, array $components, array $storage, Logger $log)
    {
        parent::__construct($c);
        $this->pdo = $pdo;
        $this->components = $components;
        $this->Storage = $storage;
        $this->logger = $log;
    }

    public function Run(): ?Gerror
    {
        // self::cross_domain();
        if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
            return new Gerror(200);
        }
		$logger = $this->logger;
$logger->screen_start($_SERVER["REQUEST_METHOD"], $_SERVER["REQUEST_URI"], $_SERVER["REMOTE_ADDR"], $_SERVER['HTTP_USER_AGENT']);
        if (empty($this->default_actions[$_SERVER["REQUEST_METHOD"]])) {
$logger->info("request method not defined.");
            return new Gerror(405);
        }
		
        list ($cache_type, $role_name, $tag_name, $comp_name, $action, $url_key, $err) = $this->getUrl();
        if (isset($err)) { return $err; }
$logger->info("role=>" . $role_name);
$logger->info("tag=>" . $tag_name);
$logger->info("comp=>" . $comp_name);
$logger->info("action=>" . $action);
        if (empty($this->chartags[$tag_name])) {
$logger->info("tag not found.");
            return new Gerror(404);
        }
		$tag_obj = $this->chartags[$tag_name];
		$is_json = $this->Is_json_tag($tag_name);
		$c = $this->original;

        if ($role_name != $this->pubrole) {
$logger->info("login role.");
            if (empty($this->roles[$role_name])) {
$logger->info("role not found.");
                return new Gerror(404);
            }

            if ($this->Is_logout($comp_name)) {
$logger->info("logout.");
                $base = new Base($c, $role_name, $tag_name);
				$logout = $base->Handler_logout();
        		if ($is_json) {
					header("Content-Type: application/json");
					return new Gerror(200, json_encode(["success" => true, "error_string" => $tag_obj->logout]));
				}
                return new Gerror(303, $logout);
            } elseif ($this->Is_login($comp_name) || $this->Is_oauth2($comp_name)) {
$logger->info("login using " . $this->provider_name);
                $dbi = new Dbi($this->pdo);
                $ticket = $this->Is_oauth2($comp_name)
                ? new Oauth2($dbi, null, $c, $role_name, $tag_name, $comp_name)
                : isset($_REQUEST[$this->provider_name])
                ? new Procedure($dbi, null, $c, $role_name, $tag_name, $_REQUEST[$this->provider_name])
                : new Procedure($dbi, null, $c, $role_name, $tag_name);
                $err = ($is_json) ? $ticket->Handler_login():$ticket->Handler();
			    if ($err === null) { return new Gerror(401); }
                if ($err->error_code == 303) { // success is 303
$logger->info("login succeeded.");
					if ($is_json) {
						header("Content-Type: application/json");
						return new Gerror(200, json_encode(["success" => true, "error_string" => $tag_obj->logged]));
					}
                    return $err;
                } // all other cases are login page error
$logger->info("login failed.");
                return new Gerror(200, $this->login_page($role_name, $tag_name, $err));
            }
        }
        if (empty($this->components[$comp_name]) ||
            empty($this->components[$comp_name]->{"actions"}) ||
            empty($this->components[$comp_name]->{"actions"}->{$action})) {
$logger->info("component or action not found.");
            return new Gerror(404);
        }

        $filter_name = ($this->project == "Genelet")
        ? '\\Genelet\\Filter'
        : '\\' . $this->project . '\\' . ucfirst($comp_name) . '\\Filter';
        $filter = new $filter_name($this->components[$comp_name], $action, $comp_name, $c, $role_name, $tag_name);

		if (!empty($url_key) && $cache_type===0) { // GET request with 4 in url
$logger->info("ID from URL.");
			$_REQUEST[$filter->current_key] = $url_key;
		}
        $OLD = $_REQUEST;

        if (!$filter->Is_public()) {
$logger->info("check authentication for not public role.");
			$surface = $filter->roles[$role_name]->surface;
            $err = empty($_REQUEST[$surface]) ? $filter->Verify_cookie() : $filter->Verify_cookie($_REQUEST[$surface]);
            if ($err != null) {
$logger->info("ticket check failed.");
				$code = $err->error_code;
        		if ($is_json) {
					header("Content-Type: application/json");
					return new Gerror(200, json_encode(["success" => false, "error_code" => $err->error_code, "error_string" => $tag_obj->challenge]));
				}
				return new Gerror(303, $filter->Forbid());
			} else {
$logger->info("ticket check successful.");
            	foreach ($filter->Decoded as $k => $v) {
			    	$_REQUEST[$k] = $v;
            	}
			}
$logger->info("put decoded into the request object.");
        }

        if (!$filter->Role_can()) {
$logger->info("acl failed.");
            return new Gerror(401);
        }

        if ($this->Is_loginas($action)) {
$logger->info("login as ...");
            return $filter->Login_as();
        }

		$ttl = isset($filter->actionHash["ttl"]) ? $filter->actionHash["ttl"] : $this->ttl;
		$cache = new Cache($c, $role_name, $tag_name, $action, $comp_name, $cache_type, $ttl);
		if ($cache_type>0) {
$logger->info("caching starts...");
			if ($cache->has($url_key)) {
				return new Gerror(200, $cache->get($url_key));
			 } elseif ($cache_type===1) { // GET id request
				$_REQUEST[$filter->current_key] = $url_key;
			 } elseif ($cache_type===2 && !empty($url_key)) {
				$queries = unserialize(base64_decode(str_replace(['-','_'], ['+','/'], $url_key)));
				foreach ($queries as $k => $v) { $_REQUEST[$k] = $v; }
			}
		}

        $err = $filter->Preset();
$logger->info("preset completed.");
        if ($err != null) {return new Gerror(200, $this->error_page($tag_name, $err));}

        $model = $this->Storage[$comp_name];
        $lists = array();
        $other = array();
        $model->Set_defaults($_REQUEST,$lists,$other,$this->Storage,$logger);

        $extra = array();
        $nextextra = array();
        $err = $filter->Before($model, $extra, $nextextra);
$logger->info("before completed.");
        if ($err != null) {return new Gerror(200, $this->error_page($tag_name, $err));}

        if (empty($filter->actionHash["options"]) || array_search("no_method", $filter->actionHash["options"]) === false) {
            $action = $filter->Action;
$logger->info("start model action: " . $action);
            $err = $model->$action($extra, ...$nextextra);
            if ($err != null) {return new Gerror(200, $this->error_page($tag_name, $err));}
        }

        $err = $filter->After($model);
$logger->info("after completed.");
        if ($err != null) {return new Gerror(200, $this->error_page($tag_name, $err));}

$logger->info("start building content page.");
		$result = $this->content_page($role_name, $filter->Component, $filter->Action, $tag_name, $OLD, $model->LISTS, $model->OTHER);
		if ($cache_type>0) {
			$cache->set($url_key, $result);
		}
$logger->info("end page, and sending to browser.");
		return new Gerror(200, $result);
    }

    private function error_page(string $tag_name, Gerror $err): string
    {
        header("Pragma: no-cache");
        header("Cache-Control: no-cache, no-store, max-age=0, must-revalidate");
        if ($this->Is_json_tag($tag_name)) {
			header("Content-Type: application/json");
            return json_encode(["success" => false, "error_code" => $err->error_code, "error_string" => $err->error_string]);
        }
        $loader = new \Twig\Loader\FilesystemLoader($this->template);
        $twig = new \Twig\Environment($loader);
        return $twig->render("error." . $tag_name, ["error_code" => $err->error_code, "error_string" => $err->error_string]);
    }

    private function login_page(string $role_name, string $tag_name, Gerror $err): string
    {
        header("Pragma: no-cache");
        header("Cache-Control: no-cache, no-store, max-age=0, must-revalidate");
        if ($this->Is_json_tag($tag_name)) {
			header("Content-Type: application/json");
            return json_encode(["success" => false, "error_code" => $err->error_code, "error_string" => $err->error_string]);
        }
        $loader = new \Twig\Loader\FilesystemLoader($this->template . "/" . $role_name);
        $twig = new \Twig\Environment($loader);
        return $twig->render($this->login_name . "." . $tag_name, ["error_code" => $err->error_code, "error_string" => $err->error_string]);
    }

    private function content_page(string $role, string $comp, string $action, string $tag, array $old, array $lists, array $other): string
    {
        if ($this->Is_json_tag($tag)) {
			header("Content-Type: application/json");
			return json_encode(["success" => true, "incoming" => $old, "included" => $lists, "relationships" => $other]);
		}
        $loader = new \Twig\Loader\FilesystemLoader($this->template . "/" . $role . "/" . $comp);
        $twig = new \Twig\Environment($loader);
        return $twig->render($action . "." . $tag, array_merge(array_merge($old, $other), [$action => $lists]));
    }

    private static function cross_domain() : void
    {
        foreach ($_SERVER as $name => $value) {
            if ($name === "ORIGIN") {
                header("Access-Control-Allow-Origin: $value");
                header("Access-Control-Max-Age: 1728000");
                header("Access-Control-Allow-Credentials: true");
            } elseif ($name === "Access-Control-Request-Method") {
                header("Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE");
            } elseif ($name === "Access-Control-Request-Headers") {
                header("Access-Control-Allow-Headers: $value");
            }
        }
    }

    private function body_json() : void
    {
        $json_found = false;
        $header_found = false;
        $items = array();
        if (function_exists('apache_request_headers')) {
            $hs = apache_request_headers();
            if (isset($hs["Content-Type"])) {array_push($items, $hs["Content-Type"]);}
        }
        if (isset($_SERVER["CONTENT_TYPE"])) {array_push($items, $_SERVER["CONTENT_TYPE"]);}
        if (isset($_SERVER["HTTP_CONTENT_TYPE"])) {array_push($items, $_SERVER["HTTP_CONTENT_TYPE"]);}
        if (!empty($items)) {
            $header_found = true;
            foreach ($items as $item) {
                if ($item === "application/x-www-form-urlencoded" || $item === "multipart/form-data") {return;}
                if (strpos($item, 'json') !== false) {$json_found = true;
                    break;}
            }
        }
        if ($json_found || $header_found === false) {
            $content = file_get_contents('php://input');
            if (!empty($content)) {
                foreach (json_decode($content, true) as $k => $v) {
                    $_REQUEST[$k] = $v;
                }
            }
        }
    }

	// cache_type(1 for id, 2 others), role, tag, component, action, id, error
	private function getUrl() : array {
		$length = strlen($this->script);
        $url_obj = parse_url($_SERVER["REQUEST_URI"]);
        $l_url = strlen($url_obj["path"]);
        if ($l_url <= $length || substr($url_obj["path"], 0, $length + 1) !== $this->script . "/") {
			return array(0, "", "", "", "", "", new Gerror(400));
        }

		$cache_type = 0;
        $url_key="";

        $rest = substr($url_obj["path"], $length + 1);
        $path_info = explode("/", $rest);
        if (sizeof($path_info) == 4 && $_SERVER["REQUEST_METHOD"] == "GET") {
			$url_key = array_pop($path_info);
            $_SERVER["REQUEST_METHOD"] = "GET_item";
        } elseif (sizeof($path_info) != 3) {
			return array(0, "", "", "", "", "", new Gerror(400));
        }

        $arr = explode('.', $path_info[2]);
        if (sizeof($arr)===2) {
            $role_name = $path_info[0];
            $comp_name = $path_info[1];
            $tag_name = $arr[1];
            $action = $arr[0];
            if (preg_match("/^[0-9]+$/", $arr[0])) {
				$cache_type = 1;
                $action = $this->default_actions["GET_item"];
                $url_key = $arr[0];
            } else {
				$cache_type = 2;
                $patterns = explode('_', $arr[0], 2);
                if (sizeof($patterns)===2) {
					$action = $patterns[0];
                    $url_key = $patterns[1];
                }
            }
			return array($cache_type, $role_name, $tag_name, $comp_name, $action, $url_key, null);
        }

        $role_name = $path_info[0];
        $tag_name = $path_info[1];
        $comp_name = $path_info[2];
        if ($this->Is_json_tag($tag_name)) {
                if ($_SERVER["REQUEST_METHOD"] === "POST") {$this->body_json();}
        }
        $action = isset($_REQUEST[$this->action_name])
        ? $_REQUEST[$this->action_name]
        : $this->default_actions[$_SERVER["REQUEST_METHOD"]];
		return array($cache_type, $role_name, $tag_name, $comp_name, $action, $url_key, null);
	}
}
