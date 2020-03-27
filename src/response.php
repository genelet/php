<?php
declare (strict_types = 1);

namespace Genelet;

class Response
{
    public $code;
    public $role;
    public $tag;
    public $is_json;
	public $component;
	public $action;
	public $url_key;

	public $page_type;
	public $cache;
	public $cached;

	public $results;
	
    public function __construct(int $code, string $role=null, string $tag=null, bool $is_json=null, string $component=null, string $action=null, string $url_key=null)
    {
        $this->code = $code;
		if ($role !== null) {
        	$this->role      = $role;
        	$this->tag       = $tag;
        	$this->is_json   = $is_json;
        	$this->component = $component;
        	$this->action    = $action;
        	$this->url_key   = $url_key;
		}

        $this->page_type = "normal";
        $this->cache     = null;
        $this->cached    = false;

        $this->results   = [];
    }

	public function with_results(array $results) : Response {
		$this->results = $results;
		return $this;
	}

	public function with_cached(string $body) : Response {
		$this->cached = true;
		return $this;
	}

	public function with_login(Gerror $err) : Response {
		$this->results  = ["success"=>false, "error_code"=>$err->error_code, "error_string"=>$err->error_string];
		$this->page_type = "login";
		return $this;
	}

	public function with_error(Gerror $err) : Response {
		$this->results  = ["success"=>false, "error_code"=>$err->error_code, "error_string"=>$err->error_string];
		$this->page_type = "error";
		return $this;
	}

	public function with_redirect(string $location) : Response {
		$this->code = 303;
		$this->results = ["Location"=>$location];
		return $this;
	}

	public function report($render=null) : ?string {
		http_response_code($this->code);
		switch ($this->code) {
		case 400:
		case 401:
			if (!empty($this->results)) {
				return json_encode($this->results);
			}	
			break;
		case 303:
			header("Location: ".$this->results["Location"]);
			break;
		case 200:
			if ($this->is_json) {
				header("Content-Type: application/json");
			}
			if ($this->page_type=="error" || $this->page_type=="login") {
				header("Pragma: no-cache");
				header("Cache-Control: no-cache, no-store, max-age=0, must-revalidate");
				return ($this->is_json) ? json_encode($this->results) :
					$render($this->page_type.".".$this->tag, array_merge($_REQUEST, $this->results));
			} else {
				if ($this->cached) {
					return $this->cache->get($this->url_key);
				}
				$str = ($this->is_json) ? json_encode($this->results) :
					$render($this->action.".".$this->tag, array_merge(array_merge($this->results["incoming"], $this->results["included"]), [$this->action => $this->results["data"]]));
				if ($this->cache != null && $this->cache->ctype > 0) {
					$this->cache->set($this->url_key, $str);
				}
				return $str;
			}
			break;
		default:
		}
		return null;
	}

}
