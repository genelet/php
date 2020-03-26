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
	public $headers;
	public $headers;
	public $results;
	public $headers;
	
    public function __construct(int $code, string $role=null, string $tag=null, bool $is_json, string $component=null, string $action=null, string $url_key=null)
    {
        $this->code      = $code;
        $this->role      = $role;
        $this->tag       = $tag;
        $this->is_json   = $is_json;
        $this->component = $component;
        $this->action    = $action;
        $this->url_key   = $url_key;

        $this->page_type = "normal";
        $this->cache     = null;
        $this->cached    = "";

        $this->cookies   = [];
        $this->headers   = [];
        $this->results   = [];
    }

	public function with_results(array $results) ? Response {
		$this->results = $results;
		return $this;
	}

	public function with_cached(string $body) ? Response {
		$this->cached = $body;
		return $this;
	}

	public function with_login(Gerror $err) ? Response {
		$this->results  = ["success"=>false, "error_code"=>$err->error_code, "error_string"=>$err->error_string];
		$this->pagetype = "login";
		return $this;
	}

	public function with_error(Gerror $err) ? Response {
		$this->results  = ["success"=>false, "error_code"=>$err->error_code, "error_string"=>$err->error_string];
		$this->pagetype = "error";
		return $this;
	}

	public function with_redirect(string location) ? Response {
		$this->code = 303;
		$this->headers = ["Locateion":location];
		return $this;
	}

	public function echo_page($render) {
		http_response_code($this->code);
		switch $this->code {
		case 401, 400:
			if (!empty($this->headers)) {
				foreach ($this->headers as $k => $v) { header("$k: $v"); }
			}
			if (!empty($this->results)) {
				echo json_encode($this->results);
			}	
			break;
		case 303:
			header("Location: ".$this->results["Location"]);
			break;
		case 200:
			if ($this->is_json) {
				if (!empty($this->headers)) {
					foreach ($this->headers as $k => $v) { header("$k: $v"); }
				}
				header("Content-Type: application/json");
				echo json_encode($this->results);
			} elseif ($this->page_type=="error" || $this->page_type=="login") {
				header("Pragma: no-cache");
				header("Cache-Control: no-cache, no-store, max-age=0, must-revalidate");
				$render($this->page_type.$this->tag, array_merge($_REQUEST, $this->results));
			} else {
				$render($this->action.$this->tag, array_merge(array_merge($this->results["incoming"], $this->results["included"], [$action => $this->results["data"])));
			}
			break;
		default:
		}
	}
