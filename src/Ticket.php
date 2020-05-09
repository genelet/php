<?php
declare (strict_types = 1);

namespace Genelet;

class Ticket extends Access
{
    public $Uri;
    public $Out_hash; #map[string]interface{}
	public $Provider;

	private $basic;

    public function __construct(string $uri=null, object $c, string $r, string $t, string $p = null)
    {
        $this->Uri = $uri;
        parent::__construct($c, $r, $t);
		$this->Provider = ($p === null) ? $this->Get_provider() : $p;
		$this->basic = false;
    }

	protected function probe_value(string $input=null) : string {
		if (isset($_REQUEST[$this->go_uri_name])) {
			return $_REQUEST[$this->go_uri_name];
		}
		foreach (explode("&", parse_url($_SERVER["REQUEST_URI"], PHP_URL_QUERY)) as $item) {
			$len = strlen($this->go_uri_name);
			if (substr($item, 0, $len+1) === $this->go_uri_name."=") {
				return urldecode(substr($item, $len+1));
			}
		}
		return isset($input) ? $input : "/";
	}

    public function Basic(): ?Gerror
    {
        $issuer = $this->Get_issuer();
        $cred = $issuer->credential;

        $user = $_REQUEST[$cred[0]];
        if(!empty($_SERVER['PHP_AUTH_USER'])) {
            $user = $_SERVER['PHP_AUTH_USER'];
            $this->basic = true;
        }
        $pw = $_REQUEST[$cred[1]];
        if(!empty($_SERVER['PHP_AUTH_PW'])) {
            $pw = $_SERVER['PHP_AUTH_PW'];
            $this->basic = true;
        }

        if(empty($user) && empty($pw)) {
            return new Gerror(1026);
        }

        $err = $this->Authenticate($user, $pw);
        if ($err != null) {
            return $err;
        }

        $attrs = $this->role_obj->attributes;
		if (empty($this->Out_hash[$attrs[0]])) {
			return new Gerror(1032);
		}

 		return null;
	}

    public function IsBasic(): bool {
		return $this->basic;
	}

    public function Handler(): ?Gerror
    {
        $probe_name = $this->go_probe_name;
        $err_name = $this->go_err_name;
        if (empty($_COOKIE[$probe_name])) {
            $this->Set_cookie_session($probe_name, $this->probe_value());
            return new Gerror(1036);
        }
        if (empty($this->Uri)) {
            $this->Uri = $this->probe_value($_COOKIE[$probe_name]);
        }

        if ($_SERVER["REQUEST_METHOD"] === "GET" && isset($_REQUEST[$err_name])) {
            return new Gerror(intval($_REQUEST[$err_name]));
        }

        $issuer = $this->Get_issuer();
        $cred = $issuer->credential;

        if (empty($_REQUEST[$cred[0]]) && empty($_REQUEST[$cred[1]])) {
            return new Gerror(1026);
        } elseif (empty($_REQUEST[$cred[0]])) {
			$_REQUEST[$cred[0]] = null;
		} elseif (empty($_REQUEST[$cred[1]])) {
			$_REQUEST[$cred[1]] = null;
		}

// Credential = [code, error] MUST be for oauth
        $err = $this->Authenticate($_REQUEST[$cred[0]], $_REQUEST[$cred[1]]);
        if ($err != null) {
            return $err;
        }

        $attrs = $this->role_obj->attributes;
		if (empty($this->Out_hash[$attrs[0]])) {
			return new Gerror(1032);
		}

		return null;
	}

	public function Get_fields(Array $hash=null) : array
	{
        $fields = array();
        foreach ($this->role_obj->attributes as $i => $v) {
			if (!empty($hash) && isset($hash[$v])) {
            	$fields[$i] = $this->hash[$v];
			} else {
            	$fields[$i] = $this->Out_hash[$v];
			}
        }

		return $fields;
	}

    public function Authenticate(string $login=null, string $password=null): ?Gerror
    {
        $issuer = $this->Get_issuer();
		$pars = $issuer->provider_pars;
        if (empty($pars["Def_login"]) || empty($pars["Def_password"]) || $login != $pars["Def_login"] || $password !== $pars["Def_password"]) {
            return new Gerror(1031);
        }

        $this->role_obj->attributes = array("login", "provider");
        $this->Out_hash = array("login" => $pars["Def_login"], "provider" => $this->Provider);

        return null;
    }

    public function Get_issuer(): object
    {
        return $this->role_obj->issuers[$this->Provider];
    }

    public function Get_provider(): string
    {
        $one = "";
        foreach ($this->role_obj->issuers as $key => $val) {
            if ($val->default) {
                return $key;
            }
            if (empty($one)) {$one = $key;}
        }
        return $one;
    }

}
