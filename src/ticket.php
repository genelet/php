<?php
declare (strict_types = 1);

namespace Genelet;

include_once 'access.php';

class Ticket extends Access
{
    public $Uri;
    public $Out_hash; #map[string]interface{}
	public $Provider;

    public function __construct(string $uri=null, object $c, string $r, string $t, string $p = null)
    {
        $this->Uri = $uri;
        parent::__construct($c, $r, $t);
		$this->Provider = ($p === null) ? $this->Get_provider() : $p;
    }

	private function probe_value(string $input=null) : string {
		if (isset($_REQUEST[$this->config->{"Go_uri_name"}])) {
			return $_REQUEST[$this->config->{"Go_uri_name"}];
		}
		foreach (explode("&", parse_url($_SERVER["REQUEST_URI"], PHP_URL_QUERY)) as $item) {
			$len = strlen($this->config->{"Go_uri_name"});
			if (substr($item, 0, $len+1) === $this->config->{"Go_uri_name"}."=") {
				return urldecode(substr($item, $len+1));
			}
		}
		return isset($input) ? $input : "/";
	}

    public function Handler(): ?Gerror
    {
        $config = $this->config;
        $probe_name = $config->{"Go_probe_name"};
        $err_name = $config->{"Go_err_name"};
        if (empty($_COOKIE[$probe_name])) {
            $this->Set_cookie_session($probe_name, $this->probe_value());
            return new Gerror(1036);
        }
        if (empty($this->Uri)) {
            $this->Uri = $this->probe_value($_COOKIE[$probe_name]);
        }

        if (isset($_REQUEST[$err_name])) {
            return new Gerror(intval($_REQUEST[$err_name]));
        }

        return $this->Handler_login();
    }

    public function Handler_login(): ?Gerror
    {
        $issuer = $this->Get_issuer();
        $cred = $issuer->{"Credential"};

/*
$surface = $role->{"Surface"};
if (($surface === $cred[3]) && isset($_REQUEST[$surface])) {
$passin = $_REQUEST[$surface];
$err = $this->Verify_cookies($passin);
if ($err != null) {
return $err;
}
$this->Set_cookie($surface, $passin);
$this->Set_cookie_session($surface . "_", $passin);
return new Gerror(303, $this->Uri);
}
 */

        if (empty($_REQUEST[$cred[0]]) && empty($_REQUEST[$cred[1]])) {
            return new Gerror(1026);
        } elseif (empty($_REQUEST[$cred[0]])) {
			$_REQUEST[$cred[0]] = null;
		} elseif (empty($_REQUEST[$cred[1]])) {
			$_REQUEST[$cred[1]] = null;
		}

// Credential = [code, error] MUST be fore oauth
        $err = $this->Authenticate($_REQUEST[$cred[0]], $_REQUEST[$cred[1]]);
        if ($err != null) {
            return $err;
        }

        return $this->Handler_fields();
    }

    public function Handler_fields(): ?Gerror
    {
        $role = $this->role_obj;
        $fields = array();
        foreach ($role->{"Attributes"} as $i => $v) {
            if (empty($this->Out_hash[$v])) {
				if ($i===0) { return new Gerror(1032); }
                continue;
            }
            $fields[$i] = $this->Out_hash[$v];
        }

        $signed = $this->Signature($fields);
        $this->Set_cookie($role->{"Surface"}, $signed);
        $this->Set_cookie_session($role->{"Surface"} . "_", $signed);
		return new Gerror(303, $this->Uri);
/*
        if (isset($this->tag_obj->{"Case"}) && $this->tag_obj->{"Case"} > 0) {
            return new Gerror(200, $chartag->{"Logged"});
        }
        return new Gerror(303, $this->Uri);
*/
    }

    public function Authenticate(string $login=null, string $password=null): ?Gerror
    {
        $issuer = $this->Get_issuer();
        if (empty($issuer->{"Provider_pars"}) || $login !== $issuer->{"Provider_pars"}->{"Def_login"} || $password !== $issuer->{"Provider_pars"}->{"Def_password"}) {
            return new Gerror(1031);
        }

        $this->role_obj->{"Attributes"} = array("login", "provider");
        $this->Out_hash = array("login" => $issuer->{"Provider_pars"}->{"Def_login"}, "provider" => $this->Provider);

        return null;
    }

    public function Get_issuer(): object
    {
        return $this->role_obj->{"Issuers"}->{$this->Provider};
    }

    public function Get_provider(): string
    {
        $one = "";
        foreach ($this->role_obj->{"Issuers"} as $key => $val) {
            if (isset($val->{"Default"})) {
                return $key;
            }
            $one = $key;
        }
        return $one;
    }

}
