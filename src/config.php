<?php
declare (strict_types = 1);

namespace Genelet;

class Config
{
    public $config;
    public function __construct(object $c)
    {
        $this->config = $c;

        if (empty($this->config->{"Action_name"})) {
            $this->config->{"Action_name"} = "action";
        }
        if (empty($this->config->{"Role_name"})) {
            $this->config->{"Role_name"} = "role";
        }
        if (empty($this->config->{"Tag_name"})) {
            $this->config->{"Tag_name"} = "tag";
        }
        if (empty($this->config->{"Go_uri_name"})) {
            $this->config->{"Go_uri_name"} = "go_uri";
        }
        if (empty($this->config->{"Go_err_name"})) {
            $this->config->{"Go_err_name"} = "go_err";
        }
        if (empty($this->config->{"Go_probe_name"})) {
            $this->config->{"Go_probe_name"} = "go_probe";
        }
        if (empty($this->config->{"Provider_name"})) {
            $this->config->{"Provider_name"} = "provider";
        }
        if (empty($this->config->{"Login_name"})) {
            $this->config->{"Login_name"} = "login";
        }
        if (empty($this->config->{"Logout_name"})) {
            $this->config->{"Logout_name"} = "logout";
        }
        if (empty($this->config->{"Csrf_name"})) {
            $this->config->{"Csrf_name"} = "csrf_token";
        }
        if (empty($this->config->{"CacheURL_name"})) {
            $this->config->{"CacheURL_name"} = "cache_url";
        }
        if (empty($this->config->{"JsonURL_name"})) {
            $this->config->{"JsonURL_name"} = "json_url";
        }
        if (empty($this->config->{"Ttl"})) {
            $this->config->{"Ttl"} = 3600;
        }
		if (empty($this->config->{"Default_actions"})) {
			$this->config->{"Default_actions"} = json_decode('{"GET":"dashboard", "GET_item":"edit", "PUT":"update", "POST":"insert", "DELETE":"delete"}');
		}

        if (empty($this->config->{"Loginas_name"})) {
            $this->config->{"Loginas_name"} = "loginas";
        }
        if (empty($this->config->{"Roleas_name"})) {
            $this->config->{"Roleas_name"} = "roleas";
        }
        if (empty($this->config->{"Roleas_md5"})) {
            $this->config->{"Roleas_md5"} = "rolemd5";
        }
        if (empty($this->config->{"Roleas_uri"})) {
            $this->config->{"Roleas_uri"} = "roleuri";
        }
    }
	protected function Is_oauth2(string $name) : bool {
		return isset($this->config->{"Oauth2s"}) && array_search($name, $this->config->{"Oauth2s"}) >= 0;
	}
	protected function Is_oauth1(string $name) : bool {
		return isset($this->config->{"Oauth1s"}) && array_search($name, $this->config->{"Oauth1s"}) >= 0;
	}
	protected function Is_login(string $name) : bool {
		return $this->config->{"Login_name"}===$name;
	}
	protected function Is_loginas(string $name) : bool {
		return $this->config->{"Loginas_name"}===$name;
	}
	protected function Is_logout(string $name) : bool {
		return $this->config->{"Logout_name"}===$name;
	}
    protected function Is_json_tag(string $tag_name) : bool {
        if (empty($this->config->{"Chartags"}->{$tag_name})) {
            return false;
        }
        $chartag = $this->config->{"Chartags"}->{$tag_name};
        return isset($chartag->{"Case"}) && $chartag->{"Case"} > 0;
    }
}
