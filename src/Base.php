<?php
declare (strict_types = 1);
namespace Genelet;

class Base extends Config
{
    public $Role_name;
    public $Tag_name;
    protected $role_obj;
    protected $tag_obj;

    public function __construct(object $c, string $rv, string $cv)
    {
        parent::__construct($c);
        $this->Role_name = $rv;
        $this->Tag_name = $cv;
        if ($this->pubrole != $rv) {
		    $this->role_obj = $this->roles[$rv];
        }
        $this->tag_obj = $this->chartags[$cv];
    }

	public function Get_role() {
		return $this->role_obj;
	}

	public function Is_admin() : bool {
		if ($this->Is_public()===true) {return false;}
		return $this->role_obj->is_admin;
	}

	public function Is_public() : bool {
		return $this->pubrole == $this->Role_name;
	}

	public function Is_normal_role() : bool {
		if ($this->Is_public()===true || $this->Is_admin()===true) {return false;}
		return !empty($this->role_obj);
	}

	public function Is_json() : bool {
		return parent::Is_json_tag($this->Tag_name);
	}

    public function Get_idname(): string {
		return $this->role_obj->idname;
	}

    public function Get_ip(): string
    {
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }

	public function Get_ua(): string {
		return $_SERVER['HTTP_USER_AGENT'];
	}

    private function _set_cookie(string $name, string $value, int $current) : void
	{
		if ($this->Is_public()) { return; }
		$role = $this->role_obj;
        $domain = empty($role->domain) ? $_SERVER["HTTP_HOST"] : $role->domain;
		$_COOKIE["SET_COOKIE"][$name] = $value; // cli to get headers_list()
		$exp = ($current>0) ? $current+$role->duration : $current;
        setcookie($name, $value, $exp, $role->path, $domain);
    }

    public function Set_cookie(string $name, string $value) : void
    {
		$this->_set_cookie($name, $value, intval($_SERVER["REQUEST_TIME"]));
    }

    public function Set_cookie_session(string $name, string $value) : void
    {
        $this->_set_cookie($name, $value, 0);
    }

    public function Set_cookie_expire(string $name) : void
    {
        $this->_set_cookie($name, "0", -365 * 24 * 3600);
    }

    public function Handler_logout(): string
    {
        $role = $this->role_obj;
        $this->Set_cookie_expire($role->surface);
        $this->Set_cookie_expire($role->surface . "_");
        $this->Set_cookie_expire($this->go_probe_name);
        return $role->logout;
    }

	static public function base64_encode_url(string $string) : string {
    	return str_replace(['+','/','='], ['-','_',''], base64_encode($string));
	}

	static public function base64_decode_url(string $string) : string {
    	return base64_decode(str_replace(['-','_'], ['+','/'], $string));
	}
}
