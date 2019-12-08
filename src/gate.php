<?php
declare (strict_types = 1);

namespace Genelet;

include_once 'access.php';

class Gate extends Access
{
    public function Forbid(): ?Gerror
    {
        $error = $this->Verify_cookies();
        if ($error === null) { // security passed
            return null;
        }

		if ($this->Is_json()) {
            return new Gerror(200, $this->tag_obj->challenge);
        }

        $escaped = urlencode($_SERVER["REQUEST_URI"]);
        $this->Set_cookie_session($this->go_probe_name, $escaped);
        $this->Set_cookie_expire($this->role_obj->surface);
        $oauth = "";
        $default = "";
        $first = "";
        foreach ($this->role_obj->issuers as $k => $issuer) {
			if ($this->Is_oauth1($k) || $this->Is_oauth2($k)) {
                if (empty($oauth)) {$oauth = $k;}
            } else {
                if (empty($first)) {$first = $k;}
                if ($issuer->default) {
                    $default = $k;
                }
            }
        }
        if (!empty($default)) {$first = $default;}
        $redirect = $this->script . "/" . $this->Role_name . "/" . $this->Tag_name . "/";
		$redirect .= empty($first) ? $oauth : $this->login_name;
        $redirect .= "?" .  $this->go_uri_name . "=" . $escaped . "&" . $this->go_err_name . "=1025";
        return new Gerror(303, $redirect);
    }

    public function Handler_logout(): ?Gerror
    {
        $role = $this->role_obj;
        $this->Set_cookie_expire($role->surface);
        $this->Set_cookie_expire($role->surface . "_");
        $this->Set_cookie_expire($this->go_probe_name);

        return new Gerror(303, $role->logout);
    }

    public function Get_attribute(string $key, string &$value): ?Gerror
    {
		$ref = array();	
        $err = $this->Get_attributes($ref);
		if ($err != null) { return $err; }
		$value = $ref[$key];
		return null;
    }

    public function Get_attributes(array &$ref): ?Gerror
    {
        $a = $this->get_cookie();
        if ($a[5] != null) {
            return $a[5];
        }
        $groups = explode("|", $a[2]);

        foreach ($this->role_obj->attributes as $i => $attr) {
            if ($i == 0) {
                $ref[$attr] = $a[1];
            } elseif (sizeof($groups) >= $i) {
                $ref[$attr] = $groups[$i - 1];
            }
        }

        return null;
    }

    public function Set_attribute(string $key, string $value): ?Gerror
    {
        return $this->Set_attributes(array($key => $value));
    }

    public function Set_attributes(array $ref): ?Gerror
    {
        $role = $this->role_obj;
        $a = $this->get_cookie();
        if ($a[5] != null) {
            return $a[5];
        }
        $ip = $a[0];
        $login = $a[1];
        $group = $a[2];
        $when = $a[3];
        $hash = $a[4];

        $groups = explode("|", $a[2]);
        $attrs = $role->attributes;
        $n = sizeof($attrs);
        $new_groups = array();
        for ($i = 1; $i < $n; $i++) {
            $n_value = $ref[$attrs[$i]];
            if (isset($ref[$attrs[$i]])) {
                $new_groups[$i - 1] = $ref[$attrs[$i]];
            } elseif (sizeof($groups) >= $i) {
                $new_groups[$i - 1] = $groups[$i - 1];
            } else {
                $new_groups[$i - 1] = "";
            }
        }

        $signed = $this->signed($ip, $login, $new_groups, $when);
        $this->Set_cookie($role->surface, $signed);
        $this->Set_cookie_session($role->surface . "_", $signed);

        return null;
    }
}
