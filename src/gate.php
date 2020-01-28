<?php
declare (strict_types = 1);

namespace Genelet;

class Gate extends Access
{
    public function Forbid(): ?Gerror
    {
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
		if (!empty($first)) {
			$redirect .= "&" . $this->provider_name . "=$first";
		}
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
}
