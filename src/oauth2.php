<?php
declare (strict_types = 1);

namespace Genelet;

include "procedure.php";

class Oauth2 extends Procedure
{
    protected $Defaults;
    protected $Access_token;

    public function __constructor(Dbi $d, string $uri=null, object $c, string $r, string $t, string $p = null)
    {
        parent::__constructor($d, $uri, $c, $r, $t, $p);
        $a = array();
        switch ($this->Provider) {
            case "google":
                $a["scope"] = "profile";
                $a["response_type"] = "code";
                $a["grant_type"] = "authorization_code";
                $a["authorize_url"] = "https://accounts.google.com/o/oauth2/auth";
                $a["access_token_url"] = "https://accounts.google.com/o/oauth2/token";
                $a["endpoint"] = "https://www.googleapis.com/oauth2/v1/userinfo";
            case "facebook":
                $a["scope"] = "public_profile%20email";
                $a["authorize_url"] = "https://www.facebook.com/dialog/oauth";
                $a["access_token_url"] = "https://graph.facebook.com/oauth/access_token";
                $a["endpoint"] = "https://graph.facebook.com/me";
                $a["fields"] = "id,email,name,first_name,last_name,age_range,gender";
            case "linkedin":
                $a["scope"] = "r_basicprofile";
                $a["authorize_url"] = "https://www.linkedin.com/oauth/v2/authorization";
                $a["access_token_url"] = "https://www.linkedin.com/oauth/v2/accessToken";
                $a["grant_type"] = "authorization_code";
                $a["endpoint"] = "https://api.linkedin.com/v1/people/~";
            case "qq":
                $a["scope"] = "get_user_info";
                $a["authorize_url"] = "https://graph.qq.com/oauth2.0/authorize";
                $a["access_token_url"] = "https://graph.qq.com/oauth2.0/token";
                $a["grant_type"] = "authorization_code";
                $a["endpoint"] = "https://graph.qq.com/user/get_user_info";
                $a["fields"] = "nickname, gender";
            case "microsoft":
                $a["response_type"] = "code";
                $a["scope"] = "wl.basic%20wl.offline_access%20wl.emails%20wl.skydrive";
                $a["authorize_url"] = "https://oauth.live.com/authorize";
                $a["access_token_url"] = "https://oauth.live.com/token";
                $a["grant_type"] = "authorization_code";
                $a["token_method_get"] = "1";
                $a["endpoint"] = "https://apis.live.net/v5.0/me";
            case "salesforce":
                $a["response_type"] = "code";
                $a["grant_typ"] = "authorization_code";
                $a["authorize_url"] = "https://login.salesforce.com/services/oauth2/authorize";
                $a["access_token_url"] = "https://login.salesforce.com/services/oauth2/token";
                $a["endpoint"] = "https://login.salesforce.com/id/";
            default:
        }

        $issuer = $args[0]->Get_issuer();
        foreach ($issuer->{"Provider_pars"} as $k => $v) {
            $a[$k] = $v;
        }
        $this->Defaults = $a;
    }

// Credential MUST be [code, error]
    public function Authenticate(string $login=null, string $password=null): ?Gerror
    {
        $defaults = $this->Defaults;
        if (empty($defaults["state"])) {
            $defaults["state"] = $_SERVER["REQUEST_TIME"];
        }
        $cbk = $this->Callback_address();

        if (empty($login)) {
            if (empty($password)) {
                return new Gerror(400);
            }
            $dest = $defaults["authorize_url"] . "?client_id=" . $defaults["client_id"] . "&redirect_uri=" . urlencode($cbk);
            foreach (array("scope", "display", "state", "response_type", "access_type", "approval_prompt") as $k) {
                if (isset($defaults[$k])) {
                    $dest .= "&" . $k . "=" . $defaults[$k];
                }
            }
            return new Gerror(303, $dest);
        }

        $form = array(
            "code" => $login,
            "client_id" => $defaults["client_id"],
            "client_secret" => $defaults["client_secret"],
            "redirect_uri" => $cbk);
        if (isset($defaults["grant_type"])) {
            $form["grant_type"] = $defaults["grant_type"];
        }

        $client = new GuzzleHttp\Client();
        $res = isset($defaults["token_method_get"]) ?
        $client->request('GET', $defaults["access_token_url"]) :
        $client->request("POST", $defaults["access_token_url"], $form);
        if ($res->getStatusCode() != 200) {
            return new Gerror($res->getStatusCode());
        }
        $body = $res->getBody();

        $back = array();
        switch ($this->Provider) {
            case "facebook":
                $m = parse_url($body);
                if ($m === false) {return new Gerror(1400);}
                $back["access_token"] = $m["access_token"];
                $back["expires"] = $m["expires"];
            default:
                $ret = json_decode($body);
                if ($ret === null) {return new Gerror(1400);}
                foreach ($ret as $k => $v) {
                    $back[$k] = $v;
                }
        }
        if (empty($back["access_token"])) {return new Gerror(1401);}
        $this->Access_token = $back->{"access_token"};

        $endpoint = $defaults["endpoint"];
        if ($this->Provider === "salesforce") {
            $endpoint = $back["id"];
        }
        if (isset($endpoint)) {
            $form = array();
            foreach ($back as $k => $v) {
                if ($k === "access_token") {continue;}
                $form->{$k} = $v;
            }
            if ($this->Provider === "facebook") {
                $form["fields"] = $defaults["fields"];
            }

            $h = array();
            if ($this->Provider === "linkedin") {
                $h["x-li-format"] = "json";
            }

            $back1 = array();
            $err = $this->Oauth2_api($back1, "GET", $endpoint, $form, $h);
            if ($err != null) {return $err;}
            foreach ($back1 as $k => $v) {
                $back[$k] = $v;
            }
        }

        foreach ($defaults as $k => $v) {
            if (empty($back[$k])) {
                $back[$k] = $v;
            }
        }

        return $this->Fill_provider($back);
    }

    private function oauth2_request(string $method, string $uri, array $form, array $h): object
    {
        $client = new GuzzleHttp\Client();
        if (isset($this->Defaults["grant_type"]) && $this->Defaults["grant_type"] === "authorization_code") {
            $h["Authorization"] = "Bearer " . $this->Access_token;
        } else {
            $form["access_token"] = $this->Access_token;
        }
        return $client->request($method, $uri, $form, $h);
    }

    public function Oauth2_api(object &$json, string $method, string $uri, array $form, array $h): ?Gerror
    {
        $res = $this->oauth2_request($method, $uri, $form, $h);
        if ($res->getStatusCode() != 200) {
            return new Gerror($res->getStatusCode());
        }

        $body = $res->getBody();
        if (isset($body)) {
            $json = json_decode($body);
        }
        return null;
    }

}
