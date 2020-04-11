<?php
declare (strict_types = 1);

namespace Genelet;
use GuzzleHttp\Client;

class Oauth2 extends Procedure
{
    public $Defaults;
    protected $Access_token;

    public function __construct(Dbi $d, string $uri=null, object $c, string $r, string $t, string $p = null)
    {
        parent::__construct($d, $uri, $c, $r, $t, $p);

        $a = array();
        switch ($this->Provider) {
        case "google":
            $a["scope"] = "profile";
            $a["response_type"] = "code";
            $a["grant_type"] = "authorization_code";
            $a["authorize_url"] = "https://accounts.google.com/o/oauth2/auth";
            $a["access_token_url"] = "https://accounts.google.com/o/oauth2/token";
            $a["endpoint"] = "https://www.googleapis.com/oauth2/v1/userinfo";
			break;
        case "facebook":
            $a["scope"] = "public_profile%20email";
            $a["authorize_url"] = "https://www.facebook.com/dialog/oauth";
            $a["access_token_url"] = "https://graph.facebook.com/oauth/access_token";
            $a["endpoint"] = "https://graph.facebook.com/me";
            $a["fields"] = "id,email,name,first_name,last_name,age_range,gender";
			break;
        case "linkedin":
            $a["scope"] = "r_basicprofile";
            $a["authorize_url"] = "https://www.linkedin.com/oauth/v2/authorization";
            $a["access_token_url"] = "https://www.linkedin.com/oauth/v2/accessToken";
            $a["grant_type"] = "authorization_code";
            $a["endpoint"] = "https://api.linkedin.com/v1/people/~";
			break;
        case "qq":
            $a["scope"] = "get_user_info";
            $a["authorize_url"] = "https://graph.qq.com/oauth2.0/authorize";
            $a["access_token_url"] = "https://graph.qq.com/oauth2.0/token";
            $a["grant_type"] = "authorization_code";
            $a["endpoint"] = "https://graph.qq.com/user/get_user_info";
            $a["fields"] = "nickname,gender";
			break;
        case "microsoft":
            $a["response_type"] = "code";
            $a["scope"] = "wl.basic,wl.offline_access,wl.emails,wl.skydrive";
            $a["authorize_url"] = "https://oauth.live.com/authorize";
            $a["access_token_url"] = "https://oauth.live.com/token";
            $a["grant_type"] = "authorization_code";
            $a["token_method_get"] = "1";
            $a["endpoint"] = "https://apis.live.net/v5.0/me";
			break;
        case "salesforce":
            $a["response_type"] = "code";
            $a["grant_typ"] = "authorization_code";
            $a["authorize_url"] = "https://login.salesforce.com/services/oauth2/authorize";
            $a["access_token_url"] = "https://login.salesforce.com/services/oauth2/token";
            $a["endpoint"] = "https://login.salesforce.com/id/";
			break;
        case "github":
			$a["scope"] = "read:user";
            $a["response_type"] = "code";
            $a["grant_typ"] = "authorization_code";
            $a["authorize_url"] = "https://github.com/login/oauth/authorize";
            $a["access_token_url"] = "https://github.com/login/oauth/access_token";
            $a["endpoint"] = "https://api.github.com/user";
			break;
        default:
        }

        $issuer = $this->Get_issuer();
        foreach ($issuer->provider_pars as $k => $v) {
            $a[$k] = $v;
        }
        $this->Defaults = $a;
    }

	public function Build_authorize(string $state=null, string $uri=null, string $saved=null) : ?Gerror
    {
		$defaults = $this->Defaults;
        $cbk = isset($defaults["callback_url"]) ? $defaults["callback_url"] : $this->Callback_address();

        $dest = $defaults["authorize_url"] . "?client_id=" . $defaults["client_id"] . "&redirect_uri=" . urlencode($cbk);
        if (isset($state)) {
            $defaults["state"] = $state;
        }
        foreach (array("scope", "display", "state", "response_type", "access_type", "approval_prompt") as $k) {
            if (isset($defaults[$k])) {
                $dest .= "&" . $k . "=" . urlencode($defaults[$k]);
            }
        }

        $probe_name = $this->go_probe_name;
        if (isset($uri)) {
            $this->Set_cookie_session($probe_name, $uri);
        }
        if (isset($saved)) {
            $this->Set_cookie_session($probe_name."_1", $saved);
        }
        $this->Uri = $dest;

        return new Gerror(303);
    }

// Credential MUST be [code]
    public function Handler(): ?Gerror
    {
        $issuer = $this->Get_issuer();
        $cred = $issuer->credential;
        if (empty($_REQUEST[$cred[0]])) {
            return $this->Build_authorize($_SERVER["REQUEST_TIME"]."");
        }

        $defaults = $this->Defaults;
        $this->Uri = isset($_COOKIE[$this->go_probe_name]) ? $_COOKIE[$this->go_probe_name] : $this->Callback_address();
		$cbk = isset($defaults["callback_url"]) ? $defaults["callback_url"] : $this->Uri;
        $form = array(
            "code" => $_REQUEST[$cred[0]],
            "client_id" => $defaults["client_id"],
            "client_secret" => $defaults["client_secret"],
            "redirect_uri" => $cbk);
        if (isset($_REQUEST["state"])) {
            $form["state"] = $_REQUEST["state"];
        }
        if (isset($defaults["grant_type"])) {
            $form["grant_type"] = $defaults["grant_type"];
        }

        $client = new Client();
        $res = isset($defaults["token_method_get"]) ?
$client->request('GET',  $defaults["access_token_url"], ['http_errors' => false, 'query'=>$form]) :
$client->request("POST", $defaults["access_token_url"], ['headers' => ["accept" => "application/json"], 'http_errors' => false, 'form_params'=>$form]);
#$this->logger->info($res);
$this->logger->info($res->getReasonPhrase());
        if ($res->getStatusCode() != 200) {
            return new Gerror($res->getStatusCode());
        }
        $body = (string)$res->getBody();
        $back = array();

        switch ($this->Provider) {
        case "facebook":
            $m = parse_url($body);
            if ($m === false) {return new Gerror(1400);}
            $back["access_token"] = $m["access_token"];
            $back["expires"] = $m["expires"];
            break;
        default:
            $ret = json_decode($body);
            if ($ret === null) {return new Gerror(1400);}
            foreach ($ret as $k => $v) {
                $back[$k] = $v;
            }
        }
        if (empty($back["access_token"])) {return new Gerror(1401);}
        $this->Access_token = $back["access_token"];

        $endpoint = "";
		if ($this->Provider === "salesforce") {
			$endpoint = $back["id"];
		} elseif (isset($defaults["endpoint"])) {
			$endpoint = $defaults["endpoint"];
		}
        if (!empty($endpoint)) {
            $form = array();
            if ($this->Provider === "facebook") {
                $form["fields"] = $defaults["fields"];
            }
            $h = array("Accept"=>"application/json");
            if ($this->Provider === "linkedin") {
                $h["x-li-format"] = "json";
            } elseif ($this->Provider === "github") {
                $h["Authorization"] = "token ". $this->Access_token;
            }

            $res = $client->request('GET', $endpoint, ['http_errors' => false, 'headers'=>$h, 'query'=>$form]);
$this->logger->info($res->getReasonPhrase());
            if ($res->getStatusCode() != 200) {
                return new Gerror($res->getStatusCode());
            }
            foreach (json_decode((string)$res->getBody()) as $k => $v) {
                $back[$k] = $v;
            }
        }

        foreach ($defaults as $k => $v) {
            if (empty($back[$k])) {
                $back[$k] = $v;
            }
        }
        if (isset($_COOKIE[$probe_name."_1"])) {
            foreach (json_decode($_COOKIE[$probe_name."_1"]) as $k => $v) {
                $back[$k] = $v;
            }
        }

        return $this->Fill_provider($back);
    }
}
