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
            $a["access_type"] = "offline";
            $a["approval_prompt"] = "force";
            $a["endpoint"] = "https://www.googleapis.com/oauth2/v1/userinfo";
			break;
        case "facebook":
            $a["scope"] = "public_profile,email";
            $a["response_type"] = "code";
            $a["authorize_url"] = "https://www.facebook.com/v6.0/dialog/oauth";
            $a["access_token_url"] = "https://graph.facebook.com/v6.0/oauth/access_token";
            $a["endpoint"] = "https://graph.facebook.com/me";
            $a["fields"] = "id,email,first_name,last_name";
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
            $this->Set_cookie_session($probe_name, urlencode($uri));
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
        $this->Uri = isset($_COOKIE[$this->go_probe_name]) ? urldecode($_COOKIE[$this->go_probe_name]) : $this->Callback_address();
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
        $back = json_decode($body, true);
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
			if ($this->Provider === "github") {
                $h["Authorization"] = "token ". $this->Access_token;
            } else {
                $h["Authorization"] = "Bearer ". $this->Access_token;
			}
            if ($this->Provider === "linkedin") {
                $h["x-li-format"] = "json";
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

        $probe_name = $this->go_probe_name;
        if (isset($_COOKIE[$probe_name."_1"])) {
            foreach (json_decode($_COOKIE[$probe_name."_1"]) as $k => $v) {
                $back[$k] = $v;
            }
        }

        return $this->Fill_provider($back);
    }
}

/*
FACEBOOK
    [access_token] => EAAIpCZCs7ehMBANupYjf54PkylySJml3UtcyBTjmruDfPgeyoB0ldr1RoiD7zvjP3dxZBOS5NddoNNcIRA1wDwQvvz0GT4xNgiHHKPF8hfgnuw2Q8JKrVfMiGWWC3ZCwUMsDRetfsMb3yv7AhMZBxUAUsnukSTwZD
    [token_type] => bearer
    [expires_in] => 5183999
    [id] => 10158715393768606
    [email] => tianzhen99@yahoo.com
    [first_name] => Peter
    [last_name] => Bi

GOOGLE
    [access_token] => ya29.a0Ae4lvC0S1TOV3LYMf3aiNWEqO_wfQ1KmxIYMThRI2f4Yw3gjOc8Yt14VVb83tylBuuskdBl2kPp-yy5AokOruEINRFdFuauEreAe69QZA_AYSnOSE3N9JCEfn9jcHDI9z7T2v-vhFZzs1K_zNXdWlAqKf4xvpi0PdEo
    [expires_in] => 3599
    [refresh_token] => 1//0fGSVZsXWcJyyCgYIARAAGA8SNwF-L9Ir6Hyhakp33Pi6MkZsTKwpS2H7tS_wGVlvdMPxRZvKPp-w3PhvFDLVY4Nn3K-8X1ELnFQ
    [scope] => https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid
    [token_type] => Bearer
    [id_token] => eyJhbGciOiJSUzI1NiIsImtpZCI6IjZmY2Y0MTMyMjQ3NjUxNTZiNDg3NjhhNDJmYWMwNjQ5NmEzMGZmNWEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiOTkyNDcyNjAwNTA5LTU2N2xka2IxaGowMXNoYzRmaGJrcXB2bW9vMWg2Mjg0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiOTkyNDcyNjAwNTA5LTU2N2xka2IxaGowMXNoYzRmaGJrcXB2bW9vMWg2Mjg0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTAzNTA1MDQ2MTMwNTU4NzE3Mjg4IiwiZW1haWwiOiJncmVldGluZ2xhbmRAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiJtcEowWmdIZ2dmMExhRUx1UFNlSzFnIiwiaWF0IjoxNTg2NjE2OTQ3LCJleHAiOjE1ODY2MjA1NDd9.DMFSUpVIGnMb8tM7MJSwOtjFb7ev2K9e8YatIDxuix-7wfEx82ItZqcdvO6YZUvGMqE2Fnh9V_q4cCH3w4V6QczdGnCDiTAW8DCj729WC7pCncPJ6h0V-KUd37XMSXKl8BA-0AaVmBCLYxtSiuv_nMh-4ysnsrAC-K9vEgRiRAv_9FZcQvBdFjIuHDbDUQZPeGlweqMHFnFTc8SUyh5Wcd51yyPqZteUEIYWnW6PZRx6kMQQnpwGv84YO5Ct5lAhcgI9MNMHGWFNSfT7jaRRKiJTVHPazO56UDIKUFHCsOqQE0Tj35e4j3F3bPDTX6NFIAqfJMZll1dFDLgK5al9MA
    [id] => 103505046130558717288
    [email] => greetingland@gmail.com
    [verified_email] => 1
    [name] => Peter Bi
    [given_name] => Peter
    [family_name] => Bi
    [picture] => https://lh4.googleusercontent.com/-FmCKmMu0QEo/AAAAAAAAAAI/AAAAAAAAAAA/AAKWJJPgRp4TCmWwq04xVBXXFJRFU-GHEw/photo.jpg
    [locale] => en
    [response_type] => code

GITHUB
    [access_token] => 1306b6ccd64a1be7c7e8a697c5dad9445f77feb1
    [token_type] => bearer
    [scope] => user:email
    [login] => genelet
    [id] => 710562
    [node_id] => MDQ6VXNlcjcxMDU2Mg==
    [avatar_url] => https://avatars3.githubusercontent.com/u/710562?v=4
    [gravatar_id] =>
    [url] => https://api.github.com/users/genelet
    [html_url] => https://github.com/genelet
    [followers_url] => https://api.github.com/users/genelet/followers
    [following_url] => https://api.github.com/users/genelet/following{/other_user}
    [gists_url] => https://api.github.com/users/genelet/gists{/gist_id}
    [starred_url] => https://api.github.com/users/genelet/starred{/owner}{/repo}
    [subscriptions_url] => https://api.github.com/users/genelet/subscriptions
    [organizations_url] => https://api.github.com/users/genelet/orgs
    [repos_url] => https://api.github.com/users/genelet/repos
    [events_url] => https://api.github.com/users/genelet/events{/privacy}
    [received_events_url] => https://api.github.com/users/genelet/received_events
    [type] => User
    [site_admin] =>
    [name] => Peter Bi
    [company] => Greetingland, LLC
    [blog] => http://www.genelet.com
    [location] => Orange County, CA, USA
    [email] => genelet@gmail.com
    [hireable] =>
    [bio] => VP of Technology of EIC & Founder of Greetingland
    [public_repos] => 10
    [public_gists] => 0
    [followers] => 2
    [following] => 1
    [created_at] => 2011-04-05T11:49:56Z
    [updated_at] => 2020-04-11T04:19:51Z
    [response_type] => code
    [grant_typ] => authorization_code
    [authorize_url] => https://github.com/login/oauth/authorize
    [access_token_url] => https://github.com/login/oauth/access_token
    [endpoint] => https://api.github.com/user
    [callback_url] => http://sandy/app.php/a/html/github
    [client_id] => 4348f5e5456a8dc76c83
    [client_secret] => e8edbd7a60ee9e695a833452be88dbb97b2f7832
*/
