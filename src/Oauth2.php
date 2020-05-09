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
        case "zoom":
            $a["scope"] = "user:read:admin";
            $a["response_type"] = "code";
            $a["grant_type"] = "authorization_code";
            $a["authorize_url"] = "https://zoom.us/oauth/authorize";
            $a["access_token_url"] = "https://zoom.us/oauth/token";
            $a["endpoint"] = "https://api.zoom.us/v2/users/me";
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

	public function Build_authorize(string $state=null, string $uri=null) : ?Gerror
    {
		$defaults = $this->Defaults;
        $cbk = $defaults["callback_url"];

        $dest = $defaults["authorize_url"] . "?client_id=" . $defaults["client_id"] . "&redirect_uri=" . urlencode($cbk);
        if (isset($state)) {
            $defaults["state"] = $state;
        }
        foreach (array("scope", "display", "state", "response_type", "access_type", "approval_prompt") as $k) {
            if (isset($defaults[$k])) {
                $dest .= "&" . $k . "=" . urlencode($defaults[$k]);
            }
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
        $landing  = "/";
		if (isset($defaults["landing"])) {
			$landing = $defaults["landing"];
		}
        $this->Uri = $landing;
        $form = array(
            "code" => $_REQUEST[$cred[0]],
            "redirect_uri" => $defaults["callback_url"]);
        if (isset($_REQUEST["state"])) {
            $form["state"] = $_REQUEST["state"];
        }
        if (isset($defaults["grant_type"])) {
            $form["grant_type"] = $defaults["grant_type"];
        }
		$options = ['http_errors' => false];
		if ($this->Provider=="zoom") {
			$options["auth"] = [$defaults["client_id"], $defaults["client_secret"]];
		} else {
			$form["client_id"]     = $defaults["client_id"];
			$form["client_secret"] = $defaults["client_secret"];
		}	

        $client = new Client();
		$m = "POST";
		if (isset($defaults["token_method_get"])) {
			$m = "GET";
			$options['query'] = $form;
		} else {
			$options['form_params'] = $form;
		}
        $res = $client->request($m, $defaults["access_token_url"], $options);
        if ($res->getStatusCode() != 200) {
            if ($body = $res->getBody()) {
                $this->logger->info($body->getContents());
            }
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
            $h["Authorization"] = "Bearer ". $this->Access_token;
            if ($this->Provider === "linkedin") {
                $h["x-li-format"] = "json";
            } 

            $res = $client->request('GET', $endpoint, ['http_errors' => false, 'headers'=>$h, 'query'=>$form]);
            if ($res->getStatusCode() != 200) {
                if ($body = $res->getBody()) {
                    $this->logger->info($body->getContents());
                }
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

ZOOM
{
  "access_token": "eyJhbGciOiJIUzUxMiIsInYiOiIyLjAiLCJraWQiOiI8S0lEPiJ9.eyJ2ZXIiOiI2IiwiY2xpZW50SWQiOiI8Q2xpZW50X0lEPiIsImNvZGUiOiI8Q29kZT4iLCJpc3MiOiJ1cm46em9vbTpjb25uZWN0OmNsaWVudGlkOjxDbGllbnRfSUQ-IiwiYXV0aGVudGljYXRpb25JZCI6IjxBdXRoZW50aWNhdGlvbl9JRD4iLCJ1c2VySWQiOiI8VXNlcl9JRD4iLCJncm91cE51bWJlciI6MCwiYXVkIjoiaHR0cHM6Ly9vYXV0aC56b29tLnVzIiwiYWNjb3VudElkIjoiPEFjY291bnRfSUQ-IiwibmJmIjoxNTgwMTQ2OTkzLCJleHAiOjE1ODAxNTA1OTMsInRva2VuVHlwZSI6ImFjY2Vzc190b2tlbiIsImlhdCI6MTU4MDE0Njk5MywianRpIjoiPEpUST4iLCJ0b2xlcmFuY2VJZCI6MjV9.F9o_w7_lde4Jlmk_yspIlDc-6QGmVrCbe_6El-xrZehnMx7qyoZPUzyuNAKUKcHfbdZa6Q4QBSvpd6eIFXvjHw",
  "token_type": "bearer",
  "refresh_token": "eyJhbGciOiJIUzUxMiIsInYiOiIyLjAiLCJraWQiOiI8S0lEPiJ9.eyJ2ZXIiOiI2IiwiY2xpZW50SWQiOiI8Q2xpZW50X0lEPiIsImNvZGUiOiI8Q29kZT4iLCJpc3MiOiJ1cm46em9vbTpjb25uZWN0OmNsaWVudGlkOjxDbGllbnRfSUQ-IiwiYXV0aGVudGljYXRpb25JZCI6IjxBdXRoZW50aWNhdGlvbl9JRD4iLCJ1c2VySWQiOiI8VXNlcl9JRD4iLCJncm91cE51bWJlciI6MCwiYXVkIjoiaHR0cHM6Ly9vYXV0aC56b29tLnVzIiwiYWNjb3VudElkIjoiPEFjY291bnRfSUQ-IiwibmJmIjoxNTgwMTQ2OTkzLCJleHAiOjIwNTMxODY5OTMsInRva2VuVHlwZSI6InJlZnJlc2hfdG9rZW4iLCJpYXQiOjE1ODAxNDY5OTMsImp0aSI6IjxKVEk-IiwidG9sZXJhbmNlSWQiOjI1fQ.Xcn_1i_tE6n-wy6_-3JZArIEbiP4AS3paSD0hzb0OZwvYSf-iebQBr0Nucupe57HUDB5NfR9VuyvQ3b74qZAfA",
  "expires_in": 3599,
  "scope": "user:read:admin"
}
{
  "id": "KdYKjnimT4KPd8FFgQt9FQ",
  "first_name": "Jane",
  "last_name": "Dev",
  "email": "jane.dev@email.com",
  "type": 2,
  "role_name": "Owner",
  "pmi": 1234567890,
  "use_pmi": false,
  "vanity_url": "https://janedevinc.zoom.us/my/janedev",
  "personal_meeting_url": "https://janedevinc.zoom.us/j/1234567890",
  "timezone": "America/Denver",
  "verified": 1,
  "dept": "",
  "created_at": "2019-04-05T15:24:32Z",
  "last_login_time": "2019-12-16T18:02:48Z",
  "last_client_version": "4.6.12611.1124(mac)",
  "pic_url": "https://janedev.zoom.us/p/KdYKjnimFR5Td8KKdQt9FQ/19f6430f-ca72-4154-8998-ede6be4542c7-837",
  "host_key": "533895",
  "jid": "kdykjnimt4kpd8kkdqt9fq@xmpp.zoom.us",
  "group_ids": [],
  "im_group_ids": [
    "3NXCD9VFTCOUH8LD-QciGw"
  ],
  "account_id": "gVcjZnYYRLDbb_MfgHuaxg",
  "language": "en-US",
  "phone_country": "US",
  "phone_number": "+1 1234567891",
  "status": "active"
}

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
    [email] => gd@gmail.com
    [verified_email] => 1
    [name] => Pe Be
    [given_name] => Pe
    [family_name] => Be
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
    [name] => Pe Be
    [company] => Grend, LLC
    [blog] => http://www.genelet.com
    [location] => Orange County, CA, USA
    [email] => g@gmail.com
    [hireable] =>
    [bio] => tingland
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
*/
