<?php
declare (strict_types = 1);

namespace Genelet;

class Access extends Base
{
	public $Decoded;
	public $Endtime=0;
	public $Raw;

// https://www.php.net/manual/en/function.openssl-encrypt.php
    public function Encode(string $str) : string {
		$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
		$iv = openssl_random_pseudo_bytes($ivlen);
		$key = $this->role_obj->coding;
		$ciphertext_raw = openssl_encrypt($str, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
		$hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
        return str_replace(['+','/','='], ['-','_',''], base64_encode($iv.$hmac.$ciphertext_raw));
    }

    public function Decode(string $str) : ?string {
        $c = base64_decode(str_replace(['-','_'], ['+','/'], $str));

		$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
		$iv = substr($c, 0, $ivlen);
		$hmac = substr($c, $ivlen, $sha2len=32);
		$ciphertext_raw = substr($c, $ivlen+$sha2len);
		$key = $this->role_obj->coding;
		$original = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
		if (hash_equals($hmac, hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true)))//PHP 5.6+ timing attack safe comparison
		{
			return $original;
		}
		return null;
    }

    public function Digest(string $str) : string {
        //return str_replace(['+','/','='], ['-','_',''], base64_encode(sha1($this->role_obj->secret.$this->Endtime.$str)));
        return str_replace(['+','/','='], ['-','_',''], base64_encode(hash_hmac('sha256', $str . $this->Endtime, $this->role_obj->secret, true)));
    }

    public function Token(int $stamp, string $str) : string {
        return str_replace(['+','/','='], ['-','_',''], base64_encode(pack("L", $stamp).hash_hmac('sha256', $str . $this->Endtime . strval($stamp), $this->role_obj->secret, true)));
    }

    public static function Get_tokentime(string $str) : int {
		$arr = unpack("L1stamp", base64_decode(str_replace(['-','_'], ['+','/'], $str)));
		return $arr["stamp"];
	}

    public function Set_ip(): string
    {
        $ip = $this->Get_ip();
        if ($this->role_obj->length>0) {
            $a = explode(".", $ip);
            $full = sprintf("%02X%02X%02X%02X", $a[0], $a[1], $a[2], $a[3]);
            $ip = substr($full, 0, $this->role_obj->length);
        }
        return $ip;
    }

    public function Signature(array $fields): string
    {
        $login = array_shift($fields);
		$this->Endtime = $_SERVER["REQUEST_TIME"] + $this->role_obj->duration;
        return $this->signed($this->Set_ip(), $login, $fields, sprintf("%d", $this->Endtime));
    }

    protected function signed(string $ip, string $login, array $groups, string $when): string
    {
        $str_group = join("|", $groups);
        $hash = $this->Digest($ip. $login. $str_group);
        //return Scoder::Encode_scoder(join("/", array($ip, $login, $str_group, $when, $hash)), $this->role_obj->coding);
		return $this->Encode(join("/", array($ip, $login, $str_group, $when, $hash)));
    }

    public function Forbid(): string
    {
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
        return $redirect;
    }

    public function Verify_cookie(string ...$raws): ?Gerror
    {
        $role = $this->role_obj;
        $raw = "";
        if (empty($raws)) {
			$header = null;
			if (isset($_SERVER['Authorization'])) {
				$header = trim($_SERVER["Authorization"]);
			} else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
				$header = trim($_SERVER["HTTP_AUTHORIZATION"]);
			} elseif (function_exists('apache_request_headers')) {
				$requestHeaders = apache_request_headers();
				$requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
				if (isset($requestHeaders['Authorization'])) {
					$headers = trim($requestHeaders['Authorization']);
				}
			}
			if ($header != null && substr($header, 0, 7) == 'Bearer ') {
				$raw = substr($header, 7);
			} else if (!empty($_COOKIE[$role->surface])) {
            	$raw = $_COOKIE[$role->surface];
			} else {
                return new Gerror(1020);
            }
        } else {
            $raw = $raws[0];
        }

        $value = $this->Decode($raw);
		if ($value===null) {return new Gerror(1021);}
        //$value = Scoder::Decode_scoder($raw, $role->coding);
        $x = explode("/", $value);
        if (sizeof($x) < 5) {
            return new Gerror(1022);
        }
        $ip = $x[0];
        $login = $x[1];
        $group = urldecode($x[2]);
        $groups = explode("|", $group);
		$this->Decoded = array();
        foreach ($role->attributes as $i => $attr) {
            if ($i == 0) {
                $this->Decoded[$attr] = $login;
            } elseif (sizeof($groups) >= $i) {
                $this->Decoded[$attr] = $groups[$i - 1];
            }
        }
        $when = intval($x[3]);
		$this->Endtime = $when;
        $hash = $x[4];
		$this->Raw = array($ip, $login, $group, $when, $hash);
        if ($role->length>0 && $this->Set_ip() != $ip) {
            return new Gerror(1023);
        }
        if ($_SERVER["REQUEST_TIME"] > $when) {
            return new Gerror(1024);
        }
		
        if (!empty($role->userlist) && array_search($login, $role->userlist) === false) {
            return new Gerror(1025);
        }

        if ($this->Digest($ip. $login. $group) != $hash) {
            return new Gerror(1026);
        }

        return null;
    }
}
