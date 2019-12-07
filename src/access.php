<?php
declare (strict_types = 1);

namespace Genelet;

include_once 'base.php';
//include 'scoder.php';
include 'randint.php';

class Access extends Base
{
	public $Decoded;
	public $Endtime=0;

// https://www.php.net/manual/en/function.openssl-encrypt.php
    public function Encode(string $str) : string {
		$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
		$iv = openssl_random_pseudo_bytes($ivlen);
		$key = $this->role_obj->{"Coding"};
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
		$key = $this->role_obj->{"Coding"};
		$original = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
		if (hash_equals($hmac, hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true)))//PHP 5.6+ timing attack safe comparison
		{
			return $original;
		}
		return null;
    }

    public function Digest(string $str) : string {
        //return str_replace(['+','/','='], ['-','_',''], base64_encode(sha1($this->role_obj->{"Secret"}.$this->Endtime.$str)));
        return str_replace(['+','/','='], ['-','_',''], base64_encode(hash_hmac('sha256', $str . $this->Endtime, $this->role_obj->{"Secret"}, true)));
    }

    public function Token(int $stamp, string $str) : string {
        return str_replace(['+','/','='], ['-','_',''], base64_encode(pack("L", $stamp).hash_hmac('sha256', $str . $this->Endtime . strval($stamp), $this->role_obj->{"Secret"}, true)));
    }

    public static function Get_tokentime(string $str) : int {
		$arr = unpack("L1stamp", base64_decode(str_replace(['-','_'], ['+','/'], $str)));
		return $arr["stamp"];
	}

    public function Set_ip(): string
    {
        $ip = $this->Get_ip();
        if (isset($this->role_obj->{"Length"})) {
            $a = explode(".", $ip);
            $full = sprintf("%02X%02X%02X%02X", $a[0], $a[1], $a[2], $a[3]);
            $ip = substr($full, 0, $this->role_obj->{"Length"});
        }
        return $ip;
    }

    public function Signature(array $fields): string
    {
        $login = array_shift($fields);
		$this->Endtime = $_SERVER["REQUEST_TIME"] + $this->role_obj->{"Duration"};
        return $this->signed($this->Set_ip(), $login, $fields, sprintf("%d", $this->Endtime));
    }

    protected function signed(string $ip, string $login, array $groups, string $when): string
    {
        $str_group = join("|", $groups);
        $this->get_index_ciper($login, $str_group);
        $hash = $this->Digest($ip. $login. $str_group);
        //return Scoder::Encode_scoder(join("/", array($ip, $login, $str_group, $when, $hash)), $this->role_obj->{"Coding"});
		return $this->Encode(join("/", array($ip, $login, $str_group, $when, $hash)));
    }

    public function get_index_ciper(string &$login, string &$group, int $p_or_n = 1): ?string
    {
        $role = $this->role_obj;
        $n = sizeof($role->{"Attributes"});
        for ($i = 0; $i < $n; $i++) {
            if ($role->{"Attributes"}[$i] === ($role->{"Id_name"}) && isset($role->{"Id_cipher"})) {
                $cipher = hex2bin($role->{"Id_cipher"});
                if ($p_or_n === 1) {
                    if ($i === 0) {
                        $login = encryptInteger(intval($login), $cipher);
                    } else {
                        $groups = explode("|", $group);
                        $groups[$i - 1] = encryptInteger(intval($groups[$i - 1]), $cipher);
                        $group = join("|", $groups);
                    }
                    return null;
                } elseif ($p_or_n === -1) {
                    if ($i === 0) {
                        $orig = $login;
                        $login = decryptInteger($orig, $cipher);
                    } else {
                        $groups = explode("|", $group);
                        $orig = $groups[$i - 1];
                        $groups[$i - 1] = decryptInteger($orig, $cipher);
                        $group = join("|", $groups);
                    }
                    return $orig;
                }
            }
        }
        return null;
    }

    public function get_cookie(string ...$raws): array
    {
        $role = $this->role_obj;
        $raw = "";
        if (empty($raws)) {
            if (empty($_COOKIE[$role->{"Surface"}])) {
                return array("", "", "", "", "", new Gerror(1029));
            }
            $raw = $_COOKIE[$role->{"Surface"}];
        } else {
            $raw = $raws[0];
        }

        $value = $this->Decode($raw);
		if ($value===null) {return array("", "", "", "", "", new Gerror(1020));}
        //$value = Scoder::Decode_scoder($raw, $role->{"Coding"});
        $x = explode("/", $value);
        if (sizeof($x) < 5) {
            return array("", "", "", "", "", new Gerror(1020));
        }
        $ip = $x[0];
        $login = $x[1];
        $group = urldecode($x[2]);
        $groups = explode("|", $group);
		$this->Decoded = array();
        foreach ($role->{"Attributes"} as $i => $attr) {
            if ($i == 0) {
                $this->Decoded[$attr] = $login;
            } elseif (sizeof($groups) >= $i) {
                $this->Decoded[$attr] = $groups[$i - 1];
            }
        }
        $when = intval($x[3]);
		$this->Endtime = $when;
        $hash = $x[4];
        if ($this->Set_ip() != $ip) {
            return array("", "", "", "", "", new Gerror(1023));
        }
        if ($_SERVER["REQUEST_TIME"] > $when) {
            return array("", "", "", "", "", new Gerror(1022));
        }
		
        if (isset($role->{"Userlist"}) && array_search($login, $role->{"Userlist"}) === false) {
            return array("", "", "", "", "", new Gerror(1021));
        }

        if ($this->Digest($ip. $login. $group) != $hash) {
            return array("", "", "", "", "", new Gerror(1024));
        }

        //$this->get_index_cipher($login, $group, -1);
        return array($ip, $login, $group, $when, $hash, null);
    }

    public function Verify_cookies(string $raw = null): ?Gerror
    {
        $a = $this->get_cookie();
        if ($a[5] != null) { // error found
            return $a[5];
        }
		foreach ($this->Decoded as $k => $v) {
			$_REQUEST[$k] = $v;
		}

        return null;
    }
}
