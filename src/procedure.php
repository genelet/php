<?php
declare (strict_types = 1);

namespace Genelet;

class Procedure extends Ticket
{
    protected $dbi;

    public function __construct(Dbi $d, string $uri=null, object $c, string $r, string $t, string $p = null)
    {
        $this->dbi = $d;
        parent::__construct($uri, $c, $r, $t, $p);
    }

    public function Run_sql(string $call_name, ...$in_vals): ?Gerror
    {
        $issuer = $this->Get_issuer();
        if (($issuer->screen & 1) != 0) {
            $in_vals = array_push($in_vals, ip2long($this->Get_ip()));
        }
        if (($issuer->screen & 2) != 0 && !empty($this->Uri)) {
            $in_vals = array_push($in_vals, $this->Uri);
        }
        // if ($issuer->screen & 4) !=0 {$in_vals= array_push($in_vals, $this->Get_ua())}
        // if ($issuer->screen & 8) !=0 {$in_vals= array_push($in_vals, $this->Get_referer())}
        $out_pars = empty($issuer->out_pars) ? $this->role_obj->attributes : $issuer->out_pars;
        $this->Out_hash = array();
        return (strtolower(substr($call_name, 0, 7)) === "select ") ?
        $this->dbi->Get_sql_label($this->Out_hash, $out_pars, $call_name, ...$in_vals) :
        $this->dbi->Do_proc_label($this->Out_hash, $out_pars, $call_name, ...$in_vals);
    }

    public function Authenticate(string $login=null, string $passwd=null): ?Gerror
    {
        $issuer = $this->Get_issuer();
        return $this->Run_sql($issuer->sql, $login, $passwd);
    }

    public function Authenticate_as(string $login): ?Gerror
    {
        $issuer = $this->Get_issuer();
        return $this->Run_sql($issuer->sql_as, $login);
    }

    public function Callback_address(): string
    {
        $http = "http";
        if (isset($_SERVER["HTTPS"])) {
            $http .= "s";
        }
        return $http . "://" . $_SERVER["HTTP_HOST"] . $this->script . "/" . $this->Role_name . "/" . $this->Tag_name . "/" . $this->Provider . "?" . $this->go_uri_name . "=" . urlencode($this->Uri);
    }

    public function Fill_provider(array $back): ?Gerror
    {
        $issuer = $this->Get_issuer();
        $in_vals = array();
        foreach ($issuer->in_pars as $par) {
            if (!empty($back[$par])) {
                $in_vals = array_push($in_vals, $back[$par]);
            }
        }

        $err = $this->Run_sql($issuer->sql, $in_vals);
        if ($err != null) {return $err;}

        foreach ($this->role_obj->sttributes as $key) {
            if (empty($this->Out_hash[$key])) {
                $this->Out_hash[$key] = $back[$key];
            }
        }

        return null;
    }
}
