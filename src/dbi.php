<?php
declare (strict_types = 1);

namespace Genelet;

include_once 'error.php';

class Dbi
{
    public $Conn;
    public $Last_id;
    public $Affected;

    public function __construct(\PDO $pdo)
    {
        $this->Conn = $pdo;
    }

    private function errstr(): string
    {
        return implode("; ", $this->Conn->errorInfo());
    }
    private function errsmt(object $sth): string
    {
        return implode("; ", $sth->errorInfo());
    }

    public function Exec_sql(string $sql): ?Gerror
    {
        $n = $this->Conn->exec($sql);
        if ($n === false) {return new Gerror(1071, $this->errstr());}
        $this->Affected = $n;
        return null;
    }

    public function Do_sql(string $sql, ...$args): ?Gerror
    {
        $sth = $this->Conn->prepare($sql);
        if ($sth === false) {return new Gerror(1071, $this->errstr());}
        $result = $sth->execute($args);
        if ($result === false) {return new Gerror(1072, self::errsmt($sth));}

        $this->Last_id = intval($this->Conn->lastInsertId());
        $sth->closeCursor();
        return null;
    }

    public function Do_sqls(string $sql, ...$args): ?Gerror
    {
        $sth = $this->Conn->prepare($sql);
        if ($sth === false) {return new Gerror(1071, $this->errstr());}
        foreach ($args as $item) {
            $result = $sth->execute($item);
            if ($result === false) {return new Gerror(1072, self::errsmt($sth));}
            $this->Last_id = intval($this->Conn->lastInsertId());
        }
        $sth->closeCursor();
        return null;
    }

    public function Get_args(array &$res, string $sql, ...$args): ?Gerror
    {
        $lists = array();
        $err = $this->Select_sql($lists, $sql, ...$args);
        if ($err != null) {return $err;}
        if (sizeof($lists) === 1) {
            foreach ($lists[0] as $k => $v) {
                $res[$k] = $v;
            }
        }
        return null;
    }

    public function Get_sql_label(array &$res, array $select_labels, string $sql, ...$args): ?Gerror
    {
        $lists = array();
        $err = $this->Select_sql_label($lists, $select_labels, $sql, ...$args);
        if ($err != null) {return $err;}
        if (sizeof($lists) === 1) {
            foreach ($lists[0] as $k => $v) {
                $res[$k] = $v;
            }
        }
        return null;
    }

    public function Select_sql(array &$lists, string $sql, ...$args): ?Gerror
    {
        $sth = $this->Conn->prepare($sql);
        if ($sth === false) {return new Gerror(1071, $this->errstr());}
        $result = $sth->execute($args);
        if ($result === false) {
			return new Gerror(1072, $this->errstr());
		}
        $lists = $sth->fetchAll(\PDO::FETCH_ASSOC);
        if ($lists === false) {return new Gerror(1073, self::errsmt($sth));}
        $sth->closeCursor();
        return null;
    }

    public function Select_sql_label(array &$lists, array $select_labels, string $sql, ...$args): ?Gerror
    {
        $sth = $this->Conn->prepare($sql, array(\PDO::ATTR_CURSOR => \PDO::CURSOR_SCROLL));
        if ($sth == false) {return new Gerror(1071, $this->errstr());}
        $result = $sth->execute($args);
        if ($result === false) {
			return new Gerror(1072, $this->errstr());
		}
        while ($row = $sth->fetch(\PDO::FETCH_NUM, \PDO::FETCH_ORI_NEXT)) {
            $item = array();
            foreach ($select_labels as $i => $key) {
                $item[$key] = $row[$i];
            }
            array_push($lists, $item);
        }
        $sth = null;
        return null;
    }

    public function Do_proc(string $proc_name, ...$args): ?Gerror
    {
        $n = sizeof($args);
        $str = "CALL " . $proc_name . "(" . implode(',', array_fill(0, $n, '?'));
        $str .= ")";

        return $this->Do_sql($str, ...$args);
    }

    public function Do_proc_label(array &$hash, array $names, string $proc_name, ...$args): ?Gerror
    {
        $n = sizeof($args);
        $str = "CALL " . $proc_name . "(" . implode(',', array_fill(0, $n, '?'));
        $str_n = "@" . implode(", @", $names);
        $str .= ", " . $str_n . ")";

        $err = $this->Do_sql($str, ...$args);
        if ($err != null) {return $err;}
        return $this->Get_sql_label($hash, $names, "SELECT " . $str_n);
    }

    public function Select_proc_label(array &$lists, array $select_labels, string $proc_name, ...$args): ?Gerror
    {
        $n = sizeof($args);
        $str = "CALL " . $proc_name . "(" . implode(',', array_fill(0, $n, '?'));
        $str .= ")";

        return $this->Select_sql_label($lists, $select_labels, $str, ...$args);
    }

    public function Select_do_proc_label(array &$lists, array $select_labels, array &$hash, array $names, string $proc_name, ...$args): ?Gerror
    {
        $n = sizeof($args);
        $str = "CALL " . $proc_name . "(" . implode(',', array_fill(0, $n, '?'));
        $str_n = "@" . implode(", @", $names);
        $str .= ", " . $str_n . ")";

        $err = $this->Select_sql_label($lists, $select_labels, $str, ...$args);
        if ($err != null) {return $err;}

        return $this->Get_sql_label($hash, $names, "SELECT " . $str_n);
    }
}
