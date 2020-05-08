<?php
declare (strict_types = 1);

namespace Genelet;

class Dbi
{
    public $Conn;
    public $Last_id;
    public $Affected;
	public $logger;

    public function __construct(\PDO $pdo, Logger $logger = null)
    {
        $this->Conn = $pdo;
		$this->Conn->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_SILENT);
		if (isset($logger)) $this->logger = $logger;
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
if (isset($this->logger)) { $this->logger->info($sql); }
        $n = $this->Conn->exec($sql);
        if ($n === false) {return new Gerror(1071, $this->errstr());}
        $this->Affected = $n;
        return null;
    }

    public function Do_sql(string $sql, ...$args): ?Gerror
    {
if (isset($this->logger)) { $this->logger->info($sql, $args); }
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
if (isset($this->logger)) { $this->logger->info($sql, $args); }
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
if (isset($this->logger)) { $this->logger->info($sql, $args); }
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
if (isset($this->logger)) { $this->logger->info($sql, $args); }
        $sth = $this->Conn->prepare($sql, array(\PDO::ATTR_CURSOR => \PDO::CURSOR_SCROLL));
        if ($sth == false) {return new Gerror(1071, $this->errstr());}
        $result = $sth->execute($args);
        if ($result === false) {
            return new Gerror(1072, $this->errstr());
        }
        $is_map = count(array_filter(array_keys($select_labels),'is_string'))>0;
        $xs = array();
        $i = 0;
        foreach ($select_labels as $k => $v) {
            if ($is_map) {
                // PDO::PARAM_BOOL (integer) PDO::PARAM_NULL (integer) PDO::PARAM_INT (integer) PDO::PARAM_STR (integer) PDO::PARAM_STR_NATL (integer) PDO::PARAM_STR_CHAR (integer) PDO::PARAM_LOB (integer) PDO::PARAM_INPUT_OUTPUT (integer)
                $sth->bindColumn($i+1, $xs[$i], $v);
            } else {
                $sth->bindColumn($i+1, $xs[$i]);
            }
            $i++;
        }
        while ($row = $sth->fetch(\PDO::FETCH_ASSOC, \PDO::FETCH_ORI_NEXT)) {
            $item = array();
            $i = 0;
            foreach ($select_labels as $k => $v) {
                if ($is_map) {
                    $item[$k] = $xs[$i];
                } else {
                    $item[$v] = $xs[$i];
                }
                $i++;
            }
            // array_push only pushes references, push $labels directly makes it contain only the last item, many times
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
