<?php
declare (strict_types = 1);

namespace Genelet;

class Crud extends Dbi
{
    public $Current_table;
    public $Current_tables;

    public function __construct(\PDO $pdo, string $tbl, array $tbls = null, Logger $logger = null)
    {
        parent::__Construct($pdo, $logger);
        $this->Current_table = $tbl;
        if ($tbls != null) {
            $this->Current_tables = $tbls;
        }
    }

    public function Table_string(): string
    {
        $sql = "";
        foreach ($this->Current_tables as $i => $table) {
            $name = $table["name"];
            if (isset($table["alias"])) {
                $name .= " " . $table["alias"];
            }
            if ($i === 0) {
                $sql = $name;
            } elseif (isset($table["using"])) {
                $sql .= "\n" . $table["type"] . " JOIN " . $name . " USING (" . $table["using"] . ")";
            } elseif (isset($table["on"])) {
                $sql .= "\n" . $table["type"] . " JOIN " . $name . " ON (" . $table["on"] . ")";
            }
        }

        return $sql;
    }

    public function Select_label_string(array $select_pars): array
    {
        $select_labels = array();
        $sql = "";
        if (isset($select_pars[0])) {
            array_push($select_labels, ...$select_pars);
            $sql = implode(", ", $select_labels);
        } else {
            $i = 0;
            foreach ($select_pars as $k => $val) {
                if ($i > 0) {$sql .= ", ";}
                $sql .= $k;
                array_push($select_labels, $val);
                $i++;
            }
        }
        array_unshift($select_labels, $sql);
        return $select_labels;
    }

    public function Select_condition_string(array $extra, string ...$table): array
    {
        if (empty($extra)) {return array("");}

        $sql = "";
        $values = array();
        $i = 0;
        foreach ($extra as $field => $value) {
            if ($i > 0) {$sql .= " AND ";}
            $sql .= "(";

            if (isset($table[0]) && (strpos($field, ".") === false)) {
                $field = $table[0] . "." . $field;
            }
            if (gettype($value) === "array") {
                $n = sizeof($value);
                $sql .= $field . " IN (" . implode(',', array_fill(0, $n, '?')) . ")";
                array_push($values, ...$value);
            } else {
                if (substr($field, -5, 5) === "_gsql") {
                    $sql .= $value;
                } else {
                    $sql .= $field . "=?";
                    array_push($values, $value);
                }
            }
            $sql .= ")";
            $i++;
        }

        array_unshift($values, $sql);
        return $values;
    }

    public function Single_condition_string(array $keyids, array ...$extra): array
    {
        $sql = "";
        $extra_values = array();

        $i = 0;
        foreach ($keyids as $keyname => $val) {
            if ($i === 0) {
                $sql = "(";
            } else {
                $sql .= " AND ";
            }
            if (gettype($val) === "array") {
                $n = sizeof($val);
                $sql .= $keyname . " IN (" . implode(',', array_fill(0, $n, '?')) . ")";
                array_push($extra_values, ...$val);
            } else {
                $sql .= $keyname . "=?";
                array_push($extra_values, $val);
            }
            $sql .= ")";
			$i++;
        }

        if (!empty($extra)) {
            $arr = $this->Select_condition_string($extra[0]);
            $s = array_shift($arr);
            if ($s != "") {
                $sql .= " AND " . $s;
                array_push($extra_values, ...$arr);
            }
        }

        array_unshift($extra_values, $sql);
        return $extra_values;
    }

    public function Insert_hash(array $field_values): ?Gerror
    {
        return $this->insert_hash_("INSERT", $field_values);
    }

    public function Replace_hash(array $field_values): ?Gerror
    {
        return $this->insert_hash_("REPLACE", $field_values);
    }

    private function insert_hash_(string $how, array $field_values): ?Gerror
    {
        $fields = array();
        $values = array();
        foreach ($field_values as $k => $v) {
            array_push($fields, $k);
            array_push($values, $v);
        }
        $sql = $how . " INTO " . $this->Current_table . " (" . implode(", ", $fields) . ") VALUES (" . implode(',', array_fill(0, sizeof($fields), '?')) . ")";
        return $this->Do_sql($sql, ...$values);
    }

    public function Update_hash(array $field_values, array $keyids, array ...$extra): ?Gerror
    {
        return $this->Update_hash_nulls($field_values, $keyids, null, ...$extra);
    }

    public function Update_hash_nulls(array $field_values, array $keyids, array $empties = null, array ...$extra): ?Gerror
    {
        $fields = array();
        $field0 = array();
        $values = array();
        foreach ($field_values as $k => $v) {
            array_push($fields, $k);
            array_push($field0, $k . "=?");
            array_push($values, $v);
        }

        $sql = "UPDATE " . $this->Current_table . " SET " . implode(", ", $field0);
        if (!empty($empties)) {
            foreach ($empties as $v) {
                if (isset($field_values[$v])) {continue;}
                $found = false;
                foreach ($keyids as $keyname => $ids) {
                    if ($v === $keyname) {
                        $found = true;
                        break;
                    }
                }
                if ($found === true) {continue;}
                $sql .= ", " . $v . "=NULL";
            }
        }

        $extra_values = $this->Single_condition_string($keyids, ...$extra);
        $where = array_shift($extra_values);
        if ($where != "") {
            $sql .= "\nWHERE " . $where;
        }
        array_push($values, ...$extra_values);

        return $this->Do_sql($sql, ...$values);
    }

    public function Insupd_table(array $field_values, string $keyname, array $uniques, string &$s_hash): ?Gerror
    {
        $s = "SELECT " . $keyname . " FROM " . $this->Current_table . "\nWHERE ";
        $v = array();
        foreach ($uniques as $i => $val) {
            if ($i > 0) {$s .= " AND ";}
            $s .= $val . "=?";
            array_push($v, $field_values[$val]);
        }

        $lists = array();
        $err = $this->Select_sql($lists, $s, ...$v);
        if ($err != null) {return $err;}
        if (sizeof($lists) > 1) {return new Gerror(1070);}

        if (sizeof($lists) === 1) {
            $id = $lists[0][$keyname];
            $err = $this->Update_hash($field_values, array($keyname => $id));
            if ($err != null) {return $err;}
            $s_hash = "update";
            $field_values[$keyname] = $id;
        } else {
            $err = $this->Insert_hash($field_values);
            if ($err != null) {return $err;}
            $s_hash = "insert";
            $field_values[$keyname] = $this->Last_id;
        }

        return null;
    }

    public function Insupd_hash(array $field_values, array $upd_field_values, array $keyname, array $uniques, string &$s_hash): ?Gerror
    {
        $ks = $keyname;
        $s = "SELECT " . implode(", ", $ks) . " FROM " . $this->Current_table . "\nWHERE ";
        $v = array();
        foreach ($uniques as $i => $val) {
            if ($i > 0) {$s .= " AND ";}
            $s .= $val . "=?";
            array_push($v, $field_values[$val]);
        }

        $lists = array();
        $err = $this->Select_sql($lists, $s, ...$v);
        if ($err != null) {return $err;}
        if (sizeof($lists) > 1) {return new Gerror(1070);}

        if (sizeof($lists) === 1) {
            $ids = array_fill(0, sizeof($ks), "");
            $keyids = array();
            foreach ($ks as $i => $k) {
                $ids[$i] = $lists[0][$k];
                $field_values[$k] = $ids[$i];
                $keyids[$k] = $ids;
            }
            $err = $this->Update_hash($field_values, $keyids);
            if ($err != null) {return $err;}
            $s_hash = "update";
        } else {
            $err = $this->Insert_hash($field_values);
            if ($err != null) {return $err;}
            $s_hash = "insert";
        }

        return null;
    }

    public function Delete_hash(array $keyids, array ...$extra): ?Gerror
    {
        $sql = "DELETE FROM " . $this->Current_table;
        $extra_values = $this->Single_condition_string($keyids, ...$extra);
        $where = array_shift($extra_values);
        if ($where != "") {
            $sql .= "\nWHERE " . $where;
        }

        return $this->Do_sql($sql, ...$extra_values);
    }

    public function Edit_hash(array &$lists, array $select_pars, array $keyids, array ...$extra): ?Gerror
    {
        $select_labels = $this->Select_label_string($select_pars);
        $sql = array_shift($select_labels);
        $sql = "SELECT " . $sql . "\nFROM " . $this->Current_table;
        $extra_values = $this->Single_condition_string($keyids, ...$extra);
        $where = array_shift($extra_values);
        if ($where != "") {
            $sql .= "\nWHERE " . $where;
        }

        return $this->Select_sql_label($lists, $select_labels, $sql, ...$extra_values);
    }

    public function Topics_hash(array &$lists, array $select_pars, string $order, array ...$extra): ?Gerror
    {
        $select_labels = $this->Select_label_string($select_pars);
        $sql = array_shift($select_labels);
        $table = array();
        if (!empty($this->Current_tables)) {
            $sql = "SELECT " . $sql . "\nFROM " . $this->Table_string();
            $tbl = (isset($this->Current_tables[0]["alias"])) ? $this->Current_tables[0]["alias"] : $this->Current_tables[0]["name"];
            array_push($table, $tbl);
        } else {
            $sql = "SELECT " . $sql . "\nFROM " . $this->Current_table;
        }

        if (!empty($extra) > 0) {
            $values = $this->Select_condition_string($extra[0], ...$table);
            $where = array_shift($values);
            if ($where != "") {
                $sql .= "\nWHERE " . $where;
            }
            if ($order != "") {
                $sql .= "\n" . $order;
            }
            return $this->Select_sql_label($lists, $select_labels, $sql, ...$values);
        }

        if ($order != "") {
            $sql .= "\n" . $order;
        }
        return $this->Select_sql_label($lists, $select_labels, $sql);
    }

    public function Total_hash(array &$hash, string $label, array ...$extra): ?Gerror
    {
        $table = array();
        $sql = "SELECT COUNT(*) FROM ";
        if (!empty($this->Current_tables)) {
            $sql .= $this->Table_string();
            $tbl = (isset($this->Current_tables[0]["alias"])) ? $this->Current_tables[0]["alias"] : $this->Current_tables[0]["name"];
            array_push($table, $tbl);
        } else {
            $sql .= $this->Current_table;
        }

        if (!empty($extra)) {
            $values = $this->Select_condition_string($extra[0], ...$table);
            $where = array_shift($values);
            if ($where != "") {
                $sql .= "\nWHERE " . $where;
            }
            return $this->Get_sql_label($hash, array($label), $sql, ...$values);
        }

        return $this->Get_sql_label($hash, array($label), $sql);
    }

}
