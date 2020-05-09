<?php
declare (strict_types = 1);

namespace Genelet;

class Model extends Crud
{
    public $ARGS;
    public $LISTS;
    public $OTHER;

    public $SORTBY;
    public $SORTREVERSE;
    public $PAGENO;
    public $ROWCOUNT;
    public $TOTALNO;
    public $MAXPAGENO;
    public $FIELDS;
    public $EMPTIES;

    public $Nextpages;
    public $Storage;

    public $Current_key;
    public $Current_id_auto;
    public $Key_in;

    public $Insert_pars;
    public $Edit_pars;
    public $Update_pars;
    public $Insupd_pars;
    public $Topics_pars;
    public $Topics_hashpars;

    public $Total_force;

	private $role_name;
	private $tag_name;

// I may move pdo to Set_default so nextpage shares the same pdo as caller?
    public function __construct(\PDO $pdo, object $comp)
    {
        self::Initialize($comp);
		if (isset($this->Current_tables)) {
        	parent::__construct($pdo, $this->Current_table, $this->Current_tables);
		} else {
        	parent::__construct($pdo, $this->Current_table);
		}
    }

    public function Set_defaults(array $args, array $lists, array $other, array $storage=null, Logger $logger=null, string $role=null, string $tag=null)
    {
        $this->ARGS = $args;
        $this->LISTS = $lists;
        $this->OTHER = $other;
        if ($storage != null) {
            $this->Storage = $storage;
        }
        if ($logger != null) {
            $this->logger = $logger;
        }
		if ($role != null) {
			$this->role_name = $role;
		}
		if ($tag != null) {
			$this->tag_name = $tag;
		}
    }

	public function Get_rolename()
	{
		return $this->role_name;
	}

	public function Get_tagname()
	{
		return $this->tag_name;
	}

    private function Initialize(object $comp)
    {
        $this->SORTBY = isset($comp->{"sortby"}) ? $comp->{"sortby"} : "sortby";
        $this->SORTREVERSE = isset($comp->{"sortreverse"}) ? $comp->{"sortreverse"} : "sortreverse";
        $this->PAGENO = isset($comp->{"pageno"}) ? $comp->{"pageno"} : "pageno";
        $this->ROWCOUNT = isset($comp->{"rowcount"}) ? $comp->{"rowcount"} : "rowcount";
        $this->TOTALNO = isset($comp->{"totalno"}) ? $comp->{"totalno"} : "totalno";
        $this->MAXPAGENO = isset($comp->{"maxpageno"}) ? $comp->{"maxpageno"} : "maxpageno";
        $this->FIELDS = isset($comp->{"fields"}) ? $comp->{"fields"} : "fields";
        $this->EMPTIES = isset($comp->{"empties"}) ? $comp->{"empties"} : "empties";

        if (isset($comp->{"nextpages"})) {
            $this->Nextpages = array();
            foreach ($comp->{"nextpages"} as $action => $obj_ms) {
				$ms = array();
				foreach ($obj_ms as $obj_m) {
					$table = array();
					foreach ($obj_m as $k => $v) {
						if ($k=="relate_item") {
							$table[$k] = array();
							foreach ($v as $kk => $vv) {
								$table[$k][$kk] = $vv;
							}
						} else {
							$table[$k] = $v;
						}
					}
					array_push($ms, $table);
				}
				$this->Nextpages[$action] = $ms;
			}
        }

        $this->Current_table = $comp->{"current_table"};
        if (isset($comp->{"current_tables"})) {
            $this->Current_tables = array();
			foreach ($comp->{"current_tables"} as $obj_tbl) {
				$table = array();
				foreach ($obj_tbl as $k => $v) {
					$table[$k] = $v;
				}
				array_push($this->Current_tables, $table);
			}
        }
        if (isset($comp->{"current_key"})) {
            $this->Current_key = $comp->{"current_key"};
        }
        if (isset($comp->{"current_id_auto"})) {
            $this->Current_id_auto = $comp->{"current_id_auto"};
        }
        if (isset($comp->{"key_in"})) {
            $this->Key_in = $comp->{"key_in"};
        }
        if (isset($comp->{"insert_pars"})) {
            $this->Insert_pars = $comp->{"insert_pars"};
        }
        if (isset($comp->{"edit_pars"})) {
            $this->Edit_pars = $comp->{"edit_pars"};
        }
        if (isset($comp->{"update_pars"})) {
            $this->Update_pars = $comp->{"update_pars"};
        }
        if (isset($comp->{"insupd_pars"})) {
            $this->Insupd_pars = $comp->{"insupd_pars"};
        }
        if (isset($comp->{"topics_pars"})) {
            $this->Topics_pars = $comp->{"topics_pars"};
        }

        if (isset($comp->{"topics_hash"})) {
			$this->Topics_hashpars = array();
            foreach ($comp->{"topics_hash"} as $k => $v) {
                $this->Topics_hashpars[$k] = $v;
            }
        }
        $this->Total_force = 1;
        if (isset($comp->{"total_force"})) {
            $this->Total_force = $comp->{"total_force"};
        }
    }

    public function filtered_fields(array $pars): array
    {
        $ARGS = $this->ARGS;
        if (empty($ARGS[$this->FIELDS])) {
            return $pars;
        }
        $in = $ARGS[$this->FIELDS];
        $out = array();
        if (gettype($in) == "array") {
            foreach ($in as $val) {
                if (array_search($val, $pars) !== false) {
                    array_push($out, $val);
                }
            }
        } elseif (array_search($in, $pars) !== false) {
            array_push($out, $in);
        }
        return empty($out) ? $pars : $out;
    }

    private function get_fv(array $pars): array
    {
        $ARGS = $this->ARGS;
        $field_values = array();
        $filted = $this->filtered_fields($pars);
        foreach ($filted as $f) {
            if (!empty($ARGS[$f])) {
                $field_values[$f] = $ARGS[$f];
            }
        }
        return $field_values;
    }

    public function properValue(string $v, array $extra = null): ?array
    {
        $ARGS = $this->ARGS;
        if (isset($extra[$v])) {
            return (gettype($extra[$v]) == "array") ? $extra[$v] : [$extra[$v]];
        } elseif (isset($ARGS[$v])) {
            return (gettype($ARGS[$v]) == "array") ? $ARGS[$v] : [$ARGS[$v]];
        }
        return null;
    }

    public function properValues(array $vs, array $extra = null): ?array
    {
        $ARGS = $this->ARGS;
        $outs = array();
        foreach ($vs as $v) {
            if (isset($extra[$v])) {array_push($outs, $extra[$v]);}
            if (isset($ARGS[$v])) {array_push($outs, $ARGS[$v]);}
            return null;
        }

        return $outs;
    }

    public function get_id_val(array $extra = null): array
    {
        $id = $this->Current_key;
        $val = (gettype($id) == "array")
        ? $this->properValues($id, $extra)
        : $this->properValue($id, $extra);
        if ($val == null) {return array($id);}
        return array($id, $val);
    }

    public function topics(...$extra): ?Gerror
    {
        $ARGS = $this->ARGS;
        $totalno = $this->TOTALNO;
        $pageno = $this->PAGENO;
        if ($this->Total_force != 0 && isset($ARGS[$this->ROWCOUNT]) && (empty($ARGS[$pageno]) || $ARGS[$pageno] == "1")) {
            $nt = 0;
            if ($this->Total_force < -1) {
                $nt = abs($this->Total_force);
            } elseif ($this->Total_force == -1 || empty($ARGS[$totalno])) {
                $hash = array();
                $err = $this->Total_hash($hash, $totalno, ...$extra);
                if ($err != null) {return $err;}
                $nt = $hash[$totalno];
            } else {
            	$nt = $ARGS[$totalno];
			}
            $this->ARGS[$totalno] = $nt;
            $nr = $ARGS[$this->ROWCOUNT];
            $this->ARGS[$this->MAXPAGENO] = floor(($nt - 1) / $nr) + 1;
			$this->OTHER[$totalno] = $nt;
			$this->OTHER[$this->MAXPAGENO] = $this->ARGS[$this->MAXPAGENO];
        }

        $fields = (empty($this->Topics_hashpars)) ? // user may supply field=,,,
        $this->filtered_fields($this->Topics_pars) :
        $this->Topics_hashpars;
        $err = $this->Topics_hash($this->LISTS, $fields, $this->get_order_string(), ...$extra);
        if ($err != null) {return $err;}

        return $this->process_after("topics", ...$extra);
    }

    public function edit(...$extra): ?Gerror
    {
        $val2 = $this->get_id_val((!empty($extra)) ? $extra[0] : null);
        $id = array_shift($val2);
        if (empty($val2)) {return new Gerror(1040, $id);}
        $val = $val2[0]; // two elements and the second is the val

        $field_values = $this->filtered_fields($this->Edit_pars);
        if (empty($field_values)) {return new Gerror(1077);}

        $err = $this->Edit_hash($this->LISTS, $field_values, array($id => $val), ...$extra);
        if ($err != null) {return $err;}

        return $this->process_after("edit", ...$extra);
    }

// use 'extra' to override field_values for selected fields
    public function insert(...$extra): ?Gerror
    {
        $field_values = $this->get_fv($this->Insert_pars);

        if (!empty($extra)) {
            foreach ($extra[0] as $kkey => $value) {
                if (array_search($kkey, $this->Insert_pars) !== false) {
                    $field_values[$kkey] = $value;
                }
            }
        }
        if (empty($field_values)) {return new Gerror(1078);}

        $err = $this->Insert_hash($field_values);
        if ($err != null) {return $err;}

        if (isset($this->Current_id_auto)) {
            $field_values[$this->Current_id_auto] = $this->Last_id;
            $this->ARGS[$this->Current_id_auto] = $this->Last_id;
        }
        $this->LISTS = array($field_values);

        return $this->process_after("insert", ...$extra);
    }

    public function insupd(...$extra): ?Gerror
    {
        if (empty($this->Insupd_pars)) {return new Gerror(1078);}
        $uniques = $this->Insupd_pars;

        $field_values = $this->get_fv($this->Insert_pars);
        if (!empty($extra)) {
            foreach ($extra[0] as $kkey => $value) {
                if (array_search($kkey, $this->Insert_pars) !== false) {
                    $field_values[$kkey] = $value;
                }
            }
        }
        if (empty($field_values)) {return new Gerror(1078);}

        foreach ($uniques as $v) {
            if (empty($field_values[$v])) {return new Gerror(1075, $v);}
        }

        $upd_field_values = $this->get_fv($this->Update_pars);

        $s_hash = "";
        $keys = isset($this->Current_keys)
        ? $this->Current_keys
        : array($this->Current_key);
        $err = $this->Insupd_hash($field_values, $upd_field_values, $keys, $uniques, $s_hash);
        if ($err != null) {return $err;}

        if (isset($this->Current_id_auto) && $s_hash == "insert") {
            $field_values[$this->Current_id_auto] = $this->Last_id;
            $this->ARGS[$this->Current_id_auto] = $this->Last_id;
        }
        array_push($this->LISTS, $field_values);

        return $this->process_after("insupd", ...$extra);
    }

    public function update(...$extra): ?Gerror
    {
        $val2 = $this->get_id_val((!empty($extra)) ? $extra[0] : null);
        $id = array_shift($val2);
        if (empty($val2)) {return new Gerror(1040, $id);}
        $val = $val2[0];

        $field_values = $this->get_fv($this->Update_pars);
        if (empty($field_values)) {return new Gerror(1074);}

        if (count($field_values) == 1 && isset($field_values[$id])) {
            $this->LISTS = array($field_values);
            return $this->process_after("update", ...$extra);
        }

        $ARGS = $this->ARGS;
        $err = $this->Update_hash_nulls($field_values, array($id => $val), isset($ARGS[$this->EMPTIES]) ? $ARGS[$this->EMPTIES] : null, ...$extra);
        if ($err != null) {return $err;}

        $this->LISTS = array($field_values);

        return $this->process_after("Update", ...$extra);
    }

    public function delete(...$extra): ?Gerror
    {
        $val2 = $this->get_id_val((!empty($extra)) ? $extra[0] : null);
        $id = array_shift($val2);
        if (empty($val2)) {return new Gerror(1040, $id);}
        $val = $val2[0];

        if (isset($this->Key_in)) {
            foreach ($this->Key_in as $table => $keyname) {
                foreach ($val as $v) {
                    $err = $this->existing($table, $keyname, $v);
                    if ($err != null) {return $err;}
                }
            }
        }

        $err = $this->Delete_hash(array($id => $val), ...$extra);
        if ($err != null) {return $err;}

        $field_values = array();
        if (gettype($id) == "array") {
            foreach ($id as $i => $v) {
                $field_values[$v] = $val[$i];
            }
        } else {
            $field_values[$id] = $val[0];
        }
        $this->LISTS = array($field_values);

        return $this->process_after("delete", ...$extra);
    }

    public function existing(string $table, string $field, $val): ?Gerror
    {
        $hash = array();
        $err = $this->Get_args($hash,
            "SELECT " . $field . " FROM " . $table . " WHERE " . $field . "=?", $val);
        if ($err != null) {return $err;}
        if (!empty($hash[$field])) {return new Gerror(1075);}

        return null;
    }

    public function randomid(string $table, string $field, ...$m): ?Gerror
    {
        $mi = 0;
        $ma = 4294967295;
        $trials = 10;
        if (!empty($m)) {
            $mi = $m[0];
            $ma = $m[1];
            $trials = isset($m[2]) ? $m[2] : 10;
        }

        for ($i = 0; $i < $trials; $i++) {
            $val = rand($mi, $ma);
            $err = $this->existing($table, $field, $val);
            if ($err != null) {continue;}
            $this->ARGS[$field] = $val;
            return null;
        }

        return new Gerror(1076);
    }

    public function get_order_string(): string
    {
        $ARGS = $this->ARGS;
        $column = "";
        if (isset($ARGS[$this->SORTBY])) {
            $column = $ARGS[$this->SORTBY];
        } elseif (isset($this->Current_tables)) {
            $table = $this->Current_tables[0];
			if (isset($table["sortby"])) {
				$column = $table["sortby"];
			} else {
            	$name = isset($table["alias"]) ? $table["alias"] : $table["name"];
            	$name .= ".";
            	$column = $name . ((gettype($this->Current_key) == "array") ? implode(", $name", $this->Current_key) : $this->Current_key);
			}
        } else {
            $column = (gettype($this->Current_key) == "array") ? implode(", ", $this->Current_key) : $this->Current_key;
        }

        $order = "ORDER BY " . $column;
        if (isset($ARGS[$this->SORTREVERSE])) {$order .= " DESC";}

        if (isset($ARGS[$this->ROWCOUNT])) {
            $rowcount = $ARGS[$this->ROWCOUNT];
            $pageno = isset($ARGS[$this->PAGENO]) ? $ARGS[$this->PAGENO] : 1;
            $order .= " LIMIT " . $rowcount . " OFFSET " . (($pageno - 1) * $rowcount);
        }

        if (strpos($order, ";") === false && strpos($order, "'") === false && strpos($order, '"') === false) {
            return $order;
        }

        return "";
    }

    private function another_object(array &$item, array $page, ...$extra): ?Gerror
    {
        $model = $page["model"];
        if (empty($this->Storage)) {
            return new Gerror(2013);
        }
        $p = $this->Storage[$model];
        if (empty($p)) {
            return new Gerror(2014, $model);
        }

        $action = $page["action"];
        $marker = $model . "_" . $action;
        if (isset($page["alias"])) {
            $marker = $page["alias"];
        }
        if (isset($page["ignore"]) && !empty($item[$marker])) {
            return null;
        }

        $args = array();
        foreach ($this->ARGS as $k => $v) {
            if ($k == "sortby" || $k == "sortreverse") {continue;}
            $args[$k] = $v;
        }

        if (isset($page["manual"])) {
            if (empty($extra)) {
                $extra = array($page["manual"]);
            } else {
                foreach ($page["manual"] as $k => $v) {
                    $extra[0][$k] = $v;
                }
            }
        }

        $lists = array();
        $other = array();
        $p->Set_defaults($args, $lists, $other, $this->Storage);
        $err = $p->$action(...$extra);
        if ($err !== null) {return $err;}
        if (!empty($p->LISTS)) {
            $item[$marker] = $p->LISTS;
        }
        if (!empty($p->OTHER)) {
            foreach ($p->OTHER as $k => $v) {
                $this->OTHER[$k] = $v;
            }
        }
        return null;
    }

    public function call_once(array $page, ...$extra): ?Gerror
    {
        return $this->another_object($this->OTHER, $page, ...$extra);
    }

    public function call_nextpage(array $page, ...$extra): ?Gerror
    {
        if (empty($this->LISTS)) {return null;}

        foreach ($this->LISTS as $i=>$item) {
            foreach ($page["relate_item"] as $k => $v) {
                if (!empty($item[$k])) {
                    $extra[0][$v] = $item[$k];
                }
            }
            $err = $this->another_object($this->LISTS[$i], $page, ...$extra);
            if ($err !== null) {return $err;}
        }

        return null;
    }

    public function process_after(string $action, ...$extra): ?Gerror
    {
        if (empty($this->Nextpages) || empty($this->Nextpages[$action])) {return null;}
        foreach ($this->Nextpages[$action] as $k => $page) {
            if (!empty($extra)) {
                array_shift($extra);
            }
            $err = (empty($page["relate_item"])) ? $this->call_once($page, ...$extra) : $this->call_nextpage($page, ...$extra);
            if ($err !== null) {return $err;}
        }
        return null;
    }

}
