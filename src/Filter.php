<?php

declare(strict_types=1);

namespace Genelet;

class Filter extends Access
{
	private $oncepages;

	public $Action; //		string
	public $Component; //	string
	public $Actions; //		map[string]map[string][]string
	public $Fks; //			map[string][]string

	public $actionHash;
	public $fkArray;
	public $current_key;

	public function __construct(object $comp, string $a_name, string $c_name, object $c, string $rv, string $cv)
	{
		parent::__construct($c, $rv, $cv);
		$this->Action = $a_name;
		$this->Component = $c_name;
		self::Initialize($comp);
	}

	private function Initialize(object $comp): void
	{
		$this->current_key = $comp->{"current_key"};
		$hash = array();
		foreach ($comp->{"actions"} as $action => $obj_item) {
			$item = array();
			foreach ($obj_item as $k => $obj_vs) {
				$vs = array();
				foreach ($obj_vs as $v) {
					array_push($vs, $v);
				}
				$item[$k] = $vs;
			}
			$hash[$action] = $item;
			if ($this->Action === $action) {
				$this->actionHash = $item;
			}
		}
		$this->Actions = $hash;
		if (isset($comp->{"fks"})) {
			$fks = array();
			foreach ($comp->{"fks"} as $role => $obj_fk) {
				$fk = array();
				foreach ($obj_fk as $v) {
					array_push($fk, $v);
				}
				$fks[$role] = $fk;
			}
			$this->Fks = $fks;
			if (isset($fks[$this->Role_name])) {
				$this->fkArray = $fks[$this->Role_name];
			}
		}
		if (isset($comp->{"oncepages"})) {
			$oncepages = array();
			foreach ($comp->{"oncepages"} as $action => $obj_ms) {
				$ms = array();
				foreach ($obj_ms as $obj_m) {
					$table = array();
					foreach ($obj_m as $k => $v) {
						$table[$k] = $v;
					}
					array_push($ms, $table);
				}
				$oncepages[$action] = $ms;
			}
			$this->oncepages = $oncepages;
		}
	}

	public function Role_can(): bool
	{
		if ($this->Is_admin()) {
			return true;
		}
		if (empty($this->actionHash["groups"])) {
			return false;
		}
		return array_search($this->Role_name, $this->actionHash["groups"]) >= 0;
	}

	private function DigestWithinLogin(array $ARGS, string $str): string
	{
		$idname = $this->Get_idname();
		$value_idname = $ARGS[$idname];
		return $this->Digest($this->Role_name . $idname . $value_idname . $str);
	}

	private function TokenWithinLogin(array $ARGS, int $stamp): string
	{
		$idname = $this->Get_idname();
		$value_idname = $ARGS[$idname];
		return $this->Token($stamp, $this->Role_name . $idname . $value_idname);
	}

	// "upload":{"field1":"name1","field2":"name2",...}
	// file will be moved to folder Uploaddir/role/name1/
	// or Uploaddir/role/ID_value/, if name1 matched its role-id name
	protected function upload(): ?Gerror
	{
		foreach ($_FILES as $field => $image) {
			if ($image["error"] !== UPLOAD_ERR_OK) {
				return new Gerror(3207, "Upload internal: " . $image["error"]);
			}
			$item = $this->actionHash["upload"][$field];
			$uploadfile = $this->uploaddir . "/" . $this->Role_name . "/";
			$uploadfile .= (!$this->Is_public() && $item === $this->Get_idname()) ? $_REQUEST[$item] : $item;
			if (!file_exists($uploadfile)) {
				mkdir($uploadfile, 0777, true);
			}
			$uploadfile .= "/" . basename($image['name']);
			$ok = move_uploaded_file($image['tmp_name'], $uploadfile);
			if ($ok) {
				$_REQUEST[$field] = $uploadfile;
			} else {
				return new Gerror(3208, "Upload error: " . $image["name"]);
			}
		}
		return null;
	}

	public function Preset(): ?Gerror
	{
		if (isset($this->actionHash["upload"]) && !empty($_FILES)) {
			$err = $this->upload();
			if ($err != null) {
				return $err;
			}
		}
		if (isset($this->actionHash["options"]) && array_search("csrf", $this->actionHash["options"]) !== false) {
			if (empty($_POST[$this->csrf_name])) {
				return new Gerror(3209);
			}
			$token = $_POST[$this->csrf_name];
			$stamp = Access::Get_tokentime($token);
			if ($token !== $this->TokenWithinLogin($_REQUEST, $stamp)) {
				return new Gerror(3210);
			}
		}

		return null;
	}

	public function Before(object &$model, array &$extra, array &$nextextra, array &$onceextra = null): ?Gerror
	{
		$ARGS = $model->ARGS;
		if (isset($this->actionHash["validate"])) {
			foreach ($this->actionHash["validate"] as $k) {
				if (empty($ARGS[$k])) {
					return new Gerror(1035, $k);
				}
			}
		}
		if ($this->Action == 'topics') {
			foreach ($model->Topics_pars as $k) {
				if (isset($ARGS[$k])) {
					$extra[$k] = $ARGS[$k];
				}
			}
		}
		if (isset($this->fkArray) && isset($this->fkArray[0])) {
			$name = $this->fkArray[0];
			if (empty($ARGS[$name])) {
				return new Gerror(1041);
			}
			$value = $ARGS[$name];
			$extra[$name] = $value;
			if ($name === $this->Get_idname()) {
				return null;
			}
			if (empty($this->fkArray[1]) || empty($ARGS[$this->fkArray[1]])) {
				return new Gerror(1054);
			}
			$md5 = $ARGS[$this->fkArray[1]];
			if ($ARGS[$this->fkArray[1]] != $this->DigestWithinLogin($ARGS, $name . $value)) {
				return new Gerror(1052);
			}
		}

		return null;
	}

	public function After(object $model, array $onceextra = null): ?Gerror
	{
		$ARGS = $model->ARGS;
		if (isset($this->oncepages) && isset($this->oncepages[$this->Action])) {
			foreach ($this->oncepages[$this->Action] as $page) {
				$err = $model->call_once($page, ...$onceextra);
				if ($err !== null) {
					return $err;
				}
				if (!empty($onceextra)) {
					array_shift($onceextra);
				}
			}
		}
		if (isset($this->fkArray) && !empty($model->LISTS)) {
			$fk = $this->fkArray;
			while (sizeof($fk) > 3) {
				foreach ($model->LISTS as &$item) {
					$name = $fk[2];
					if (empty($item[$name])) {
						continue;
					}
					$value = $item[$name];
					$item[$fk[3]] = $this->DigestWithinLogin($ARGS, $name . $value);
				}
				array_shift($fk);
				array_shift($fk);
			}
		}
		if (!$this->Is_public()) {
			$idname = $this->Get_idname();
			$value_idname = $ARGS[$idname];
			$model->OTHER[$this->csrf_name] = $this->TokenWithinLogin($ARGS, intval($_SERVER["REQUEST_TIME"]));
		}
		if ($_SERVER["REQUEST_METHOD"] === "GET" || $_SERVER["REQUEST_METHOD"] === "GET_item") {
			$name = "";
			if ($this->Action == $this->default_actions["GET_item"]) {
				$name = $ARGS[$this->current_key];
			} else {
				$name = $this->Action;
				if (!empty($_GET)) {
					$name .= "_" . str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(serialize($_GET)));
				}
			}
			$model->OTHER[$this->cache_url_name] = $this->script . "/" . $this->Role_name . "/" . $this->Component . "/" . $name . "." . $this->Tag_name;
			$parts = explode("/", $_SERVER["REQUEST_URI"]);
			$parts[3] = "json";
			$model->OTHER[$this->json_url_name] = implode("/", $parts);
		}
		return null;
	}
}
