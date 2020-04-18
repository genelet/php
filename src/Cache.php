<?php
declare (strict_types = 1);

namespace Genelet;

use Psr\SimpleCache;

class Cache extends Base implements \Psr\SimpleCache\CacheInterface
{
    public $Action;
    public $Component;
    public $ctype;
    public $ttl;

    public function __construct(object $c, string $rv, string $cv, string $a_name, string $c_name, int $ctype, int $ttl)
    {
        parent::__construct($c, $rv, $cv);
        $this->Action = $a_name;
        $this->Component = $c_name;
        $this->ctype = $ctype;
        $this->ttl = $ttl;
    }

    private function getDir(): string
    {
        $role = $this->Get_role();

        $dir = $this->cachetop . "/" . $this->Role_name;
        if (!$this->Is_public()) {
            $dir .= "/" . $_REQUEST[$role->idname];
        }
        if (!file_exists($dir)) {
            mkdir($dir, 0777, true);
        }
        return $dir;
    }

    private function full($key): string
    {
        $fn = ($this->ctype === 1) ? $key : empty($key) ? $this->Action : $this->Action . "_" . $key;
        return $this->getDir() . "/" . $fn . "." . $this->Tag_name;
    }

    public function has($key): bool
    {
        $path = $this->full($key);
        $modified = filemtime($path);
        if ($modified === false) {
            return $default; // file not found
        }
        return ($modified + $this->ttl) > $_SERVER["REQUEST_TIME"];
        // return file_exists($this->full($key));
    }

    public function get($key, $default = null)
    {
        $path = $this->full($key);
        $data = file_get_contents($path);
        if ($data === false) {return $default;}
        return $data;
    }

    public function set($key, $msg, $ttl = null)
    {
        $path = $this->full($key);
        return file_put_contents($path, $msg);
    }

    public function delete($key)
    {
        return !$this->has($key) || unlink($this->full($key));
    }

    public function clear()
    {
        unlink($this->getDir());
    }

    public function getMultiple($keys, $default = null)
    {
        if (!is_array($keys) && !$keys instanceof Traversable) {
            throw new InvalidArgumentException("keys must be either of type array or Traversable");
        }
        $values = [];
        foreach ($keys as $key) {
            $values[$key] = $this->get($key, $default);
        }
        return $values;
    }

    public function setMultiple($values, $ttl = null)
    {
        if (!is_array($values) && !$values instanceof Traversable) {
            throw new InvalidArgumentException("keys must be either of type array or Traversable");
        }
        $ok = true;
        foreach ($values as $key => $value) {
            $ok = $ok && $this->set($key, $value, $ttl);
        }
        return $ok;
    }

    public function deleteMultiple($keys)
    {
        if (!is_array($keys) && !$keys instanceof Traversable) {
            throw new InvalidArgumentException("keys must be either of type array or Traversable");
        }
        $ok = true;
        foreach ($keys as $key) {
            $ok = $ok && $this->delete($key);
        }
        return $ok;
    }

}
