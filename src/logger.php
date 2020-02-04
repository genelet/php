<?php
declare (strict_types = 1);

namespace Genelet;

use Psr\Log\LogLevel;
use Psr\Log\LoggerInterface;

class Logger implements \Psr\Log\LoggerInterface
{
	private $current_msg;
	private $current_level;
	public $filename;

	const LOG_LEVEL_NONE = 'none';
	const LEVELS = [
        self::LOG_LEVEL_NONE => -1,
        LogLevel::DEBUG      => 0,
        LogLevel::INFO       => 1,
        LogLevel::NOTICE     => 2,
        LogLevel::WARNING    => 3,
        LogLevel::ERROR      => 4,
        LogLevel::CRITICAL   => 5,
        LogLevel::ALERT      => 6,
        LogLevel::EMERGENCY  => 7,
	];

	public function __construct(string $log_file, string $log_level = LogLevel::WARNING)
    {
        $this->filename  = $log_file;
        $this->current_level = $log_level;
    }

	public function screen_start(string $method, string $uri='', string $ip, string $ua) {

		return $this->warning("GENELET LOGGER {New Screen}{".$_SERVER["REQUEST_TIME"]."}{".$ip."}{".$method."}{".$uri."}{".$ua."}");
	}

	public function debug($msg, array $c=null)     { return $this->log(self::LEVELS[LogLevel::DEBUG], $msg, $c); }
	public function info($msg, array $c=null)      { return $this->log(self::LEVELS[LogLevel::INFO], $msg, $c); }
	public function notice($msg, array $c=null)    { return $this->log(self::LEVELS[LogLevel::NOTICE], $msg, $c); }
	public function warning($msg, array $c=null)   { return $this->log(self::LEVELS[LogLevel::WARNING], $msg, $c); }
	public function error($msg, array $c=null)     { return $this->log(self::LEVELS[LogLevel::ERROR], $msg, $c); }
	public function critical($msg, array $c=null)  { return $this->log(self::LEVELS[LogLevel::CRITICAL], $msg, $c); }
	public function alert($msg, array $c=null)     { return $this->log(self::LEVELS[LogLevel::ALERT], $msg, $c); }
	public function emergency($msg, array $c=null) { return $this->log(self::LEVELS[LogLevel::EMERGENCY], $msg, $c); }

	public function log($level, $msg, array $c=null) : void {
		if ($level < self::LEVELS[$this->current_level]) { return; }
		$t = gettype($msg);
		$this->current_msg = ($t == "array" || $t == "object") ? print_r($msg, true) : $msg;
		if (isset($c)) { $this->current_msg .= ", " . print_r($c, true); };
		$ref = array();
		foreach (self::LEVELS as $k=>$v) { $ref[$v] = $k; }
		$mix = "[" . $ref[$level] . " " . getmypid() . "]" . $this->current_msg . "\n";
		// Log to file
		try {
			$fh = fopen($this->filename, 'a');
			fwrite($fh, $mix);
			fclose($fh);
		} catch (\Throwable $e) {
			throw new \RuntimeException("Could not open log file {$this->filename}", 0, $e);
		}

		return;
	}

	public function is_debug()     {return $this->logAtThisLevel(LogLevel::DEBUG);}
	public function is_info()      {return $this->logAtThisLevel(LogLevel::INFO);}
	public function is_notice()    {return $this->logAtThisLevel(LogLevel::NOTICE);}
	public function is_warning()   {return $this->logAtThisLevel(LogLevel::WARNING);}
	public function is_error()     {return $this->logAtThisLevel(LogLevel::ERROR);}
	public function is_critical()  {return $this->logAtThisLevel(LogLevel::CRITICAL);}
	public function is_alert()     {return $this->logAtThisLevel(LogLevel::ALERT);}
	public function is_emergency() {return $this->logAtThisLevel(LogLevel::EMERGENCY);}

	private function logAtThisLevel(string $level) : bool {
		return self::LEVELS[$level] <= self::LEVELS[$this->current_level];
	}

}

