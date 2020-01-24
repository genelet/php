<?php
declare (strict_types = 1);
namespace Genelet\Tests;

use PHPUnit\Framework\TestCase;
use Genelet\Logger;

final class LoggerTest extends TestCase
{
    public function testCreatedLogger(): void
    {
        $content = file_get_contents("conf/test.conf");
        $config = json_decode($content);
        $this->assertInstanceOf(
            Logger::class,
            new Logger($config->{"Log"}->{"Filename"}, $config->{"Log"}->{"Level"})
        );
    }

    public function testLogger(): void
    {
        $config = json_decode(file_get_contents("conf/test.conf"));
        $logger = new Logger($config->{"Log"}->{"Filename"}, $config->{"Log"}->{"Level"});
		$this->assertFalse($logger->is_emergency());
		$this->assertFalse($logger->is_alert());
		$this->assertTrue($logger->is_critical());
		$this->assertTrue($logger->is_error());
		$this->assertTrue($logger->is_warning());
		$this->assertTrue($logger->is_notice());
		$this->assertTrue($logger->is_info());
		$this->assertTrue($logger->is_debug());

		$logger->debug("this is debug");
		$logger->info("this is info");
		$logger->notice("this is notice");
		$logger->warning("this is warning");
		$logger->error("this is error");
		$logger->critical("this is critical");
		$logger->alert("this is alert");
		$logger->emergency("this is emergency");
		$this->assertTrue($logger->is_debug());
    }
}
