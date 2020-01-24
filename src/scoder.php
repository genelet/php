<?php
declare (strict_types = 1);

namespace Genelet;

class Scoder
{
    protected $CRYPTEXT;

    public function __construct(string $c)
    {
        $this->CRYPTEXT = $c;
    }

    private static function mycrypt(array $cryptext, int $len, int $buf, int $i): array
    {
        $buf ^= 255 & ($cryptext[$i] ^ ($cryptext[0] * $i));
        $cryptext[$i] += ($i < ($len - 1)) ? $cryptext[$i + 1] : $cryptext[0];
        if ($cryptext[$i] == null) {
            $cryptext[$i] += 1;
        }
        if (++$i >= $len) {
            $i = 0;
        }
        return array($buf, $i);
    }

    private function make_scoder(string $text): string
    {
        $len = strlen($this->CRYPTEXT);
        $cryptext = array_map('ord', str_split($this->CRYPTEXT));

        $out = array();
        $k = intval( $len / 2 );
        foreach (str_split($text) as $c) {
            $cnew = self::mycrypt($cryptext, $len, ord($c), $k);
            array_push($out, $cnew[0]);
            $k = $cnew[1];
        }

        return join('', array_map('chr', $out));
    }

    public static function Encode_scoder(string $text, string $CRYPTEXT): string
    {
        $s = new Scoder($CRYPTEXT);
        return base64_encode($s->make_scoder($text));
    }

    public static function Decode_scoder(string $text, string $CRYPTEXT): string
    {
        $data = base64_decode($text);
        $s = new Scoder($CRYPTEXT);
        return $s->make_scoder($data);
    }
}
