<?php
declare (strict_types = 1);

namespace Genelet;

class Gerror
{
    public $error_code;
    public $error_string;

    public function __construct(int $code, string $msg = null)
    {
        $this->error_code = $code;
        $this->error_string = empty($msg) ? $this->get_string() : $msg;
    }

    public function get_string(): string
    {
		if (!empty($this->error_string)) { return $this->error_string;}
        $hash = array(
            1000 => "Application error.",
            1001 => "Google authorization required.",
            1002 => "Facebook authorization required.",
            1003 => "User denied authorization.",
            1004 => "Failed in browser getting token.",
            1005 => "Failed in browser getting app.",
            1006 => "Failed in browser refreshing token.",
            1007 => "Failed in browser refreshing app.",
            1008 => "Failed in finding token.",
            1009 => "Twitter athorization required.",
            1010 => "Failed in retrieve token secret from db for twitter.",
            1011 => "Failed in getting user_id from twitter.",
            1013 => "Failed to get ticket from box.",

            1020 => "Login required.",
            1021 => "Not authorized to view the page.",
            1022 => "Login is expired.",
            1023 => "Your IP does not match the login credential.",
            1024 => "Login signature is not acceptable.",
            1025 => "Sign In to your account",
            1026 => "Missing login or password",

            1030 => "Too many failed logins.",
            1031 => "Login incorrect. Please try again.",
            1032 => "Login failed",
            1033 => "Web server configuration error.",
            1034 => "Login failed. Please try again.",
            1035 => "This input field is missing: ",
            1036 => "Please make sure your browser supports cookie.",
            1037 => "Missing input.",
			1038 => "Login as admin is now allowed.",

            1040 => "Empty field.",
            1041 => "Foreign key forced but its value not provided.",
            1042 => "Foreign key fields and foreign key-to-be fields do not match.",
            1043 => "Variable undefined in your customzied method.",
            1044 => "Variable undefined in your procedure method.",
            1045 => "Upload field not found.",
            1051 => "Object method does not exist.",
            1052 => "Foreign key is broken.",
            1053 => "Foreign key session expired.",
            1054 => "Signature field not found.",
            1055 => "Signature not found.",
            1056 => "Signature column not found.",

            1060 => "Email Server, Sender, From, To and Subject must be existing.",
            1061 => "Message is empty.",
            1062 => "Sending mail failed.",
            1063 => "Mail server not reachable.",
            1064 => "No message nor template.",

            1070 => "Multiple records found in insupd.",
            1071 => "Select Syntax error.",
            1072 => "Failed to connect to the database.",
            1073 => "SQL failed, check your SQL statement; or duplicate entry.",

            1171 => "Insert failed, the column may exist",
            1172 => "Delete failed, maybe foreign keyed",
            1173 => "Update failed",
            1174 => "Select condition failed",
            1175 => "PROCEDURE format incorrect",

            1074 => "Die from db.",
            1075 => "Records exist in other tables",
            1076 => "Could not get a random ID.",
            1077 => "Condition not found in update.",
            1078 => "Hash not found in insert.",
            1079 => "Missing lists.",
            1080 => "Can't write to cache.",
            1090 => "No socket.",
            1091 => "Can't connect to socket.",
            1092 => "SSL error.",

            1100 => "Sender signature not found.",
            1101 => "Sender signature not confirmed.",
            1102 => "Invalid JSON.",
            1103 => "Incompatible JSON.",
            1105 => "Not allowed to send.",
            1106 => "Inactive recipient.",
            1107 => "Bounce not found.",
            1108 => "Bounce query exception.",
            1109 => "JSON required.",
            1110 => "Too many batch messages.",
            1111 => "HTTP email server error.",
            1113 => "Invalid email request.",

/**
 * Content from http://en.wikipedia.org/wiki/List_of_HTTP_status_codes
 **/
    100 => 'Continue',
    101 => 'Switching Protocols',
    102 => 'Processing', // WebDAV; RFC 2518
    200 => 'OK',
    201 => 'Created',
    202 => 'Accepted',
    203 => 'Non-Authoritative Information', // since HTTP/1.1
    204 => 'No Content',
    205 => 'Reset Content',
    206 => 'Partial Content',
    207 => 'Multi-Status', // WebDAV; RFC 4918
    208 => 'Already Reported', // WebDAV; RFC 5842
    226 => 'IM Used', // RFC 3229
    300 => 'Multiple Choices',
    301 => 'Moved Permanently',
    302 => 'Found',
    303 => 'See Other', // since HTTP/1.1
    304 => 'Not Modified',
    305 => 'Use Proxy', // since HTTP/1.1
    306 => 'Switch Proxy',
    307 => 'Temporary Redirect', // since HTTP/1.1
    308 => 'Permanent Redirect', // approved as experimental RFC
    400 => 'Bad Request',
    401 => 'Unauthorized',
    402 => 'Payment Required',
    403 => 'Forbidden',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    406 => 'Not Acceptable',
    407 => 'Proxy Authentication Required',
    408 => 'Request Timeout',
    409 => 'Conflict',
    410 => 'Gone',
    411 => 'Length Required',
    412 => 'Precondition Failed',
    413 => 'Request Entity Too Large',
    414 => 'Request-URI Too Long',
    415 => 'Unsupported Media Type',
    416 => 'Requested Range Not Satisfiable',
    417 => 'Expectation Failed',
    418 => 'I\'m a teapot', // RFC 2324
    419 => 'Authentication Timeout', // not in RFC 2616
    420 => 'Enhance Your Calm', // Twitter
    422 => 'Unprocessable Entity', // WebDAV; RFC 4918
    423 => 'Locked', // WebDAV; RFC 4918
    424 => 'Failed Dependency', // WebDAV; RFC 4918
    425 => 'Unordered Collection', // Internet draft
    426 => 'Upgrade Required', // RFC 2817
    428 => 'Precondition Required', // RFC 6585
    429 => 'Too Many Requests', // RFC 6585
    431 => 'Request Header Fields Too Large', // RFC 6585
    444 => 'No Response', // Nginx
    449 => 'Retry With', // Microsoft
    450 => 'Blocked by Windows Parental Controls', // Microsoft
    451 => 'Unavailable For Legal Reasons', // Internet draft
    494 => 'Request Header Too Large', // Nginx
    495 => 'Cert Error', // Nginx
    496 => 'No Cert', // Nginx
    497 => 'HTTP to HTTPS', // Nginx
    499 => 'Client Closed Request', // Nginx
    500 => 'Internal Server Error',
    501 => 'Not Implemented',
    502 => 'Bad Gateway',
    503 => 'Service Unavailable',
    504 => 'Gateway Timeout',
    505 => 'HTTP Version Not Supported',
    506 => 'Variant Also Negotiates', // RFC 2295
    507 => 'Insufficient Storage', // WebDAV; RFC 4918
    508 => 'Loop Detected', // WebDAV; RFC 5842
    509 => 'Bandwidth Limit Exceeded', // Apache bw/limited extension
    510 => 'Not Extended', // RFC 2774
    511 => 'Network Authentication Required', // RFC 6585
    598 => 'Network read timeout error', // Unknown
    599 => 'Network connect timeout error', // Unknown
);
        return isset($hash[$this->error_code]) ? $hash[$this->error_code] : "$this->error_code";
    }
}
