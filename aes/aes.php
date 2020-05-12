<?php

    /**
     * MCRYPT_RIJNDAEL_128 & CBC + 16位Key + 16位iv = openssl_encrypt(AES-128-CBC, 16位Key, 16位iv) = AES-128
     * MCRYPT_RIJNDAEL_128 & CBC + 24位Key + 16位iv = openssl_encrypt(AES-192-CBC, 24位Key, 16位iv) = AES-192
     * MCRYPT_RIJNDAEL_128 & CBC + 32位Key + 16位iv = openssl_encrypt(AES-256-CBC, 32位Key, 16位iv) = AES-256
     * ------------------------------------------------------------------------------------------------------
     * openssl_簇 options
     * 0 : 默认模式，自动对数据做 pkcs7 填充, 且返回的加密数据经过 base64 编码
     * 1 : OPENSSL_RAW_DATA, 自动对数据做 pkcs7 填充, 且返回的加密数据未经过 base64 编码
     * 2 : OPENSSL_ZERO_PADDING, 处理使用 NUL("\0") 的数据，故需手动使用 NUL("\0") 填充好数据再做加密处理，如未做则会报错
     * --------------------------------------------------------------------------------------------------------
     * 加密工具类
     */

    // mcrypt AES 固定使用 MCRYPT_RIJNDAEL_128 通过 key 的长度来决定具体使用的具体何种 AES
    $mcrypt_cipher = MCRYPT_RIJNDAEL_128;
    $mcrypt_mode   = MCRYPT_MODE_CBC;

    // aes-128=16 aes-192=24 aes-256=32
    $key_size = 16;
    $key      = get_random_str($key_size);
    // openssl AES 向量长度固定 16 位 这里为兼容建议固定长度为 16 位
    $iv_size = 16;
    $iv      = get_random_str($iv_size);

    // 随机字符串
     function get_random_str($length = 16)
    {
        $char_set = array_merge(range('a', 'z'), range('A', 'Z'), range('0', '9'));
        shuffle($char_set);
        return implode('', array_slice($char_set, 0, $length));
    }

    /**
     * 加密算法
     * @param  string $content 待加密数据
     * @param  string $key     加密key 注意 key 长度要求
     * @param  string $iv      加密向量 固定为16位可以保证与openssl的兼容性
     * @param  string $cipher  加密算法
     * @param  string $mode    加密模式
     * @param  bool $pkcs7     是否使用pkcs7填充 否则使用 mcrypt 自带的 NUL("\0") 填充
     * @param  bool $base64    是否对数据做 base64 处理 因加密后数据会有非打印字符 所以推荐做 base64 处理
     * @return string          加密后的内容
     */
     function user_mcrypt_encrypt($content, $key, $iv, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_CBC, $pkcs7 = true, $base64 = true)
    {
        //AES, 128 模式加密数据 CBC
        $content           = $pkcs7 ? addPKCS7Padding($content) : $content;
        $content_encrypted = mcrypt_encrypt($cipher, $key, $content, $mode, $iv);
        return $base64 ? base64_encode($content_encrypted) : $content_encrypted;
    }

    /**
     * 解密算法
     * @param  [type] $content_encrypted 待解密的内容
     * @param  [type] $key     加密key 注意 key 长度要求
     * @param  [type] $iv      加密向量 固定为16位可以保证与openssl的兼容性
     * @param  [type] $cipher  加密算法
     * @param  [type] $mode    加密模式
     * @param  bool $pkcs7     带解密内容是否使用了pkcs7填充 如果没使用则 mcrypt 会自动移除填充的 NUL("\0")
     * @param  bool $base64    是否对数据做 base64 处理
     * @return [type]          [description]
     */
     function user_mcrypt_decrypt($content_encrypted, $key, $iv, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_CBC, $pkcs7 = true, $base64 = true)
    {
        //AES, 128 模式加密数据 CBC
        $content_encrypted = $base64 ? base64_decode($content_encrypted) : $content_encrypted;
        $content           = mcrypt_decrypt($cipher, $key, $content_encrypted, $mode, $iv);
        // 解密后的内容 要根据填充算法来相应的移除填充数
        $content = $pkcs7 ? stripPKSC7Padding($content) : rtrim($content, "\0");
        return $content;
    }

    /**
     * PKCS7填充算法
     * @param string $source
     * @return string
     */
     function addPKCS7Padding($source, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_CBC)
    {
        $source = trim($source);
        $block  = mcrypt_get_block_size($cipher, $mode);
        $pad    = $block - (strlen($source) % $block);
        if ($pad <= $block) {
            $char = chr($pad);
            $source .= str_repeat($char, $pad);
        }
        return $source;
    }
    /**
     * 移去PKCS7填充算法
     * @param string $source
     * @return string
     */
     function stripPKSC7Padding($source)
    {
        $source = trim($source);
        $char   = substr($source, -1);
        $num    = ord($char);
        if ($num == 62) {
            return $source;
        }

        $source = substr($source, 0, -$num);
        return $source;
    }

    /**
     * NUL("\0")填充算法
     * @param string $source
     * @return string
     */
     function addZeroPadding($source, $cipher = MCRYPT_RIJNDAEL_128, $mode = MCRYPT_MODE_CBC)
    {
        $source = trim($source);
        // openssl 并没有提供加密cipher对应的数据块大小的api这点比较坑
        $block = mcrypt_get_block_size($cipher, $mode);
        $pad   = $block - (strlen($source) % $block);
        if ($pad <= $block) {
            // $source .= str_repeat("\0", $pad);//KISS写法
            // pack 方法 a 模式使用 NUL("\0") 对内容进行填充  A 模式则使用空白字符填充
            $source .= pack("a{$pad}", ""); //高端写法
        }
        return $source;
    }

    /**
     * NUL("\0")填充算法移除
     * @param string $source
     * @return string
     */
     function stripZeroPadding($source)
    {
        return rtrim($source, "\0");
    }

// 待加密内容
//$content = "hello worldhello worldhello worldhello worldhello worldhello world";

/*echo '使用 NUL("\0") 填充算法 不对结果做 base64 处理:' . PHP_EOL;
echo 'mcrypt 加密:' . PHP_EOL;
var_dump($data = user_mcrypt_encrypt($content, $key, $iv, $mcrypt_cipher, $mcrypt_mode, false, false));
echo 'openssl 解密:' . PHP_EOL;
// 需经过 NUL("\0") 填充加密后被 base64_encode 的数据 解密后续手动移除 NUL("\0")
var_dump(stripZeroPadding(openssl_decrypt(base64_encode($data), "AES-128-CBC", $key, OPENSSL_ZERO_PADDING, $iv)));
echo 'openssl 加密:' . PHP_EOL;
// 需对待处理的数据做 NUL("\0") 填充，且返回的数据被 base64_encode 编码了
var_dump($data = base64_decode(openssl_encrypt(addZeroPadding($content), "AES-128-CBC", $key, OPENSSL_ZERO_PADDING, $iv)));
echo 'mcrypt 解密:' . PHP_EOL;
var_dump(user_mcrypt_decrypt($data, $key, $iv, $mcrypt_cipher, $mcrypt_mode, false, false));
echo PHP_EOL;

echo '使用 NUL("\0") 填充算法 对结果做 base64 处理:' . PHP_EOL;
echo 'mcrypt 加密:' . PHP_EOL;
var_dump($data = user_mcrypt_encrypt($content, $key, $iv, $mcrypt_cipher, $mcrypt_mode, false, true));
echo 'openssl 解密:' . PHP_EOL;
var_dump(stripZeroPadding(openssl_decrypt($data, "AES-128-CBC", $key, OPENSSL_ZERO_PADDING, $iv)));
echo 'openssl 加密:' . PHP_EOL;
var_dump($data = openssl_encrypt(addZeroPadding($content), "AES-128-CBC", $key, OPENSSL_ZERO_PADDING, $iv));
echo 'mcrypt 解密:' . PHP_EOL;
var_dump(user_mcrypt_decrypt($data, $key, $iv, $mcrypt_cipher, $mcrypt_mode, false, true));
echo PHP_EOL;

echo "使用 pkcs7 填充算法 不对结果做 base64 处理" . PHP_EOL;
echo 'mcrypt 加密:' . PHP_EOL;
var_dump($data = user_mcrypt_encrypt($content, $key, $iv, $mcrypt_cipher, $mcrypt_mode, true, false));
echo 'openssl 解密:' . PHP_EOL;
var_dump(openssl_decrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv));
echo 'openssl 加密:' . PHP_EOL;
var_dump($data = openssl_encrypt($content, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv));
echo 'mcrypt 解密:' . PHP_EOL;
var_dump(user_mcrypt_decrypt($data, $key, $iv, $mcrypt_cipher, $mcrypt_mode, true, false));
echo PHP_EOL;*/
/*var_dump($iv);exit;
echo "使用 pkcs7 填充算法 对结果做 base64 处理（推荐）：" . PHP_EOL;
$key = "8oTvHQAsfEU8lLs9";*/
/*echo 'openssl 加密:' . PHP_EOL;
var_dump($data = openssl_encrypt($content, "AES-128-CBC", $key, 0));*/
/*echo 'openssl 解密:' . PHP_EOL;
$data = "opt22SQO554SA9kneeRmAIT5ttagcsDb6PuPFKIfdiY=";
var_dump(openssl_decrypt($data, "AES-128-CBC", $key, 0));*/
/*$str = "{'7':'Qa7EJk0lip9Nohhr'}";
var_dump(json_decode($str));*/