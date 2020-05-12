<?php 
 require_once "rsa/my_rsa.php";
 //require_once "aes/aes.php";
//创建websocket服务器对象，监听0.0.0.0:9502端口
$ws_server = new swoole_websocket_server('0.0.0.0', 9502);
 
//设置server运行时的各项参数
$ws_server->set(array(
	'daemonize' => true, //是否作为守护进程
));
 
//监听WebSocket连接打开事件
$ws_server->on('open', function ($ws, $request) {
	//1：当前所有在线用户fd 
	$all_online_fd = file_get_contents( __DIR__ .'/online.txt');
	if(!$all_online_fd){
		if($request->fd){
			file_put_contents( __DIR__ .'/online.txt' , $request->fd);
		}
	}else{
		$all_online_fd = $all_online_fd.','.$request->fd;
		if($all_online_fd){
			file_put_contents( __DIR__ .'/online.txt' , $all_online_fd);
		}
	}
});
 
//监听WebSocket消息事件
$ws_server->on('message', function ($ws, $frame) {
	$data = json_decode($frame->data,true);
	if($data['status']=='onOpen'){
		pushMessage1($ws,$frame);
	}else{
		pushMessage($ws,$frame);
	}
	
});
 
//监听WebSocket连接关闭事件
$ws_server->on('close', function ($ws, $fd) {
	//echo "client-{$fd} is closed\n";
	//1：当前所有在线用户fd 
	$all_online_fd = file_get_contents( __DIR__ .'/online.txt');
	$all_online_fd_array = explode(",", $all_online_fd);
	$index = array_search($fd,$all_online_fd_array);
	if($index!==false){
		unset($all_online_fd_array[$index]);
	}
	file_put_contents( __DIR__ .'/online.txt' , join(",",$all_online_fd_array));
	//2:所有用户fd对应的aes_key
	$all_keys_str = file_get_contents( __DIR__ .'/keys.txt');
	$all_keys_array = json_decode($all_keys_str,true);
	if(isset($all_keys_array[$fd])){
		unset($all_keys_array[$fd]);
		if($all_keys_array){
			file_put_contents( __DIR__ .'/keys.txt' , json_encode($all_keys_array));
		}else{
			file_put_contents( __DIR__ .'/keys.txt' , '');
		}
		
	}
	//iv
	$all_ivs_str = file_get_contents( __DIR__ .'/ivs.txt');
	$all_ivs_array = json_decode($all_ivs_str,true);
	if(isset($all_ivs_array[$fd])){
		unset($all_ivs_array[$fd]);
		if($all_ivs_array){
			file_put_contents( __DIR__ .'/ivs.txt' , json_encode($all_ivs_array));
		}else{
			file_put_contents( __DIR__ .'/ivs.txt' , '');
		}
		
	}
});
 
$ws_server->start();



//消息推送
function pushMessage($ws,$frame){
	$data = json_decode($frame->data,true);
	$data_text = $data['text'];
	//$data_key = $data['key'];
	$rsa = new Rsa();
	$data_text = $rsa->privDecrypt($data_text);

	/*$data_text = trim($data_text);  
    $data_text = strip_tags($data_text);   
    $data_text = htmlspecialchars($data_text);     
    $data_text = addslashes($data_text);  */

	/*$all_keys_str = file_get_contents( __DIR__ .'/keys.txt');
	$all_keys_array = json_decode($all_keys_str,true);
	$data_key = $all_keys_array[$frame->fd];*/
	//$data_text = openssl_encrypt($data_text, "AES-128-CBC", $data_key, 0);
	$all_online_fd = file_get_contents( __DIR__ .'/online.txt');
	$all_online_fd_array = explode(",", $all_online_fd);
	$all_keys_str = file_get_contents( __DIR__ .'/keys.txt');
	$all_keys_array = json_decode($all_keys_str,true);
	$all_ivs_str = file_get_contents( __DIR__ .'/ivs.txt');
	$all_ivs_array = json_decode($all_ivs_str,true);
	foreach ($all_online_fd_array as $k => $fd) {
		$data_key = $all_keys_array[$fd];
		$data_iv = $all_ivs_array[$fd];
		$ws->push($fd,openssl_encrypt($frame->fd.' : '.$data_text, "AES-128-CBC", $data_key,0,$data_iv));
	}
}


function pushMessage1($ws,$frame){
	//2:所有用户fd对应的aes_key
	$data = json_decode($frame->data,true);
	$data_key = $data['key'];
	
	$rsa = new Rsa();
	$data_key = $rsa->privDecrypt($data_key);
	$all_keys_str = file_get_contents( __DIR__ .'/keys.txt');
	if(!$all_keys_str){
		$str = '{"'.$frame->fd.'":"'.$data_key.'"}';
		file_put_contents( __DIR__ .'/keys.txt' , $str);
	}else{
		$all_keys_array = json_decode($all_keys_str,true);
		$all_keys_array[$frame->fd] = $data_key;
		$all_keys_str = json_encode($all_keys_array);
		file_put_contents( __DIR__ .'/keys.txt' , $all_keys_str);
	}
	//iv
	$data_iv = $data['iv'];
	$data_iv = $rsa->privDecrypt($data_iv);
	$all_ivs_str = file_get_contents( __DIR__ .'/ivs.txt');
	if(!$all_ivs_str){
		$str = '{"'.$frame->fd.'":"'.$data_iv.'"}';
		file_put_contents( __DIR__ .'/ivs.txt' , $str);
	}else{
		$all_ivs_array = json_decode($all_ivs_str,true);
		$all_ivs_array[$frame->fd] = $data_iv;
		$all_ivs_str = json_encode($all_ivs_array);
		file_put_contents( __DIR__ .'/ivs.txt' , $all_ivs_str);
	}
}
	