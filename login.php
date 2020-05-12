<?php

 if($_POST['account']==='admin123'&&$_POST['password']==='admin123'){
 	$res = array('status'=>200);
 	
 }else if($_POST['account']==='admin456'&&$_POST['password']==='admin456'){
 	$res = array('status'=>200);
 }else{
 	$res = array('status'=>404);
 }
 exit(json_encode($res));