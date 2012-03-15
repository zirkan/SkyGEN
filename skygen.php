<?php
/**
	skygen function make hash of string
	@param string - String for hashing
	@param array - Options of hashing
	@return string - Hash
*/
function skygen($string,$options=array(
	5/*size of chunk of md5 hash*/ => 8 /*position this chunk in sha1 hash*/,
	6 => 12,
	3 => 0,
	10 => 30,
	-1 => 20,
)){
	$sha1=sha1($string);
	$md5=md5($string);
	$chunks=array();
	foreach($options as $chunkSize=>$pos){
		if($chunkSize==-1) $chunk=$md5;
		else {
			$chunk=substr($md5,0,$chunkSize);
			$md5=substr_replace($md5,'',0,$chunkSize);
		}
		$chunks[$pos]=$chunk;
	}
	$keys=array_keys($chunks);
	sort($keys);
	$delta=0;
	foreach($keys as $key){
		$delta+=$key;
		$sha1=substr($sha1,0,$delta).$chunks[$key].substr($sha1,$delta+1);
	}
	return sha1($sha1);
}
