<?php
/**
	skygen function make hash of string
	@param string - String for hashing
	@param array - Options of hashing
	@return string - Hash
*/
function skygen($string,$options=array(
	array('size' => 5, 'position' => 8 ),
	array('size' => 6, 'position' => 0 ),
	array('size' => 5, 'position' => 30 ),
	array('size' => -1, 'position' => 20 ),
)){
	$sha512=hash('sha512', $string);
	$md5=md5($string);
	$chunks=array();
	foreach($options as $item){
		if($item['size']==-1) $chunk=$md5;
		else {
			$chunk=substr($md5,0,$item['size']);
			$md5=substr_replace($md5,'',0,$item['size']);
		}
		$chunks[$item['position']]=$chunk;
	}
	$keys=array_keys($chunks);
	sort($keys);
	$delta=0;
	foreach($keys as $key){
		$sha512=substr($sha512,0,$key+$delta).$chunks[$key].substr($sha512,$key+$delta);
		$delta+=strlen($chunks[$key]);
	}
	return hash('sha512', $sha512);
}
