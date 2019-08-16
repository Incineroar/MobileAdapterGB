<?php
#error_reporting(E_ALL & ~E_NOTICE & ~E_STRICT);
#mb_http_output('UTF-8');

global $db;

function connectMySQL(){
	global $db;

	if(!$db) $db = new mysqli('127.0.0.1', 'USER', 'PASS', 'DB');
	return $db;
}

function fancy_get_result(&$stmt) {
	$result = array();
	$stmt->store_result();
	for($i = 0; $i < $stmt->num_rows; $i++) {
		$meta = $stmt->result_metadata();
		$params = array();
		while ( $field = $meta->fetch_field() ) {
			$params[] = &$result[ $i ][ $field->name ];
		}
		call_user_func_array(array($stmt, 'bind_result'), $params);
		$stmt->fetch();
	}
	$stmt->close();
	return $result;
}
