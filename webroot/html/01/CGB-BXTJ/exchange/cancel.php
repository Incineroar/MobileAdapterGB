<?php
require "/var/www/cgb/core/core.php";
require "/var/www/cgb/core/pokemon/func.php";
require "/var/www/cgb/core/database.php";

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // HTTP405 Method not Allowed.
    die("405 Method not Allowed"); // Exit but scarier!
};

$data = decodeExchange("php://input", true); // This makes a nice array of data.
$db = connectMySQL(); // Connect to DION Database!

$stmt = $db->prepare("DELETE FROM `pkm_trades` WHERE email = ?;"); // Delete the trade from Database.
$stmt->bind_param("s",$data["email"]);
$stmt->execute();

