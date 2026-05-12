<?php
header("Content-Type: application/json");
include "db.php";

echo json_encode([
    "success" => true,
    "message" => "Connected to MSU LMS database successfully."
]);
?>