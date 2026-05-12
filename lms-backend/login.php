<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");

if ($_SERVER["REQUEST_METHOD"] === "OPTIONS") {
    http_response_code(200);
    exit;
}

include "db.php";

$data = json_decode(file_get_contents("php://input"), true);

$email = $data["email"] ?? "";
$password = $data["password"] ?? "";

if (empty($email) || empty($password)) {
    echo json_encode([
        "success" => false,
        "message" => "Email and password are required."
    ]);
    exit;
}

$stmt = $conn->prepare("SELECT * FROM users WHERE email = ? LIMIT 1");

if (!$stmt) {
    echo json_encode([
        "success" => false,
        "message" => "SQL error: " . $conn->error
    ]);
    exit;
}

$stmt->bind_param("s", $email);
$stmt->execute();

$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo json_encode([
        "success" => false,
        "message" => "User not found."
    ]);
    exit;
}

$user = $result->fetch_assoc();

if ($password !== $user["password"]) {
    echo json_encode([
        "success" => false,
        "message" => "Incorrect password."
    ]);
    exit;
}

echo json_encode([
    "success" => true,
    "message" => "Login successful.",
    "user" => [
        "id" => $user["id"] ?? "",
        "name" => $user["name"] ?? "",
        "email" => $user["email"] ?? "",
        "role" => $user["role"] ?? "student"
    ]
]);
?>