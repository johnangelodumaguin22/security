<?php
include __DIR__ . '/db_connect.php'; // adjust path relative to this file

header('Content-Type: application/json; charset=utf-8');

if (!isset($_POST['email'])) {
    echo json_encode(['exists' => false, 'message' => '']);
    exit;
}

$email = strtolower(trim($_POST['email']));

// Email is optional — empty is not an error, just nothing to check.
if ($email === '') {
    echo json_encode(['exists' => false, 'message' => '']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['exists' => false, 'message' => '❌ Enter a valid email address.']);
    exit;
}

$stmt = $conn->prepare("SELECT COUNT(*) FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->bind_result($count);
$stmt->fetch();
$stmt->close();

if ($count > 0) {
    echo json_encode(['exists' => true, 'message' => '❌ Email already registered.']);
} else {
    echo json_encode(['exists' => false, 'message' => '✅ Email is available.']);
}

$conn->close();
