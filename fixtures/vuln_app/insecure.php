<?php
// Intentionally vulnerable fixture for end-to-end tests.
// Never deployed - this file exists only so the test suite can
// verify the static engine finds sqli + xss in a real scan run.
$conn = mysqli_connect("localhost", "root", "", "test");

// SQLi - direct concatenation (php-sqli-mysqli-get)
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// SQLi - taint (php-sqli-taint-get)
$uid = $_GET['uid'];
mysqli_query($conn, "SELECT * FROM users WHERE id = $uid");

// XSS - direct echo (php-xss-echo-get)
echo $_GET['name'];

// XSS - taint (php-xss-taint-get)
$msg = $_GET['msg'];
echo "Message: " . $msg;
?>
