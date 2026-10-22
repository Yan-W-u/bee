<?php
function find($name) {
    $sql = "SELECT id FROM users WHERE name = '" . $_GET['n'] . "'";
    return mysqli_query(connect(), $sql);
}
