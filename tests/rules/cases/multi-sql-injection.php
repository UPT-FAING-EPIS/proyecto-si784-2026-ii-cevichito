<?php
$id = $_GET["id"];
// Regresión: el motor heredado no lo detectaba (docs/baseline-f0.md).
// ruleid: multi/sql-injection
$r = query("SELECT * FROM users WHERE id = " . $id);
// ok: multi/sql-injection
$s = $pdo->prepare("SELECT * FROM users WHERE id = ?");
