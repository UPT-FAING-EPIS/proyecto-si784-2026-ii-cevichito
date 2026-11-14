<?php
// ruleid: multi/insecure-deserialization
$obj = unserialize($_COOKIE["data"]);
// ok: multi/insecure-deserialization
$ok = json_decode($_COOKIE["data"], true);
