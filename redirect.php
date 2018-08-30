<?php

require_once(dirname(__FILE__) . '/../../../wp-load.php');
require_once "class.spaces-oauth.php";

$oauth = new MittwaldSpacesOauth;
$url = $oauth->getRedirectUrl();

if (!$url) {
    throw new InvalidArgumentException('redirect url to spaces oauth no present!');
}

header('Location: ' . $oauth->getRedirectUrl());
die();