<?php
/*
Plugin Name: SPACES OAuth Plugin
Plugin URI: https://github.com/mittwald/spaces-wordpress-oauth
Description: Wordpress Plugin implementing Mittwald SPACES OAuth for backend Logins
Version: 1.0.0
Author: Mittwald CM Service GmbH & Co. KG
Author URI: https://www.mittwald.de
License: MIT
Text Domain: spaces
*/

if (!function_exists( 'add_action' )) {
	die('it\'s dangerous to go alone! stop here pal.');
}

require_once "class.spaces-oauth.php";

$spacesOauth = new MittwaldSpacesOauth;
add_action('plugins_loaded', [$spacesOauth, 'init']);