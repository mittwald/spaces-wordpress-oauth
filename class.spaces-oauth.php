<?php

/**
 * Class MittwaldSpacesOauth
 */
class MittwaldSpacesOauth
{
    CONST SESSION_OAUTH_SPACES_CSRF = 'spaces/csrf';
    CONST DEFAULT_CLIENT_ID = 'spaces.de/oauth/cms/wordpress/%spaceID%';
    CONST DEFAULT_USER_GROUP = 'subscriber';

    /** @var array */
    private $loginMessages = [];

    /**
     * MittwaldSpacesOauth constructor.
     */
    public function __construct()
    {
        if (!session_id()) {
            session_start();
        }
    }

    /**
     * @return void
     */
    public function init()
    {
        add_action('login_form', [$this, 'appendBackendLoginTemplate']);
        add_filter('login_message', [$this, 'loginMessages']);

        add_filter('authenticate', [$this, 'onAuthenticate'], 10, 0);
        add_filter('authenticate', [$this, 'afterAuthenticate'], 30, 3);

        add_action('admin_menu', [$this, 'initAdminMenu']);
    }

    /**
     * Init Admin Menü
     */
    function initAdminMenu()
    {
        add_menu_page(
            'SPACES OAuth',
            'SPACES OAuth',
            'administrator',
            __FILE__,
            [$this, 'initAdminSettingsTemplate'],
            plugins_url('/images/spaces-16x16.png', __FILE__)
        );

        add_action('admin_init', [$this, 'initAdminSettings']);
    }

    /**
     * Register Admin Settings
     */
    function initAdminSettings()
    {
        register_setting('space-oauth-settings-group', 'spaces_oauth_default_user_group', [
            'default' => self::DEFAULT_USER_GROUP,
        ]);
        register_setting('space-oauth-settings-group', 'spaces_oauth_space_id');
        register_setting('space-oauth-settings-group', 'spaces_oauth_client_id', [
            'default' => self::DEFAULT_CLIENT_ID,
        ]);
    }

    /**
     * Init Admin Settings
     */
    function initAdminSettingsTemplate()
    {
        ?>
        <div class="wrap">
            <h1>SPACES OAuth</h1>
            <form method="post" action="options.php">
                <?php settings_fields('space-oauth-settings-group'); ?>
                <?php do_settings_sections('space-oauth-settings-group'); ?>
                <table class="form-table">
                    <tr valign="top">
                        <th scope="row">SPACE ID</th>
                        <td>
                            <input style="width:100%" type="text" name="spaces_oauth_space_id"
                                   value="<?php echo esc_attr(get_option('spaces_oauth_space_id')); ?>"/><br/>
                            Leave empty to get the SPACE_ID over environment variable `SPACES_SPACE_ID`
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">CLIENT ID</th>
                        <td>
                            <input style="width:100%" type="text" name="spaces_oauth_client_id"
                                   value="<?php echo esc_attr(get_option('spaces_oauth_client_id')); ?>"/><br/>
                            Leave empty to get the CLIENT_ID over environment variable `SPACES_OAUTH_CLIENT_ID`<br />
                            DEFAULT: <?php echo self::DEFAULT_CLIENT_ID ?>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">DEFAULT ROLE</th>
                        <td>
                            <select name="spaces_oauth_default_user_group">
                                <?php foreach($this->getAvailableRoles() as $role): ?>
                                    <option value="<?php echo esc_attr($role); ?>">
                                        <?php echo esc_attr($role); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }

    /**
     * @return string
     */
    function loginMessages()
    {
        $messages = $this->loginMessages;
        if (count($messages) == 0) {
            return '';
        }

        $messageHTML = '';
        foreach ($messages as $message) {
            $messageHTML .= '<div id="login_error" class="message">' . $message . '</div>';
        }

        return $messageHTML;
    }

    /**
     * @return void
     */
    function appendBackendLoginTemplate()
    {
        ?>
        <p class="spaces-oauth">
            <a class="button" href="?oauthSpaces">SPACES OAUTH Login</a>
        </p>
        <br>
        <?php
    }

    /**
     * @return WP_User|boolean
     */
    function onAuthenticate()
    {
        if(isset($_GET['oauthSpaces'])) {
            header('Location: ' . $this->getRedirectUrl());
            die();
        }

        $code = isset($_GET['code']) ? $_GET['code'] : null;
        $state = isset($_GET['state']) ? $_GET['state'] : null;

        $error = isset($_GET['error']) ? $_GET['error'] : null;
        $errorDescription = isset($_GET['error_description']) ? $_GET['error_description'] : null;

        if ($error) {
            $this->addLoginMessage('<b>'.$error.':</b><br />' . $errorDescription);
            return false;
        }

        if ($code && $state) {
            try {
                if ($_SESSION[self::SESSION_OAUTH_SPACES_CSRF] !== $state || !$code) {
                    $this->addLoginMessage("SPACES Login failed! Token invalid");
                    return false;
                }

                $oAuthProvider = $this->getAuthProvider();
                $accessToken = $oAuthProvider->getAccessToken('authorization_code', [
                    'code' => $code,
                ]);

                $owner = $oAuthProvider->getResourceOwner($accessToken);

                if(!$owner->getId()) {
                    $this->addLoginMessage("SPACES Login failed! Missing ownerID");
                    return false;
                }

                $user = $this->getUser($owner);

                wp_set_current_user($user->ID, $user->user_login);
                wp_set_auth_cookie($user->ID);

                return $user;

            } catch (Exception $e) {

                $this->addLoginMessage("SPACES Login failed!");
            }
        }

        return false;
    }

    /**
     * @param $user
     * @param $username
     * @param $password
     * @return bool
     */
    function afterAuthenticate($user, $username, $password)
    {

        if ($username && $password && $user) {
            $spaceOwnerId = get_user_meta($user->ID, 'spaces_owner_id', true);

            if ($spaceOwnerId) {
                return false;
            }
        }

        return $user;
    }

    /**
     * @return \Mw\Spaces\OAuth2\SpacesProvider
     */
    function getAuthProvider()
    {
        require_once __DIR__ . '/vendor/autoload.php';

        $environment = $this->getEnvironment();
        $spaceID = $this->getSpaceId();
        $clientID = $this->getClientID();

        if ($spaceID === null) {
            throw new InvalidArgumentException('missing spaces oauth spaceID - provide via env variable `SPACES_SPACE_ID` or in wp settings');
        }

        if (!$clientID) {
            throw new InvalidArgumentException('missing spaces oauth clientID - provide via env variable `SPACES_OAUTH_CLIENT_ID` or in wp settings');
        }

        $environment['SPACES_SPACE_ID'] = $spaceID;
        $environment['SPACES_OAUTH_CLIENT_ID'] = $clientID;

        $oauthContext = new \Mw\Spaces\OAuth2\StaticContext(wp_login_url());
        $oauthOptions = new \Mw\Spaces\OAuth2\EnvironmentOptions($environment);

        return new \Mw\Spaces\OAuth2\SpacesProvider($oauthOptions, $oauthContext);
    }

    /**
     * @return string
     */
    function getRedirectUrl()
    {
        $provider = $this->getAuthProvider();

        $redirectUrl = $provider->getAuthorizationUrl();
        $stateCSRF = $provider->getState();

        $_SESSION[self::SESSION_OAUTH_SPACES_CSRF] = $stateCSRF;

        return $redirectUrl;
    }

    /**
     * @param \Mw\Spaces\OAuth2\SpacesResourceOwner $owner
     * @return WP_User
     */
    private function getUser(\Mw\Spaces\OAuth2\SpacesResourceOwner $owner)
    {
        $user = get_user_by('email', $owner->getEmailAddress());

        if ($user) {
            return $user;
        }

        $user_id = wp_create_user(
            $owner->getFullName(),
            wp_generate_password(),
            $owner->getEmailAddress()
        );

        $user = new WP_User($user_id);
        $user->set_role(
            get_option('spaces_oauth_default_user_group', self::DEFAULT_USER_GROUP)
        );

        wp_update_user($user);
        add_user_meta($user_id, 'spaces_owner_id', $owner->getId());

        return get_user_by('id', $user_id);
    }

    /**
     * @return array
     */
    private function getAvailableRoles() {
        return array_keys(
            get_editable_roles()
        );
    }

    /**
     * @param $message
     */
    private function addLoginMessage($message)
    {
        $this->loginMessages[] = $message;
    }

    /**
     * @return array
     */
    private function getEnvironment()
    {
        return $_SERVER;
    }

    /**
     * @return mixed|null
     */
    private function getSpaceId()
    {
        $env = $this->getEnvironment();
        $spaceID = isset($env['SPACES_SPACE_ID']) ? $env['SPACES_SPACE_ID'] : null;

        if (!$spaceID) {
            return get_option('spaces_oauth_space_id', null);
        }

        return $spaceID;
    }

    /**
     * @return mixed|null
     */
    private function getClientID()
    {
        $env = $this->getEnvironment();
        $clientID = isset($env['SPACES_OAUTH_CLIENT_ID']) ? $env['SPACES_OAUTH_CLIENT_ID'] : null;

        if (!$clientID) {
            $clientID = get_option('spaces_oauth_client_id', self::DEFAULT_CLIENT_ID);
        }

        $clientID = str_replace('%spaceID%', $this->getSpaceId(), $clientID);

        return $clientID;
    }
}
