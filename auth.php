<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * User key auth method.
 *
 * @package    auth_userkey
 * @copyright  2016 Dmitrii Metelkin (dmitriim@catalyst-au.net)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

use auth_userkey\core_userkey_manager;
use auth_userkey\userkey_manager_interface;

require_once($CFG->libdir . "/externallib.php");
require_once($CFG->libdir.'/authlib.php');

/**
 * User key authentication plugin.
 */
class auth_plugin_userkey extends auth_plugin_base {

    /**
     * Default mapping field.
     */
    const DEFAULT_MAPPING_FIELD = 'email';

    /**
     * User key manager.
     *
     * @var userkey_manager_interface
     */
    protected $userkeymanager;

    /**
     * Defaults for config form.
     *
     * @var array
     */
    protected $defaults = array(
        'mappingfield' => self::DEFAULT_MAPPING_FIELD,
        'keylifetime' => 60,
        'iprestriction' => 0,
        'redirecturl' => '',
        'ssourl' => '',
        // TODO: use this field when implementing user creation. 'createuser' => 0.
    );

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'userkey';
        $this->config = get_config('auth_userkey');
    }

    /**
     * All the checking happens before the login page in this hook
     */
    public function pre_loginpage_hook() {
        global $SESSION;

        // If we previously tried to skip SSO on, but then navigated
        // away, and come in from another deep link while SSO only is
        // on, then reset the previous session memory of forcing SSO.
        if (isset($SESSION->enrolkey_skipsso)) {
            unset($SESSION->enrolkey_skipsso);
        }
        $this->loginpage_hook();
    }

    /**
     * All the checking happens before the login page in this hook
     */
    public function loginpage_hook() {
        if ($this->should_login_redirect()) {
            redirect($this->config->ssourl);
        }
    }

    /**
     * Don't allow login using login form.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     *
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password) {
        return false;
    }

    /**
     * Login user using userkey and return URL to redirect after.
     *
     * @return mixed|string URL to redirect.
     *
     * @throws \moodle_exception If something went wrong.
     */
    public function user_login_userkey() {
        global $DB, $SESSION;

        $keyvalue = required_param('key', PARAM_ALPHANUM);
        $wantsurl = optional_param('wantsurl', '', PARAM_URL);

        $options = array(
            'script' => core_userkey_manager::CORE_USER_KEY_MANAGER_SCRIPT,
            'value' => $keyvalue
        );

        if (!$key = $DB->get_record('user_private_key', $options)) {
            print_error('invalidkey');
        }

        if (!isset($this->userkeymanager)) {
            $userkeymanager = new core_userkey_manager($key->userid, $this->config);
            $this->set_userkey_manager($userkeymanager);
        }

        $this->userkeymanager->delete_key();

        if (!empty($key->validuntil) and $key->validuntil < time()) {
            print_error('expiredkey');
        }

        if ($key->iprestriction) {
            $remoteaddr = getremoteaddr(null);
            if (empty($remoteaddr) or !address_in_subnet($remoteaddr, $key->iprestriction)) {
                print_error('ipmismatch');
            }
        }

        if (!$user = $DB->get_record('user', array('id' => $key->userid))) {
            print_error('invaliduserid');
        }

        $user = get_complete_user_data('id', $user->id);
        complete_user_login($user);

        // Identify this session as using user key auth method.
        $SESSION->userkey = true;

        if (!empty($wantsurl)) {
            return $wantsurl;
        } else {
            return '/';
        }
    }

    /**
     * Don't store local passwords.
     *
     * @return bool True.
     */
    public function prevent_local_passwords() {
        return true;
    }

    /**
     * Returns true if this authentication plugin is external.
     *
     * @return bool False.
     */
    public function is_internal() {
        return false;
    }

    /**
     * The plugin can't change the user's password.
     *
     * @return bool False.
     */
    public function can_change_password() {
        return false;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param object $config
     * @param object $err
     * @param array $userfields
     */
    public function config_form($config, $err, $userfields) {
        global $CFG, $OUTPUT;

        $config = (object) array_merge($this->defaults, (array) $config );
        include("settings.html");
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     *
     * @param object $form with submitted configuration settings (without system magic quotes)
     * @param array $err array of error messages
     *
     * @return array of any errors
     */
    public function validate_form($form, &$err) {
        if ((int)$form->keylifetime == 0) {
            $err['keylifetime'] = get_string('incorrectkeylifetime', 'auth_userkey');
        }

        if (!empty($form->redirecturl) && filter_var($form->redirecturl, FILTER_VALIDATE_URL) === false) {
            $err['redirecturl'] = get_string('incorrectredirecturl', 'auth_userkey');
        }
    }

    /**
     * Process and stores configuration data for this authentication plugin.
     *
     * @param object $config Config object from the form.
     *
     * @return bool
     */
    public function process_config($config) {
        foreach ($this->defaults as $key => $value) {
            if (!isset($this->config->$key) || $config->$key != $this->config->$key) {
                set_config($key, $config->$key, 'auth_userkey');
            }
        }

        return true;
    }

    /**
     * Set userkey manager.
     *
     * @param \auth_userkey\userkey_manager_interface $keymanager
     */
    public function set_userkey_manager(userkey_manager_interface $keymanager) {
        $this->userkeymanager = $keymanager;
    }

    /**
     * Return mapping field to find a lms user.
     *
     * @return string
     */
    public function get_mapping_field() {
        if (isset($this->config->mappingfield) && !empty($this->config->mappingfield)) {
            return $this->config->mappingfield;
        }

        return self::DEFAULT_MAPPING_FIELD;
    }

    /**
     * Check if we need to create a new user.
     *
     * @return bool
     */
    protected function should_create_user() {
        if (isset($this->config->createuser)) {
            return $this->config->createuser;
        }

        return false;
    }

    /**
     * Check if restriction by IP is enabled.
     *
     * @return bool
     */
    protected function is_iprestriction_enabled() {
        if (isset($this->config->iprestriction) && $this->config->iprestriction == true) {
            return true;
        }

        return false;
    }

    /**
     * Create a new user.
     */
    protected function create_user() {
        // TODO:
        // 1. Validate user
        // 2. Create user.
        // 3. Throw exception if something went wrong.
    }

    /**
     * Return login URL.
     *
     * @param array|stdClass $data User data.
     *
     * @return string Login URL.
     *
     * @throws \invalid_parameter_exception
     */
    public function get_login_url($data) {
        global $CFG, $DB;

        $data = (array)$data;
        $mappingfield = $this->get_mapping_field();

        if (!isset($data[$mappingfield]) || empty($data[$mappingfield])) {
            throw new invalid_parameter_exception('Required field "' . $mappingfield . '" is not set or empty.');
        }

        if ($this->is_iprestriction_enabled() && !isset($data['ip'])) {
            throw new invalid_parameter_exception('Required parameter "ip" is not set.');
        }

        $params = array(
            $mappingfield => $data[$mappingfield],
            'mnethostid' => $CFG->mnet_localhost_id,
        );

        $user = $DB->get_record('user', $params);

        if (empty($user)) {
            if (!$this->should_create_user()) {
                throw new invalid_parameter_exception('User is not exist');
            } else {
                $user = $this->create_user();
            }
        }

        if (!isset($this->userkeymanager)) {
            $ips = isset($data['ip']) ? $data['ip'] : null;
            $userkeymanager = new core_userkey_manager($user->id, $this->config, $ips);
            $this->set_userkey_manager($userkeymanager);
        }

        $userkey = $this->userkeymanager->create_key();

        return $CFG->wwwroot . '/auth/userkey/login.php?key=' . $userkey;
    }

    /**
     * Return a list of mapping fields.
     *
     * @return array
     */
    public function get_allowed_mapping_fields() {
        return array(
            'username' => get_string('username'),
            'email' => get_string('email'),
            'idnumber' => get_string('idnumber'),
        );
    }

    /**
     * Return a mapping parameter for request_login_url_parameters().
     *
     * @return array
     */
    protected function get_mapping_parameter() {
        $mappingfield = $this->get_mapping_field();

        switch ($mappingfield) {
            case 'username':
                $parameter = array(
                    'username' => new external_value(
                        PARAM_USERNAME,
                        'Username'
                    ),
                );
                break;

            case 'email':
                $parameter = array(
                    'email' => new external_value(
                        PARAM_EMAIL,
                        'A valid email address'
                    ),
                );
                break;

            case 'idnumber':
                $parameter = array(
                    'idnumber' => new external_value(
                        PARAM_RAW,
                        'An arbitrary ID code number perhaps from the institution'
                    ),
                );
                break;

            default:
                $parameter = array();
                break;
        }

        return $parameter;
    }

    /**
     * Return user fields parameters for request_login_url_parameters().
     *
     * @return array
     */
    protected function get_user_fields_parameters() {
        $parameters = array();

        if ($this->is_iprestriction_enabled()) {
            $parameters['ip'] = new external_value(
                PARAM_HOST,
                'User IP address'
            );
        }

        // TODO: add more fields here when we implement user creation.

        return $parameters;
    }

    /**
     * Return parameters for request_login_url_parameters().
     *
     * @return array
     */
    public function get_request_login_url_user_parameters() {
        $parameters = array_merge($this->get_mapping_parameter(), $this->get_user_fields_parameters());

        return $parameters;
    }

    /**
     * Check if we should redirect a user as part of login.
     *
     * @return bool
     */
    public function should_login_redirect() {
        global $SESSION;
        $skipsso = optional_param('enrolkey_skipsso', 0, PARAM_BOOL);

        // Check whether we've skipped SSO already.
        // This is here because loginpage_hook is called again during form
        // submission (all of login.php is processed) and ?skipsso=on is not
        // preserved forcing us to the SSO.
        if ((isset($SESSION->enrolkey_skipsso) && $SESSION->enrolkey_skipsso == 1)) {
            return false;
        }

        $SESSION->enrolkey_skipsso = $skipsso;

        // If SSO only is set and user is not passing the skip param
        // or has it already set in their session then redirect to the SSO URL.
        if (isset($this->config->ssourl) && $this->config->ssourl != '' && !$skipsso) {
            return true;
        }

    }

    /**
     * Check if we should redirect a user after logout.
     *
     * @return bool
     */
    protected function should_logout_redirect() {
        global $SESSION;

        if (!isset($SESSION->userkey)) {
            return false;
        }

        if (!isset($this->config->redirecturl)) {
            return false;
        }

        if (empty($this->config->redirecturl)) {
            return false;
        }

        return true;
    }


    /**
     * Logout page hook.
     *
     * Override redirect URL after logout.
     *
     * @see auth_plugin_base::logoutpage_hook()
     */
    public function logoutpage_hook() {
        global $redirect;

        if ($this->should_logout_redirect()) {
            $redirect = $this->config->redirecturl;
        }
    }
}
