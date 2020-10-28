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
require_once($CFG->dirroot . '/user/lib.php');

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
        'ipwhitelist' => '',
        'redirecturl' => '',
        'ssourl' => '',
        'createuser' => false,
        'updateuser' => false,
    );

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'userkey';
        $this->config = get_config('auth_userkey');
        $this->userkeymanager = new core_userkey_manager($this->config);
    }

    /**
     * All the checking happens before the login page in this hook.
     *
     * It redirects a user if required or return true.
     */
    public function pre_loginpage_hook() {
        global $SESSION;

        // If we previously tried to skip SSO on, but then navigated
        // away, and come in from another deep link while SSO only is
        // on, then reset the previous session memory of forcing SSO.
        if (isset($SESSION->enrolkey_skipsso)) {
            unset($SESSION->enrolkey_skipsso);
        }

        return $this->loginpage_hook();
    }

    /**
     * All the checking happens before the login page in this hook.
     *
     * It redirects a user if required or return true.
     */
    public function loginpage_hook() {
        if ($this->should_login_redirect()) {
            $this->redirect($this->config->ssourl);
        }

        return true;
    }

    /**
     * Redirects the user to provided URL.
     *
     * @param $url URL to redirect to.
     *
     * @throws \moodle_exception If gets running via CLI or AJAX call.
     */
    protected function redirect($url) {
        if (CLI_SCRIPT or AJAX_SCRIPT) {
            throw new moodle_exception('redirecterrordetected', 'auth_userkey', '', $url);
        }

        redirect($url);
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
     * Logs a user in using userkey and redirects after.
     *
     * @TODO: refactor this method to make it easy to read.
     *
     * @throws \moodle_exception If something went wrong.
     */
    public function user_login_userkey() {
        global $SESSION, $CFG, $USER;

        $keyvalue = required_param('key', PARAM_ALPHANUM);
        $wantsurl = optional_param('wantsurl', '', PARAM_URL);

        if (!empty($wantsurl)) {
            $redirecturl = $wantsurl;
        } else {
            $redirecturl = $CFG->wwwroot;
        }

        try {
            $key = $this->userkeymanager->validate_key($keyvalue);
        } catch (moodle_exception $exception) {
            print_error($exception->errorcode);
        }

        if (isloggedin()) {
            if ($USER->id == $key->userid) {
                // Don't process further if the user is already logged in.
                $this->userkeymanager->delete_keys($key->userid);
                $this->redirect($redirecturl);
            }
        }

        $this->userkeymanager->delete_keys($key->userid);

        $user = get_complete_user_data('id', $key->userid);
        complete_user_login($user);

        // Identify this session as using user key auth method.
        $SESSION->userkey = true;

        $this->redirect($redirecturl);
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
     * Set userkey manager.
     *
     * This function is the only way to inject dependency, because of the way auth plugins work.
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
        if (isset($this->config->createuser) && $this->config->createuser == true) {
            return true;
        }

        return false;
    }

    /**
     * Check if we need to update users.
     *
     * @return bool
     */
    protected function should_update_user() {
        if (isset($this->config->updateuser) && $this->config->updateuser == true) {
            return true;
        }

        return false;
    }

    /**
     * Check if restriction by IP is enabled.
     *
     * @return bool
     */
    protected function is_ip_restriction_enabled() {
        if (isset($this->config->iprestriction) && $this->config->iprestriction == true) {
            return true;
        }

        return false;
    }

    /**
     * Create a new user.
     *
     * @param array $data Validated user data from web service.
     *
     * @return object User object.
     */
    protected function create_user(array $data) {
        global $DB, $CFG;

        $user = $data;
        unset($user['ip']);
        $user['auth'] = 'userkey';
        $user['confirmed'] = 1;
        $user['mnethostid'] = $CFG->mnet_localhost_id;

        $requiredfieds = ['username', 'email', 'firstname', 'lastname'];
        $missingfields = [];
        foreach ($requiredfieds as $requiredfied) {
            if (empty($user[$requiredfied])) {
                $missingfields[] = $requiredfied;
            }
        }
        if (!empty($missingfields)) {
            throw new invalid_parameter_exception('Unable to create user, missing value(s): ' . implode(',', $missingfields));
        }

        if ($DB->record_exists('user', array('username' => $user['username'], 'mnethostid' => $CFG->mnet_localhost_id))) {
            throw new invalid_parameter_exception('Username already exists: '.$user['username']);
        }
        if (!validate_email($user['email'])) {
            throw new invalid_parameter_exception('Email address is invalid: '.$user['email']);
        } else if (empty($CFG->allowaccountssameemail) &&
            $DB->record_exists('user', array('email' => $user['email'], 'mnethostid' => $user['mnethostid']))) {
            throw new invalid_parameter_exception('Email address already exists: '.$user['email']);
        }

        $userid = user_create_user($user);
        return $DB->get_record('user', ['id' => $userid]);
    }

    /**
     * Update an existing user.
     *
     * @param stdClass $user Existing user record.
     * @param array $data Validated user data from web service.
     *
     * @return object User object.
     */
    protected function update_user(\stdClass $user, array $data) {
        global $DB, $CFG;

        $userdata = $data;
        unset($userdata['ip']);
        $userdata['auth'] = 'userkey';

        $changed = false;
        foreach ($userdata as $key => $value) {
            if ($user->$key != $value) {
                $changed = true;
                break;
            }
        }

        if (!$changed) {
            return $user;
        }

        if (
            $user->username != $userdata['username']
            &&
            $DB->record_exists('user', array('username' => $userdata['username'], 'mnethostid' => $CFG->mnet_localhost_id))
        ) {
            throw new invalid_parameter_exception('Username already exists: '.$userdata['username']);
        }
        if (!validate_email($userdata['email'])) {
            throw new invalid_parameter_exception('Email address is invalid: '.$userdata['email']);
        } else if (
            empty($CFG->allowaccountssameemail)
            &&
            $user->email != $userdata['email']
            &&
            $DB->record_exists('user', array('email' => $userdata['email'], 'mnethostid' => $CFG->mnet_localhost_id))
        ) {
            throw new invalid_parameter_exception('Email address already exists: '.$userdata['email']);
        }
        $userdata['id'] = $user->id;

        $userdata = (object) $userdata;
        user_update_user($userdata, false);
        return $DB->get_record('user', ['id' => $user->id]);
    }

    /**
     * Validate user data from web service.
     *
     * @param mixed $data User data from web service.
     *
     * @return array
     *
     * @throws \invalid_parameter_exception If provided data is invalid.
     */
    protected function validate_user_data($data) {
        $data = (array)$data;

        $mappingfield = $this->get_mapping_field();

        if (!isset($data[$mappingfield]) || empty($data[$mappingfield])) {
            throw new invalid_parameter_exception('Required field "' . $mappingfield . '" is not set or empty.');
        }

        if ($this->is_ip_restriction_enabled() && !isset($data['ip'])) {
            throw new invalid_parameter_exception('Required parameter "ip" is not set.');
        }

        return $data;
    }

    /**
     * Return user object.
     *
     * @param array $data Validated user data.
     *
     * @return object A user object.
     *
     * @throws \invalid_parameter_exception If user is not exist and we don't need to create a new.
     */
    protected function get_user(array $data) {
        global $DB, $CFG;

        $mappingfield = $this->get_mapping_field();

        $params = array(
            $mappingfield => $data[$mappingfield],
            'mnethostid' => $CFG->mnet_localhost_id,
        );

        $user = $DB->get_record('user', $params);

        if (empty($user)) {
            if ($this->should_create_user()) {
                $user = $this->create_user($data);
            } else {
                throw new invalid_parameter_exception('User is not exist');
            }
        } else if ($this->should_update_user()) {
            $user = $this->update_user($user, $data);
        }

        return $user;
    }

    /**
     * Return allowed IPs from user data.
     *
     * @param array $data Validated user data.
     *
     * @return null|string Allowed IPs or null.
     */
    protected function get_allowed_ips(array $data) {
        if (isset($data['ip']) && !empty($data['ip'])) {
            return $data['ip'];
        }

        return null;
    }

    /**
     * Generate login user key.
     *
     * @param array $data Validated user data.
     *
     * @return string
     * @throws \invalid_parameter_exception
     */
    protected function generate_user_key(array $data) {
        $user = $this->get_user($data);
        $ips = $this->get_allowed_ips($data);

        return $this->userkeymanager->create_key($user->id, $ips);
    }

    /**
     * Return login URL.
     *
     * @param array|stdClass $data User data from web service.
     *
     * @return string Login URL.
     *
     * @throws \invalid_parameter_exception
     */
    public function get_login_url($data) {
        global $CFG;

        $userdata = $this->validate_user_data($data);
        $userkey  = $this->generate_user_key($userdata);

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

        if ($this->is_ip_restriction_enabled()) {
            $parameters['ip'] = new external_value(
                PARAM_HOST,
                'User IP address'
            );
        }

        $mappingfield = $this->get_mapping_field();
        if ($this->should_create_user() || $this->should_update_user()) {
            $parameters['firstname'] = new external_value(PARAM_NOTAGS, 'The first name(s) of the user', VALUE_OPTIONAL);
            $parameters['lastname']  = new external_value(PARAM_NOTAGS, 'The family name of the user', VALUE_OPTIONAL);

            if ($mappingfield != 'email') {
                $parameters['email'] = new external_value(PARAM_RAW_TRIMMED, 'A valid and unique email address', VALUE_OPTIONAL);
            }
            if ($mappingfield != 'username') {
                $parameters['username'] = new external_value(PARAM_USERNAME, 'A valid and unique username', VALUE_OPTIONAL);
            }
        }

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
    protected function should_login_redirect() {
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

    /**
     * Log out user and redirect.
     */
    public function user_logout_userkey() {
        global $CFG, $USER;

        $redirect = required_param('return', PARAM_URL);

        // We redirect when user's session in Moodle already has expired
        // or the user is still logged in using "userkey" auth type.
        if (!isloggedin() || $USER->auth == 'userkey') {
            require_logout();
            $this->redirect($redirect);
        } else {
            // If logged in with different auth type, then display an error.
            print_error('incorrectlogout', 'auth_userkey', $CFG->wwwroot);
        }
    }
}
