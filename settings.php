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
 * Admin settings and defaults.
 *
 * @package auth_userkey
 * @copyright  2016 Dmitrii Metelkin - Modified by Alessandro Romani JAN/2018
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
defined('MOODLE_INTERNAL') || die;
$yesno = array(get_string('no'), get_string('yes'));
$fields = get_auth_plugin('userkey')->get_allowed_mapping_fields();
if ($ADMIN->fulltree) {

    //MAPPING FIELD
    $settings->add(new admin_setting_configselect(
        'auth_userkey/mappingfield',
        get_string('mappingfield', 'auth_userkey'),
        get_string('mappingfield_desc', 'auth_userkey'),
        0, $fields));

    //KEY LIFETIME
    $settings->add(new admin_setting_configtext(
        'auth_userkey/keylifetime',
        get_string('keylifetime', 'auth_userkey'),
        get_string('keylifetime_desc', 'auth_userkey'),
        ''));


    //IP RESTRICTIONS
    $settings->add(new admin_setting_configtext(
        'auth_userkey/iprestriction',
        get_string('iprestriction', 'auth_userkey'),
        get_string('iprestriction_desc', 'auth_userkey'),
        ''));

    //KIP WHITELIST
    $settings->add(new admin_setting_configtext(
        'auth_userkey/ipwhitelist',
        get_string('ipwhitelist', 'auth_userkey'),
        get_string('ipwhitelist_desc', 'auth_userkey'),
        ''));

    //URL REDIRECT
    $settings->add(new admin_setting_configtext(
        'auth_userkey/redirecturl',
        get_string('redirecturl', 'auth_userkey'),
        get_string('redirecturl_desc', 'auth_userkey'),
        ''));

    //URL SSO
    $settings->add(new admin_setting_configtext(
        'auth_userkey/ssourl',
        get_string('ssourl', 'auth_userkey'),
        get_string('ssourll_desc', 'auth_userkey'),
        ''));

    $options = array(
        'NO',
        'YES'
    );

    //CREATE USER?
    $settings->add(new admin_setting_configselect('auth_userkey/createuser',
        new lang_string('createuser', 'auth_userkey'),
        new lang_string('createuser_desc', 'auth_userkey'), 0, $options));

    //UPDATE USER?
    $settings->add(new admin_setting_configselect('auth_userkey/updateuser',
        new lang_string('updateuser', 'auth_userkey'),
        new lang_string('updateuser_desc', 'auth_userkey'), 0, $options));
}
