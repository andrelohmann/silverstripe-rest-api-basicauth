<?php

namespace Ntb\APIBasicAuth;

/**
 * Authenticator for the Member
 *
 * @author Andre Lohmann <lohmann.andre@gmail.com>
 * @package silverstripe-rest-api-basicauth
 */
class Authenticator extends \Object {

	/**
	 * Attempt to find and authenticate member if possible from the given data
	 *
	 * @param array $data
	 * @param bool &$success Success flag
	 * @return \Member Found member, regardless of successful authentication
	 */
	protected static function authenticate_member($data, &$success) {
		// Default success to false
		$success = false;

		// Attempt to identify by temporary ID
		$member = null;

		$member = \Member::get()->filter("Email", $data['Email'])->first();

		// Validate against member if possible
		if($member) {
			$result = $member->checkPassword($data['Password']);
			$success = $result->valid();
		} else {
			$result = new \ValidationResult(false, _t (
				'Member.ERRORWRONGCRED'
			));
		}

		return $member;
	}

	/**
	 * Method to authenticate a member
	 *
	 * @param array $data Raw data to authenticate the app
         *
	 * @return bool|\Member Returns FALSE if authentication fails, otherwise
	 *                     the Member object
         *
	 */
	public static function authenticate($data) {
		// Find authenticated member
		$member = static::authenticate_member($data, $success);

		return $success ? $member : null;
	}
}
