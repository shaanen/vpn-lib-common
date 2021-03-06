<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http;

use DateTime;

class SimpleAuth implements CredentialValidatorInterface
{
    /** @var array */
    private $userPass;

    public function __construct(array $userPass)
    {
        $this->userPass = $userPass;
    }

    /**
     * @param string $authUser
     * @param string $authPass
     *
     * @return false|UserInfo
     */
    public function isValid($authUser, $authPass)
    {
        if (!array_key_exists($authUser, $this->userPass)) {
            return false;
        }

        if (!password_verify($authPass, $this->userPass[$authUser])) {
            return false;
        }

        return new UserInfo($authUser, [], new DateTime());
    }
}
