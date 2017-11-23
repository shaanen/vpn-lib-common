<?php

/**
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2017, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http;

use Psr\Log\LoggerInterface;
use SURFnet\VPN\Common\Exception\LdapClientException;
use SURFnet\VPN\Common\LdapClient;

class LdapAuth implements CredentialValidatorInterface
{
    /** @var \Psr\Log\LoggerInterface */
    private $logger;

    /** @var \SURFnet\VPN\Common\LdapClient */
    private $ldapClient;

    /** @var string */
    private $userDnTemplate;

    /**
     * @param string $userDnTemplate
     */
    public function __construct(LoggerInterface $logger, LdapClient $ldapClient, $userDnTemplate)
    {
        $this->logger = $logger;
        $this->ldapClient = $ldapClient;
        $this->userDnTemplate = $userDnTemplate;
    }

    /**
     * @param string $authUser
     * @param string $authPass
     *
     * @return bool
     */
    public function isValid($authUser, $authPass)
    {
        $userDn = str_replace('{{UID}}', LdapClient::escapeDn($authUser), $this->userDnTemplate);
        try {
            $this->ldapClient->bind($userDn, $authPass);

            return true;
        } catch (LdapClientException $e) {
            $this->logger->warning(sprintf('authentication failed: DN "%s" was unable to bind to LDAP server', $userDn));

            return false;
        }
    }
}