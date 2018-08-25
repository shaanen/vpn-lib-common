<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http;

use fkooman\Jwt\RS256;
use fkooman\OAuth\Client\ErrorLogger;
use fkooman\OAuth\Client\Http\CurlHttpClient;
use fkooman\OAuth\Client\OpenIdClient;
use fkooman\OAuth\Client\Provider;
use fkooman\OAuth\Client\SessionTokenStorage;
use fkooman\SeCookie\SessionInterface;

class OpenIdAuthenticationHook implements BeforeHookInterface
{
    /** @var \fkooman\SeCookie\SessionInterface */
    private $session;

    /** @var \fkooman\OAuth\Client\Provider */
    private $provider;

    /** @var \fkooman\Jwt\RS256 */
    private $jwtDecoder;

    /** @var string */
    private $callbackUri;

    /**
     * @param \fkooman\SeCookie\SessionInterface $session
     * @param \fkooman\OAuth\Client\Provider     $provider
     * @param \fkooman\Jwt\RS256                 $jwtDecoder
     * @param string                             $callbackUri
     */
    public function __construct(SessionInterface $session, Provider $provider, RS256 $jwtDecoder, $callbackUri)
    {
        $this->session = $session;
        $this->provider = $provider;
        $this->jwtDecoder = $jwtDecoder;
        $this->callbackUri = $callbackUri;
    }

    /**
     * @param Request $request
     * @param array   $hookData
     *
     * @return RedirectResponse|UserInfo
     */
    public function executeBefore(Request $request, array $hookData)
    {
        $client = new OpenIdClient(
            new SessionTokenStorage(), // we won't be using the token anyway...
            new CurlHttpClient([], new ErrorLogger()),
            $this->jwtDecoder
        );

        if (false === $idToken = $client->getIdToken($this->provider, 'openid')) {
            return new RedirectResponse($client->getAuthenticateUri($this->provider, 'openid', $this->callbackUri));
        }

        return new UserInfo($idToken->getSub(), []);
    }
}
