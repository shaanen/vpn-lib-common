<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http;

use fkooman\OAuth\Client\OpenIdClient;
use fkooman\OAuth\Client\Provider;
use fkooman\SeCookie\SessionInterface;

class OpenIdAuthenticationHook implements BeforeHookInterface, ServiceModuleInterface
{
    /** @var \fkooman\SeCookie\SessionInterface */
    private $session;

    /** @var \fkooman\OAuth\Client\Provider */
    private $provider;

    /** @var \fkooman\OAuth\Client\OpenIdClient */
    private $openIdClient;

    /**
     * @param \fkooman\SeCookie\SessionInterface $session
     * @param \fkooman\OAuth\Client\Provider     $provider
     * @param \fkooman\OAuth\Client\OpenIdClient $openIdClient
     */
    public function __construct(SessionInterface $session, Provider $provider, OpenIdClient $openIdClient)
    {
        $this->session = $session;
        $this->provider = $provider;
        $this->openIdClient = $openIdClient;
    }

    /**
     * @param Request $request
     * @param array   $hookData
     *
     * @return RedirectResponse|UserInfo
     */
    public function executeBefore(Request $request, array $hookData)
    {
        if (false === $idToken = $this->openIdClient->getIdToken($this->provider, 'openid')) {
            $this->session->set('_openid_return_to', $request->getUri());

            return new RedirectResponse(
                $this->openIdClient->getAuthenticateUri(
                    $this->provider,
                    'openid',
                    $request->getRootUri().'_openid/callback'
                )
            );
        }

        return new UserInfo($idToken->getSub(), []);
    }

    /**
     * @return void
     */
    public function init(Service $service)
    {
        $service->get(
            '/_openid/callback',
            /**
             * @return Response
             */
            function (Request $request) {
                $this->openIdClient->handleAuthenticateCallback(
                    $this->provider,
                    $request->getQueryParameters()
                );

                $returnTo = $this->session->get('_openid_return_to');

                return new RedirectResponse($returnTo);
            }
        );
    }
}
