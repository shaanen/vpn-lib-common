<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http;

use fkooman\OAuth\Client\OAuthClient;
use fkooman\OAuth\Client\Provider;
use fkooman\SeCookie\SessionInterface;

class OpenIdAuthenticationHook implements BeforeHookInterface, ServiceModuleInterface
{
    /** @var \fkooman\SeCookie\SessionInterface */
    private $session;

    /** @var \fkooman\OAuth\Client\Provider */
    private $provider;

    /** @var \fkooman\OAuth\Client\OAuthClient */
    private $oauthClient;

    /**
     * @param \fkooman\SeCookie\SessionInterface $session
     * @param \fkooman\OAuth\Client\Provider     $provider
     * @param \fkooman\OAuth\Client\OAuthClient  $oauthClient
     */
    public function __construct(SessionInterface $session, Provider $provider, OAuthClient $oauthClient)
    {
        $this->session = $session;
        $this->provider = $provider;
        $this->oauthClient = $oauthClient;
    }

    /**
     * @param Request $request
     * @param array   $hookData
     *
     * @return false|RedirectResponse|UserInfo
     */
    public function executeBefore(Request $request, array $hookData)
    {
        // do not trigger authentication on callback URL
        if ('/_openid/callback' === $request->getPathInfo()) {
            return false;
        }

        if (false === $idToken = $this->oauthClient->getIdToken($this->provider)) {
            $this->session->set('_openid_return_to', $request->getUri());

            return new RedirectResponse(
                $this->oauthClient->getAuthorizeUri(
                    $this->provider,
                    null,
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
                $this->oauthClient->handleCallback(
                    $this->provider,
                    null,
                    $request->getQueryParameters()
                );

                $returnTo = $this->session->get('_openid_return_to');

                return new RedirectResponse($returnTo);
            }
        );
    }
}
