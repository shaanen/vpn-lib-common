<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http;

use fkooman\SeCookie\Cookie;
use SURFnet\VPN\Common\Http\Exception\HttpException;

/**
 * This hook is used to be able to switch the language without requiring to be
 * authenticated. As the language switcher is only a user preference stored in
 * a cookie this is not a problem. This way, even the authentication page can
 * use the language switcher.
 */
class LanguageSwitcherHook implements BeforeHookInterface
{
    /** @var \fkooman\SeCookie\Cookie */
    private $cookie;

    /** @var array */
    private $supportedLanguages;

    public function __construct(array $supportedLanguages, Cookie $cookie)
    {
        $this->supportedLanguages = $supportedLanguages;
        $this->cookie = $cookie;
    }

    public function executeBefore(Request $request, array $hookData)
    {
        if ('POST' !== $request->getRequestMethod()) {
            return false;
        }

        if ('/setLanguage' !== $request->getPathInfo()) {
            return false;
        }

        $language = $request->getPostParameter('setLanguage', false, 'en_US');
        if (!\in_array($language, $this->supportedLanguages, true)) {
            throw new HttpException('invalid language', 400);
        }

        $this->cookie->set('ui_lang', $language);

        return new RedirectResponse($request->requireHeader('HTTP_REFERER'), 302);
    }
}
