<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Tests\Http;

use PHPUnit\Framework\TestCase;
use SURFnet\VPN\Common\Http\FormAuthenticationHook;
use SURFnet\VPN\Common\Tests\TestTpl;

class FormAuthenticationHookTest extends TestCase
{
    public function testAuthenticated()
    {
        $session = new TestSession();
        $session->set('_form_auth_user', 'foo');
        $session->set('_form_auth_entitlement_list', ['foo']);

        $tpl = new TestTpl();
        $formAuthentication = new FormAuthenticationHook($session, $tpl);

        $request = new TestRequest([]);

        $this->assertSame('foo', $formAuthentication->executeBefore($request, [])->id());
    }

    public function testNotAuthenticated()
    {
        $session = new TestSession();
        $tpl = new TestTpl();
        $formAuthentication = new FormAuthenticationHook($session, $tpl);

        $request = new TestRequest(
            [
            ]
        );

        $response = $formAuthentication->executeBefore($request, []);
        $this->assertSame('{"formAuthentication":{"_form_auth_invalid_credentials":false,"_form_auth_redirect_to":"http:\/\/vpn.example\/","_form_auth_login_page":true}}', $response->getBody());
    }
}
