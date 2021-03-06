<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http;

use SURFnet\VPN\Common\Json;

class ApiResponse extends Response
{
    /**
     * @param string                     $wrapperKey
     * @param null|bool|string|array|int $responseData
     * @param int                        $responseCode
     */
    public function __construct($wrapperKey, $responseData = null, $responseCode = 200)
    {
        $responseBody = [
            $wrapperKey => [
                'ok' => true,
            ],
        ];

        if (null !== $responseData) {
            $responseBody[$wrapperKey]['data'] = $responseData;
        }

        parent::__construct($responseCode, 'application/json');
        $this->setBody(Json::encode($responseBody));
    }
}
