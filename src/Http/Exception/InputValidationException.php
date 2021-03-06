<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common\Http\Exception;

use Exception;

class InputValidationException extends HttpException
{
    /**
     * @param string $message
     * @param int    $code
     */
    public function __construct($message, $code = 400, Exception $previous = null)
    {
        parent::__construct($message, $code, [], $previous);
    }
}
