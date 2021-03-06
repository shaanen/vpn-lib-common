<?php

/*
 * eduVPN - End-user friendly VPN.
 *
 * Copyright: 2016-2018, The Commons Conservancy eduVPN Programme
 * SPDX-License-Identifier: AGPL-3.0+
 */

namespace SURFnet\VPN\Common;

use ParagonIE\ConstantTime\Hex;

class Random implements RandomInterface
{
    /**
     * @param int $length
     *
     * @return string
     */
    public function get($length)
    {
        return Hex::encode(
            random_bytes($length)
        );
    }
}
