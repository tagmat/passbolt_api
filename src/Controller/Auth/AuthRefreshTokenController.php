<?php
declare(strict_types=1);

/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         3.3.0
 */

namespace App\Controller\Auth;

use App\Controller\AppController;
use App\Service\JwtAuthentication\JwtTokenCreateService;
use App\Service\JwtAuthentication\RefreshTokenRenewalService;

class AuthRefreshTokenController extends AppController
{
    /**
     * Serve a refresh token and a new JWT token.
     *
     * @throws \Cake\Http\Exception\BadRequestException if the refresh token is not set in the request.
     * @throws \App\Error\Exception\JWT\InvalidRefreshKeyException if the refresh token is not valid.
     * @return void
     */
    public function refreshPost()
    {
        $userId = $this->User->id();
        $refreshHttpOnlySecureCookie = (new RefreshTokenRenewalService($userId, $this->getRequest()))->renew();

        $jwtToken = (new JwtTokenCreateService())->createToken($userId);
        $this->setResponse($this->getResponse()->withCookie($refreshHttpOnlySecureCookie));

        $this->success(__('The operation was successful.'), $jwtToken);
    }
}
