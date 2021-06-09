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
use Cake\Http\Exception\BadRequestException;
use Cake\Validation\Validation;

class AuthRefreshTokenController extends AppController
{
    /**
     * @inheritDoc
     */
    public function beforeFilter(\Cake\Event\EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated([
            'refreshPost'
        ]);

        return parent::beforeFilter($event);
    }

    /**
     * Serve a refresh token and a new JWT token.
     *
     * @throws \Cake\Http\Exception\BadRequestException if the refresh token is not set in the request.
     * @throws \App\Error\Exception\JWT\InvalidRefreshKeyException if the refresh token is not valid.
     * @return void
     */
    public function refreshPost()
    {
        $cookieBased = true;

        $userId = $this->User->id() ?? $this->request->getData('user_id');
        if (!isset($userId) || !Validation::uuid($userId)) {
            throw new BadRequestException(__('A valid user id is required.'));
        }

        $token = $this->request->getCookie(RefreshTokenRenewalService::REFRESH_TOKEN_COOKIE, null);
        if (!isset($token)) {
            $cookieBased = false;
            $this->request->getData('refresh_token');
        }
        if (!isset($token) || !Validation::uuid($token)) {
            throw new BadRequestException(__('A valid refresh token is required.'));
        }

        $refreshService = new RefreshTokenRenewalService($userId, $token);
        $refreshedToken = $refreshService->renewToken();
        $jwtToken = (new JwtTokenCreateService())->createToken($userId);
        $result = [
            'access_token' => $jwtToken
        ];

        if ($cookieBased) {
            $refreshHttpOnlySecureCookie = $refreshService->renewCookie($refreshedToken);
            $this->setResponse($this->getResponse()->withCookie($refreshHttpOnlySecureCookie));
        } else {
            $result['refresh_token'] = $refreshedToken;
        }

        $this->success(__('The operation was successful.'), $result);
    }
}
