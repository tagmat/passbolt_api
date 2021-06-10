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
            'refreshPost',
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
        $token = $this->request->getCookie(RefreshTokenRenewalService::REFRESH_TOKEN_COOKIE, null);
        if (isset($token)) {
            $body = $this->handleWithCookie($token);
        } else {
            $body = $this->handleWithChallenge();
        }

        $this->success(null, $body);
    }

    /**
     * Renew the refresh token, set the refresh token in the response
     * as cookie, deliver a JWT token in the response
     *
     * @param string $token Refresh token passed as cookie.
     * @return array
     */
    protected function handleWithCookie(string $token): array
    {
        $this->validateToken($token);

        $refreshService = new RefreshTokenRenewalService($this->User->id(), $token);
        $refreshedToken = $refreshService->renewToken();
        $refreshHttpOnlySecureCookie = $refreshService->renewCookie($refreshedToken);
        $this->setResponse($this->getResponse()->withCookie($refreshHttpOnlySecureCookie));
        $accessToken = (new JwtTokenCreateService())->createToken($this->User->id());

        return ['access_token' => $accessToken];
    }

    /**
     * Get the refresh token in the payload.
     * Return the challenge with the refreshed token.
     *
     * @return array
     */
    protected function handleWithChallenge(): array
    {
        $token = $this->request->getData('refresh_token');
        $userId = $this->request->getData('user_id');

        $this->validateToken($token);
        $this->validateUserId($userId);

        /** @var \App\Authenticator\GpgJwtAuthenticator $GpgJwtAuth */
        $GpgJwtAuth = $this->getRequest()->getAttribute('authentication')->authenticators()->get('GpgJwt');
        $challenge = $GpgJwtAuth->makeArmoredChallenge($token, $userId);

        return compact('challenge');
    }

    /**
     * @param string|null $token Refresh token
     * @return void
     * @throws \Cake\Http\Exception\BadRequestException
     */
    protected function validateToken(?string $token): void
    {
        if (!isset($token) || !Validation::uuid($token)) {
            throw new BadRequestException(__('A valid refresh token is required.'));
        }
    }

    /**
     * @param string|null $userId User ID
     * @return void
     * @throws \Cake\Http\Exception\BadRequestException
     */
    protected function validateUserId(?string $userId): void
    {
        if (!isset($userId) || !Validation::uuid($userId)) {
            throw new BadRequestException(__('A valid user id is required.'));
        }
    }
}
