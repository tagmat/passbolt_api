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
namespace App\Service\JwtAuthentication;

use App\Error\Exception\JWT\InvalidRefreshKeyException;
use App\Model\Entity\AuthenticationToken;
use Cake\Core\Configure;
use Cake\Datasource\ModelAwareTrait;
use Cake\Http\Cookie\Cookie;
use Cake\Http\Exception\BadRequestException;
use Cake\Http\Exception\InternalErrorException;
use Cake\Http\ServerRequest;

/**
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class RefreshTokenRenewalService
{
    use ModelAwareTrait;

    public const REFRESH_TOKEN_COOKIE = 'refresh_token';

    /**
     * @var \Cake\Http\ServerRequest|null
     */
    protected $request;

    /**
     * @var string
     */
    protected $userId;

    /**
     * @param string $userId User ID.
     * @param \Cake\Http\ServerRequest|null $request Client request (optional).
     */
    final public function __construct(string $userId, ?ServerRequest $request = null)
    {
        $this->loadModel('AuthenticationTokens');

        $this->userId = $userId;
        $this->request = $request;
    }

    /**
     * 1. Read and validate the refresh token passed in the request
     * 2. Create a new token
     * 3. Delete the exiting token retrieved in step 1
     * 4. Return a httponly secure cookie with the new token
     *
     * @return \Cake\Http\Cookie\Cookie
     */
    public function renew(): Cookie
    {
        $oldToken = $this->readAndValidateToken();
        $newToken = (new RefreshTokenCreateService($this->userId))->create();
        $this->deactivateToken($oldToken);

        return $newToken;
    }

    /**
     * @return \App\Model\Entity\AuthenticationToken
     * @throws \Cake\Http\Exception\BadRequestException if the refresh key is not in the cookies.
     * @throws \App\Error\Exception\JWT\InvalidRefreshKeyException if the refresh key is not valid.
     */
    protected function readAndValidateToken(): AuthenticationToken
    {
        $refreshKey = $this->readRefreshTokenInRequest();
        if (empty($refreshKey)) {
            throw new BadRequestException(__('No refresh token is provided in the request.'));
        }

        $token = $this->findToken($refreshKey);

        if ($token === null) {
            throw new InvalidRefreshKeyException(__(
                'No active refresh token matching the request could be found.'
            ));
        } elseif ($this->AuthenticationTokens->isExpired($token)) {
            throw new InvalidRefreshKeyException(__('The refresh token provided is expired.'));
        }

        return $token;
    }

    /**
     * Deactivate the token passed in the request to be replaced.
     *
     * @param \App\Model\Entity\AuthenticationToken $oldToken Token to be deactivated.
     * @return void
     */
    protected function deactivateToken(AuthenticationToken $oldToken): void
    {
        // Deactivate the refresh token passed in the request
        $oldToken->set('active', false);
        $isDeactivated = $this->AuthenticationTokens->save($oldToken);
        if (!$isDeactivated) {
            throw new InternalErrorException(
                __('The refresh token could not be deactivated, and was not renewed.')
            );
        }
    }

    /**
     * Read the refresh token in the request cookies.
     *
     * @return string
     */
    protected function readRefreshTokenInRequest(): string
    {
        return $this->request->getCookie(self::REFRESH_TOKEN_COOKIE, '');
    }

    /**
     * Find the token corresponding to the user and refresh token.
     *
     * @param string $refreshToken Refresh token to retrieve.
     * @return \App\Model\Entity\AuthenticationToken|null
     */
    protected function findToken(string $refreshToken): ?AuthenticationToken
    {
        if (empty($refreshToken)) {
            return null;
        }

        /** @var \App\Model\Entity\AuthenticationToken|null $refreshToken */
        $refreshToken = $this->AuthenticationTokens->find()->where([
            'active' => true,
            'user_id' => $this->userId,
            'token' => $refreshToken,
            'type' => AuthenticationToken::TYPE_REFRESH_TOKEN,
        ])->first();

        return $refreshToken;
    }

    /**
     * Find the authentication token from the refresh token in the request.
     *
     * @return \App\Model\Entity\AuthenticationToken|null
     */
    protected function findTokenInRequest(): ?AuthenticationToken
    {
        return $this->findToken(
            $this->readRefreshTokenInRequest()
        );
    }

    /**
     * Get the pepper string used to encrypt the cookie.
     *
     * @return string|null
     */
    public static function getPepper(): ?string
    {
        return Configure::read('passbolt.gpg.serverKey.fingerprint');
    }
}
