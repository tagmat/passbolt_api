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
use Cake\Http\Cookie\Cookie;
use Cake\Http\Exception\InternalErrorException;
use Cake\Validation\Validation;

/**
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class RefreshTokenRenewalService extends RefreshTokenAbstractService
{
    /**
     * @var \Cake\Http\ServerRequest|null
     */
    protected $request;

    /**
     * @var string $userId uuid
     */
    protected $userId;

    /**
     * @var string $token uuid
     */
    protected $token;

    /**
     * @param string $userId User ID.
     * @param string $token refresh token uuid
     */
    final public function __construct(string $userId, string $token)
    {
        parent::__construct();
        if (!Validation::uuid($userId)) {
            throw new \InvalidArgumentException(__('This is not a valid user id.'));
        }
        if (!Validation::uuid($token)) {
            throw new \InvalidArgumentException(__('This is not a valid refresh token.'));
        }
        $this->userId = $userId;
        $this->token = $token;
    }

    /**
     * 1. Read and validate the refresh token passed in the request
     * 2. Create a new token
     * 3. Delete the exiting token retrieved in step 1
     * 4. Return the new token
     *
     * @return \App\Model\Entity\AuthenticationToken
     */
    public function renewToken(): AuthenticationToken
    {
        $oldToken = $this->readAndValidateToken();

        $refreshTokenCreateService = new RefreshTokenCreateService();
        $newToken = $refreshTokenCreateService->createToken($this->userId);
        $this->deactivateToken($oldToken);

        return $newToken;
    }

    /**
     * Return a httponly secure cookie with the new token
     *
     * @param \App\Model\Entity\AuthenticationToken $token New refresh token.
     * @return \Cake\Http\Cookie\Cookie
     */
    public function renewCookie(AuthenticationToken $token): Cookie
    {
        $refreshTokenCreateService = new RefreshTokenCreateService();

        return $refreshTokenCreateService->createCookie($token);
    }

    /**
     * @return \App\Model\Entity\AuthenticationToken
     * @throws \Cake\Http\Exception\BadRequestException if the refresh key is not in the cookies.
     * @throws \App\Error\Exception\JWT\InvalidRefreshKeyException if the refresh key is not valid.
     */
    protected function readAndValidateToken(): AuthenticationToken
    {
        $token = $this->findToken($this->token, $this->userId);

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
     * Get the pepper string used to encrypt the cookie.
     *
     * @return string|null
     */
    public static function getPepper(): ?string
    {
        return Configure::read('passbolt.gpg.serverKey.fingerprint');
    }
}