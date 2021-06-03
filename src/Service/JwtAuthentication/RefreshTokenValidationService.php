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
use Cake\Datasource\ModelAwareTrait;
use Cake\Http\ServerRequest;

/**
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class RefreshTokenValidationService
{
    use ModelAwareTrait;

    public const REFRESH_TOKEN_COOKIE = 'refresh_token';

    /**
     * @var \Cake\Http\ServerRequest
     */
    private $request;

    /**
     * @var string
     */
    private $userId;

    /**
     * @param ServerRequest $resquest Client request.
     * @param string $userId User ID.
     */
    public function __construct(ServerRequest $resquest, string $userId)
    {
        $this->loadModel('AuthenticationTokens');

        $this->request = $resquest;
        $this->userId = $userId;
    }

    /**
     * @return void
     * @throws \App\Error\Exception\JWT\InvalidRefreshKeyException
     */
    public function validate(): void
    {
        $refreshKey = $this->request->getCookie(self::REFRESH_TOKEN_COOKIE, '');
        if ($this->isInvalid($refreshKey)) {
            throw new InvalidRefreshKeyException(__('The provided refresh token is not valid.'));
        }
    }

    /**
     * @param string $refreshKey Refresh key.
     * @return bool true if the refresh key is expired or not found.
     */
    private function isInvalid(string $refreshKey): bool
    {
        /** @var \App\Model\Entity\AuthenticationToken|null $token */
        $token = $this->AuthenticationTokens->find()->where([
            'active' => 1,
            'user_id' => $this->userId,
            'token' => $refreshKey,
            'type' => AuthenticationToken::TYPE_REFRESH_TOKEN,
        ])->first();

        if ($token === null) {
            return true;
        }

        return $this->AuthenticationTokens->isExpired($token);
    }
}
