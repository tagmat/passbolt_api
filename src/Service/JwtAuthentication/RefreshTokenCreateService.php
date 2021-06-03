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

use App\Model\Entity\AuthenticationToken;
use Cake\Datasource\ModelAwareTrait;
use Cake\Http\Cookie\Cookie;

/**
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class RefreshTokenCreateService
{
    use ModelAwareTrait;

    public const REFRESH_TOKEN_COOKIE = 'refresh_token';

    /**
     * @var string
     */
    private $userId;

    /**
     * @param string $userId User ID.
     */
    public function __construct(string $userId)
    {
        $this->loadModel('AuthenticationTokens');

        $this->userId = $userId;
    }

    /**
     * @return \Cake\Http\Cookie\Cookie
     */
    public function create(): Cookie
    {
        $this->deleteAll();

        $token = $this->AuthenticationTokens->generate($this->userId, AuthenticationToken::TYPE_REFRESH_TOKEN);

        $cookie = new Cookie(self::REFRESH_TOKEN_COOKIE, $token->token);

        return $cookie
            ->withSecure(true)
            ->withHttpOnly(true);
    }

    /**
     * Delete all refresh tokens associated to the user.
     *
     * @return void
     */
    private function deleteAll(): void
    {
        $this->AuthenticationTokens->deleteAll([
            'user_id' => $this->userId,
            'type' => AuthenticationToken::TYPE_REFRESH_TOKEN,
        ]);
    }
}
