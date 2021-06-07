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

    public const USER_REFRESH_KEY = 'refresh_token';

    /**
     * @var string
     */
    protected $userId;

    /**
     * @param string $userId User ID.
     */
    public function __construct(string $userId)
    {
        $this->loadModel('AuthenticationTokens');
        $this->userId = $userId;
    }

    /**
     * Persist an authentication token and return a secure Cookie
     * to be attached to the response.
     *
     * @return \Cake\Http\Cookie\Cookie
     */
    public function create(): Cookie
    {
        $token = $this->AuthenticationTokens->generate(
            $this->userId,
            AuthenticationToken::TYPE_REFRESH_TOKEN
        )->token;

        $cookie = new Cookie(RefreshTokenRenewalService::REFRESH_TOKEN_COOKIE, $token);

        return $cookie->withSecure(true)->withHttpOnly(true);
    }
}
