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
use Cake\Http\Cookie\Cookie;

/**
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class RefreshTokenCreateService extends RefreshTokenAbstractService
{
    /**
     * @param string $userId user uuid
     * @return \App\Model\Entity\AuthenticationToken
     */
    public function createToken(string $userId): AuthenticationToken
    {
        return $this->AuthenticationTokens->generate($userId, AuthenticationToken::TYPE_REFRESH_TOKEN);
    }

    /**
     * @param \App\Model\Entity\AuthenticationToken $token token
     * @return \Cake\Http\Cookie\Cookie
     */
    public function createCookie(AuthenticationToken $token): Cookie
    {
        $cookie = new Cookie(RefreshTokenRenewalService::REFRESH_TOKEN_COOKIE, $token->token);

        // TODO set expiry date based on token expiry
        return $cookie
            ->withSecure(true)
            ->withHttpOnly(true);
    }
}
