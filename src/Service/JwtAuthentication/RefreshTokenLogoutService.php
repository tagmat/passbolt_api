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

class RefreshTokenLogoutService extends RefreshTokenAbstractService
{
    public const REFRESH_TOKEN_DATA_KEY = 'refresh_token';

    /**
     * @param string $userId user uuid
     * @param string|null $token token passed in the request
     * @return int The numer of tokens deactivated.
     */
    public function logout(string $userId, ?string $token): int
    {
        if ($token !== null) {
            $token = $this->findToken($token, $userId);
        }

        if ($token instanceof AuthenticationToken) {
            $token->set('active', false);
            $this->AuthenticationTokens->saveOrFail($token);

            return 1;
        } else {
            return $this->AuthenticationTokens->updateAll(
                ['active' => false],
                ['user_id' => $userId]
            );
        }
    }
}
