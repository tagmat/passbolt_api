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

use Cake\Datasource\ModelAwareTrait;

/**
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
abstract class RefreshTokenAbstractService
{
    use ModelAwareTrait;

    public const REFRESH_TOKEN_COOKIE = 'refresh_token';
    public const USER_REFRESH_TOKEN_KEY = 'refresh_token';

    /**
     * RefreshTokenCreateService constructor.
     */
    public function __construct()
    {
        $this->loadModel('AuthenticationTokens');
    }
}
