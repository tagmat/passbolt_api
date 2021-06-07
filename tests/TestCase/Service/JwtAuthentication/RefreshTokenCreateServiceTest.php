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

namespace App\Test\TestCase\Service\JwtAuthentication;

use App\Service\JwtAuthentication\RefreshTokenCreateService;
use App\Test\Factory\UserFactory;
use Cake\TestSuite\TestCase;

/**
 * @covers \App\Service\JwtAuthentication\RefreshTokenCreateService
 */
class RefreshTokenCreateServiceTest extends TestCase
{
    public function testsRefreshTokenCreateService()
    {
        $userId = UserFactory::make()->persist()->id;
        $token = (new RefreshTokenCreateService($userId))->create();
        $this->assertTrue($token->isSecure());
        $this->assertTrue($token->isHttpOnly());
        $this->assertFalse($token->isExpired());
    }
}
