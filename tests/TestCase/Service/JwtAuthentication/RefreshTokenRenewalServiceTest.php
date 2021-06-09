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

use App\Model\Entity\AuthenticationToken;
use App\Service\JwtAuthentication\RefreshTokenCreateService;
use App\Service\JwtAuthentication\RefreshTokenRenewalService;
use App\Test\Factory\AuthenticationTokenFactory;
use App\Test\Factory\UserFactory;
use Cake\Datasource\ModelAwareTrait;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;

/**
 * @covers \App\Service\JwtAuthentication\RefreshTokenRenewalService
 * @property \App\Model\Table\AuthenticationTokensTable $AuthenticationTokens
 */
class RefreshTokenRenewalServiceTest extends TestCase
{
    use ModelAwareTrait;

    public function setUp(): void
    {
        $this->loadModel('AuthenticationTokens');
    }

    public function testRefreshTokenRenewalServiceWithNoExistingRefreshCookie()
    {
        $userId = UserFactory::make()->persist()->id;

        $refreshTokenService = new RefreshTokenCreateService();
        $authToken = $refreshTokenService->createToken($userId);
        $cookie = $refreshTokenService->createCookie($authToken);

        $request = new ServerRequest(['cookies' => [
            RefreshTokenCreateService::USER_REFRESH_TOKEN_KEY => $cookie->getValue(),
        ]]);
        $tokenInTheRequest = $this->AuthenticationTokens->find()->firstOrFail();

        $someUserTokenNotInvolvedInTheRenewal = AuthenticationTokenFactory::make()
            ->type(AuthenticationToken::TYPE_REFRESH_TOKEN)
            ->active()
            ->userId($userId)
            ->persist();

        $service = new RefreshTokenRenewalService($userId, $request);
        $cookie = $service->renew();

        $this->assertTrue($this->AuthenticationTokens->exists(['id' => $someUserTokenNotInvolvedInTheRenewal->id]));
        $this->assertTrue($this->AuthenticationTokens->exists([
            'token' => $cookie->getValue(),
            'active' => true,
            'user_id' => $userId,
        ]));
        $this->assertTrue($this->AuthenticationTokens->exists(['id' => $tokenInTheRequest->id, 'active' => false]));
    }
}
