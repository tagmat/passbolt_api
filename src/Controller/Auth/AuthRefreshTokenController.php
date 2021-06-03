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

namespace App\Controller\Auth;

use App\Controller\AppController;
use App\Service\JwtAuthentication\CreateJwtUserSecretTokenService;
use App\Service\JwtAuthentication\RefreshTokenCreateService;
use App\Service\JwtAuthentication\RefreshTokenValidationService;
use Cake\Http\Response;

class AuthRefreshTokenController extends AppController
{
    /**
     * Serve a refresh token and a new JWT token.
     *
     * @return \Cake\Http\Response
     */
    public function index(): Response
    {
        (new RefreshTokenValidationService($this->getRequest(), $this->User->id()))->validate();

        $refreshHttpOnlySecureCookie = (new RefreshTokenCreateService($this->User->id()))->create();
        $jwtToken = (new CreateJwtUserSecretTokenService())->createToken($this->User->id());

        $this->success(__('The operation was successful.'), $jwtToken);

        return $this->getResponse()->withCookie($refreshHttpOnlySecureCookie);
    }
}
