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
use App\Service\JwtAuthentication\GetJwksPublicService;
use Cake\Event\EventInterface;

class AuthJwksController extends AppController
{
    /**
     * @inheritDoc
     */
    public function beforeFilter(EventInterface $event)
    {
        parent::beforeFilter($event);

        $this->Authentication->allowUnauthenticated(['index']);
    }

    /**
     * Check a user is authenticated
     *
     * @return void
     */
    public function index()
    {
        $keys['keys'][] = (new GetJwksPublicService())->getPublicKey();

        $this->success(__('The operation was successful.'), $keys);
    }
}
