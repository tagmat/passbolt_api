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
namespace App\Command;

use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;

class JwtSetupCommand extends PassboltCommand
{
    /**
     * @inheritDoc
     */
    public function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        $parser
            ->setDescription(__('JSON Web Token setup.'))
            ->addOption('force', [
                'help' => 'Override the key files if found.',
                'default' => 'false',
                'short' => 'f',
                'boolean' => true,
            ]);

        return $parser;
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): ?int
    {
        parent::execute($args, $io);

        // TODO: wrap this in a Service handling all potential errors

        # generate private key
        exec('openssl genrsa -out config/jwt.key 1024');

        # generate public key
        exec('openssl rsa -in config/jwt.key -outform PEM -pubout -out config/jwt.pem');

        return $this->successCode();
    }
}
