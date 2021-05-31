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

use App\Service\JwtAuthentication\CreateJwtKeysService;
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

        $force = $args->getOption('force');

        $service = new CreateJwtKeysService();
        $result = $service->createKeyPair($force);

        // TODO: we might want to provide more information here.
        if ($result) {
            $io->success('The JWT key pair was successfully created.');
        } else {
            $io->error('The JWT key pair was not created.');
        }

        return $this->successCode();
    }
}
