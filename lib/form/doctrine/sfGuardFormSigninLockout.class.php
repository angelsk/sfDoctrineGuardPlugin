<?php

/**
 * sfGuardFormSignin for sfGuardAuth signin action
 * 
 * INNOCENT/COKE: Account lockout after 10 login attempts
 *
 * @package    sfDoctrineGuardPlugin
 * @subpackage form
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: sfGuardFormSignin.class.php 32943 2011-08-23 11:33:53Z gimler $
 */
class sfGuardFormSigninLockout extends BasesfGuardFormSignin
{
  /**
   * @see sfForm
   */
  public function configure()
  {
    $this->validatorSchema->setPostValidator(new sfGuardValidatorUserLockout(array('lockout' => 10)));
  }
}
