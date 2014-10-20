<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Validator to validate current password when changing password value
 *
 * @package    symfony
 * @subpackage plugin
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: sfGuardValidatorUser.class.php 31850 2011-01-18 17:22:08Z gimler $
 */
class sfGuardValidatorPassword extends sfValidatorBase
{
  public function configure($options = array(), $messages = array())
  {
    $this->addOption('username_field', 'username');
    $this->addOption('old_password_field', 'current_password');
    $this->addOption('new_password_field', 'password');

    $this->setMessage('invalid', sfContext::getInstance()->getI18N()->__('The password is invalid.'));
    $this->addMessage('duplicate', sfContext::getInstance()->getI18N()->__('This password has already been used, please pick another'));
  }

  protected function doClean($values)
  {
    // If not changing password
    if (!isset($values[$this->getOption('new_password_field')]) || empty($values[$this->getOption('new_password_field')])) return $values;

    // Else validate
    $username    = isset($values[$this->getOption('username_field')]) ? $values[$this->getOption('username_field')] : '';
    $newPassword = isset($values[$this->getOption('new_password_field')]) ? $values[$this->getOption('new_password_field')] : '';

    if ($this->getOption('old_password_field')) // so can use on forgot password
    {
      $password = isset($values[$this->getOption('old_password_field')]) ? $values[$this->getOption('old_password_field')] : '';

      // Can't change to same
      if ($password === $newPassword)
      {
        throw new sfValidatorErrorSchema($this, array($this->getOption('new_password_field') => new sfValidatorError($this, 'duplicate')));
      }
    }

    // don't allow to sign in with an empty username
    if ($username)
    {
      $user = $this->getTable()->findOneByUsername($username); // don't check is active

      // user exists?
      if ($user)
      {
        if ($this->getOption('old_password_field')) // so can use on forgot password
        {
          // password is ok? check this first, in case trying to guess with changed password
          if (!$user->checkPassword($password))
          {
            throw new sfValidatorErrorSchema($this, array($this->getOption('old_password_field') => new sfValidatorError($this, 'invalid')));
          }
        }

        // Can't change to any of last x passwords
        $newPasswordHash = $user->createPasswordHash($newPassword);
        $alreadyUsed     = sfGuardUserPasswordTable::getInstance()->checkPasswordHistory($user->id, $newPasswordHash);

        if ($alreadyUsed)
        {
          throw new sfValidatorErrorSchema($this, array($this->getOption('new_password_field') => new sfValidatorError($this, 'duplicate')));
        }

        // All ok
        return array_merge($values, array('user' => $user));
      }
    }

    throw new sfValidatorErrorSchema($this, array($this->getOption('old_password_field') => new sfValidatorError($this, 'invalid')));
  }

  protected function getTable()
  {
    return Doctrine_Core::getTable('sfGuardUser');
  }
}
