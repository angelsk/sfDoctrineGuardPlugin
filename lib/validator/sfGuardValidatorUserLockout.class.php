<?php
class sfGuardValidatorUserLockout extends sfGuardValidatorUser
{
  public function configure($options = array(), $messages = array())
  {
    parent::configure($options, $messages);

    $this->addMessage('locked', sfContext::getInstance()->getI18N()->__('This account has been locked, please contact an administrator.'));
    $this->addRequiredOption('lockout');
    $this->setOption('lockout', 10); // attempts
  }

  protected function doClean($values)
  {
    $username = isset($values[$this->getOption('username_field')]) ? $values[$this->getOption('username_field')] : '';
    $password = isset($values[$this->getOption('password_field')]) ? $values[$this->getOption('password_field')] : '';

    $allowEmail = sfConfig::get('app_sf_guard_plugin_allow_login_with_email', true);
    $method = $allowEmail ? 'retrieveByUsernameOrEmailAddress' : 'retrieveByUsername';

    // don't allow to sign in with an empty username
    if ($username)
    {
      if ($callable = sfConfig::get('app_sf_guard_plugin_retrieve_by_username_callable'))
      {
        $user = call_user_func_array($callable, array($username));
      }
      else
      {
        $user = $this->getTable()->$method($username);
      }

      // user exists?
      if ($user)
      {
        // CHECK IF ACCOUNT LOCKED OUT
        if ($user->locked)
        {
          throw new sfValidatorErrorSchema($this, array($this->getOption('username_field') => new sfValidatorError($this, 'locked')));
        }

        $attempts = sfGuardUserAttemptTable::getInstance()->getActiveAttempts($user->id);

        // password is ok?
        if ($user->is_active && $user->checkPassword($password))
        {
          // Check for inccorect attempts and delete - as successful login (soft delete, so preserved)
          if ($attempts)
          {
            foreach ($attempts as $a)
            {
              $a->delete();
            }
          }

          return array_merge($values, array('user' => $user));
        }
        // ELSE - log invalid password attempt
        else if ($user->is_active)
        {
          $attempt = new sfGuardUserAttempt();
          $attempt->setUser($user);
          $attempt->setIp(sfContext::getInstance()->getRequest()->getRemoteAddress());
          $attempt->save();

          // Check if x attempts (option) then lockout - only those not deleted
          if ((count($attempts) + 1) >= $this->getOption('lockout')) // +1 as count was before latest attempt was saved
          {
            $user->setLocked(true);
            $user->save();

            throw new sfValidatorErrorSchema($this, array($this->getOption('username_field') => new sfValidatorError($this, 'locked')));
          }
        }
      }
    }

    if ($this->getOption('throw_global_error'))
    {
      throw new sfValidatorError($this, 'invalid');
    }

    throw new sfValidatorErrorSchema($this, array($this->getOption('username_field') => new sfValidatorError($this, 'invalid')));
  }
}