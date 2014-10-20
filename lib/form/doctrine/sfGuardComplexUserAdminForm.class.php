<?php

/**
 * sfGuardUserAdminForm for admin generators
 *
 * @package    sfDoctrineGuardPlugin
 * @subpackage form
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id: sfGuardUserAdminForm.class.php 192 2011-11-30 17:33:37Z januszslota $
 */
class sfGuardComplexUserAdminForm extends BasesfGuardUserAdminForm
{
  /**
   * @see sfForm
   */
  public function configure()
  {
    $this->validatorSchema['email_address'] = new sfValidatorEmail();

    // Complex password validator
    $config     = sfConfig::get('app_sf_guard_plugin_password');
    $complexity = (isset($config['complexity']) ? $config['complexity'] : array('min_length' => 8, 'min_alpha' => 1, 'min_numeric' => 1, 'min_special' => 1));

    $this->validatorSchema['password']       = new sfValidatorPassword(array('max_length' => 128, 'required' => false) + $complexity,
                                                                 array('complexity'=>sfContext::getInstance()->getI18N()->__('Your password must correspond with the appropriate password standards')));
    $this->validatorSchema['password_again'] = clone $this->validatorSchema['password'];

    // Require password for new users (or if no password set)
    if ($this->isNew() || !$this->getObject()->getPassword())
    {
      $this->validatorSchema['password']->setOption('required', true);
      $this->validatorSchema['password_again']->setOption('required', true);

      $this->widgetSchema['current_password']    = new sfWidgetFormInputHidden();
      $this->validatorSchema['current_password'] = new sfValidatorPass();
    }
    // Existing users must enter their current password to change the password on the account
    else
    {
      $this->widgetSchema['current_password']    = new sfWidgetFormInputPassword();
      $this->validatorSchema['current_password'] = new sfValidatorString(array('max_length' => 128, 'required' => false));

      $this->mergePostValidator(new sfGuardValidatorPassword(array('old_password_field'=>'current_password', 'new_password_field'=>'password'),
                                                             array('invalid'=>sfContext::getInstance()->getI18N()->__('Please enter the current password for THIS user to change their password'))));
    }
  }
}
