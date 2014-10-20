<?php

/**
 * sfGuardChangeUserPasswordForm for changing a users password
 *
 * @package    sfDoctrineGuardPlugin
 * @subpackage form
 * @author     Jonathan H. Wage <jonwage@gmail.com>
 * @version    SVN: $Id: sfGuardChangeUserPasswordForm.class.php 23536 2009-11-02 21:41:21Z Kris.Wallsmith $
 */
class sfGuardComplexChangeUserPasswordForm extends BasesfGuardChangeUserPasswordForm
{
  /**
   * @see sfForm
   */
  public function configure()
  {
    $this->widgetSchema['username']          = new sfWidgetFormInputHidden();
    $this->validatorSchema['username']       = new sfValidatorString(array('required'=>true));

    // Complex password validator
    $config     = sfConfig::get('app_sf_guard_plugin_password');
    $complexity = (isset($config['complexity']) ? $config['complexity'] : array('min_length' => 8, 'min_alpha' => 1, 'min_numeric' => 1, 'min_special' => 1));

    $this->validatorSchema['password']       = new sfValidatorPassword(array('max_length' => 128, 'required' => false) + $complexity,
                                                                       array('complexity'=>sfContext::getInstance()->getI18N()->__('Your password must correspond with the appropriate password standards')));
    $this->validatorSchema['password_again'] = clone $this->validatorSchema['password'];

    $this->validatorSchema['password']->setOption('required', true);
    $this->validatorSchema['password_again']->setOption('required', true);

    $this->mergePostValidator(new sfGuardValidatorPassword(array('old_password_field'=>null, 'new_password_field'=>'password')));
  }
}
