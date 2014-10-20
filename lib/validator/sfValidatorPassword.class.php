<?php

/**
 * Validates complexity of password
 *
 * @author Jo Carter <jocarter@holler.co.uk>
 *
 */
class sfValidatorPassword extends sfValidatorString
{
  /**
   * Configures the current validator.
   *
   * Available options:
   *
   * * min_alpha          - minimum number of alpha characters required in the password
   * * min_upper_alpha    - minimum number of upper alpha characters required in the password
   * * min_lower_alpha    - minimum number of lower alpha characters required in the password
   * * min_alpha_numeric  - minimum number of alphanumeric characters required in the password
   * * min_numeric        - minimum number of numberic characters required in the password
   * * min_special        - minimum number of special characters required in the password
   *
   * Available error codes:
   *
   *  * complexity
   *
   * @param array $options   An array of options
   * @param array $messages  An array of error messages
   *
   * @see sfValidatorBase
   */
  protected function configure($options = array(), $messages = array())
  {
    parent::configure($options, $messages);

    // Don't show password
    $this->addMessage('max_length', sfContext::getInstance()->getI18N()->__('Password is too long (%max_length% characters max).'));
    $this->addMessage('min_length', sfContext::getInstance()->getI18N()->__('Password is too short (%min_length% characters min).'));
    $this->addMessage('complexity', sfContext::getInstance()->getI18N()->__('Password is not complex enough'));

    $this->addOption('min_alpha');
    $this->addOption('min_upper_alpha');
    $this->addOption('min_lower_alpha');
    $this->addOption('min_alpha_numeric');
    $this->addOption('min_numeric');
    $this->addOption('min_special');
  }

  /**
   * @see sfValidatorBase
   */
  protected function doClean($value)
  {
    $clean = parent::doClean($value);

    $matches                  = array();
    $alpha_char_count         = preg_match_all('/[a-zA-Z]/', $clean, $matches);
    $upper_alpha_char_count   = preg_match_all('/[A-Z]/', $clean, $matches);
    $lower_char_count         = preg_match_all('/[a-z]/', $clean, $matches);
    $number_char_count        = preg_match_all('/[\d]/', $clean, $matches);
    $alpha_numeric_char_count = preg_match_all('/[a-zA-Z\d]/', $clean, $matches);
    $special_char_count       = preg_match_all('/[^a-zA-Z\d]/', $clean, $matches);

    if ($this->hasOption('min_alpha') && $alpha_char_count < $this->getOption('min_alpha'))
    {
      throw new sfValidatorError($this, 'complexity', array('value' => $value));
    }

    if ($this->hasOption('min_upper_alpha') && $upper_alpha_char_count < $this->getOption('min_upper_alpha'))
    {
      throw new sfValidatorError($this, 'complexity', array('value' => $value));
    }

    if ($this->hasOption('min_lower_alpha') && $lower_char_count < $this->getOption('min_lower_alpha'))
    {
      throw new sfValidatorError($this, 'complexity', array('value' => $value));
    }

    if ($this->hasOption('min_alpha_numeric') && $alpha_numeric_char_count < $this->getOption('min_alpha_numeric'))
    {
      throw new sfValidatorError($this, 'complexity', array('value' => $value));
    }

    if ($this->hasOption('min_numeric') && $number_char_count < $this->getOption('min_numeric'))
    {
      throw new sfValidatorError($this, 'complexity', array('value' => $value));
    }

    if ($this->hasOption('min_special') && $special_char_count < $this->getOption('min_special'))
    {
      throw new sfValidatorError($this, 'complexity', array('value' => $value));
    }

    return (string) $value;
  }
}
