<?php

/**
 * sfGuardUserPassword filter to check whether changed password in last 90 days
 *
 *    password_change:
 *      class: sfGuardPasswordFilter
 *
 * @package    innocent
 * @subpackage filter
 * @author     Jo Carter <jocarter@holler.co.uk>
 * @version    SVN: $Id: sfGuardPasswordFilter.class.php 32872 2011-08-02 15:15:56Z jcarter $
 */
class sfGuardPasswordFilter extends sfFilter
{
  /**
   * Executes the filter chain.
   *
   * @param sfFilterChain $filterChain
   */
  public function execute($filterChain)
  {
    $request     = $this->context->getRequest();
    $controller  = $this->context->getController();
    $page        = $this->context->getRouting()->getCurrentInternalUri();
    $user        = $this->context->getUser();

    if ($this->isFirstCall())
    {
      $passwordConfig         = sfConfig::get('app_sf_guard_plugin_password', array('change_every'=>null));
      $changeEvery            = (isset($passwordConfig['change_every']) ? $passwordConfig['change_every'] : null);

      if ($user->isAuthenticated() && !is_null($changeEvery)) // !null for change password
      {
        // check when changed password last (save in session to prevent repeat queries - gets set in preUpdate/preInsert too)
        $passwordChangeDate = $user->getAttribute('password_date', null, 'sfGuardSecurityUser');

        if (!$passwordChangeDate)
        {
          $passwordChangeDate = strtotime(sfGuardUserPasswordTable::getInstance()->getLastPasswordChangeDate($user->getGuardUser()->id));
          $user->setAttribute('password_date', $passwordChangeDate, 'sfGuardSecurityUser');
        }

        // calculate number of days need to change password
        $ddiff                  = time() - $passwordChangeDate;
        $ddiff_days             = floor($ddiff/60/60/24);
        $passwordChangeRequired = ($ddiff_days >= $changeEvery);

        // if not in correct module then redirect and display flash
        if ($passwordChangeRequired)
        {
          $user_id = $user->getAttribute('user_id', null, 'sfGuardSecurityUser');
          if (!$user_id) $user_id = $user->getGuardUser()->id;

          $edit   = sprintf('sfGuardUser/edit?id=%s&sf_format=html', $user_id);
          $update = sprintf('sfGuardUser/update?id=%s&sf_format=html', $user_id);

          if ($edit != $page && $update != $page)
          {
            $user->setFlash('error', sfContext::getInstance()->getI18N()->__('Your password is at least %days% days old, please change it before continuing', array('%days%'=>$changeEvery)));
            $controller->redirect('sfGuardUser/edit?id='.$user_id, 301);
          }
        }
      }
    }

    $filterChain->execute();
  }
}
